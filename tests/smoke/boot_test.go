//go:build smoke

// Package smoke contains end-to-end smoke tests that exercise the compiled
// identity binary as an external process. These tests are excluded from the
// default `go test ./...` run via the `smoke` build tag and must be invoked
// explicitly:
//
//	go test -tags=smoke -count=1 -timeout=60s ./tests/smoke/...
//
// Why a separate process test exists:
//
// The identity binary transitively imports gen/go/identity, whose init()
// registers the proto descriptor pool. A malformed descriptor (e.g. a stale
// generated file out-of-sync with its proto schema) panics at process start
// before any HTTP listener is bound. Unit tests that only import sub-packages
// of internal/* will not catch this because they don't link the same set of
// init functions as the binary. This smoke test compiles `cmd/identity` and
// boots it, so any startup-time panic surfaces as a test failure.
package smoke

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// repoRoot returns the absolute path of the repository root (the directory
// containing go.mod), discovered by walking up from the test file's working
// directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod from %s", wd)
	return ""
}

// freePort asks the kernel for an unused TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// captureBuf is a thread-safe sink for the binary's stdout/stderr so that we
// can include the captured output in a test failure message without racing
// against the still-running goroutine that reads from the pipe.
type captureBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *captureBuf) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// waitReady polls url until it returns 200 OK or the deadline elapses. It
// also returns early if the supplied process exits, so a panic-at-startup
// fails fast instead of waiting the full timeout.
func waitReady(t *testing.T, url string, proc *os.Process, exited <-chan struct{}, deadline time.Duration) error {
	t.Helper()
	end := time.Now().Add(deadline)
	client := &http.Client{Timeout: 1 * time.Second}
	for time.Now().Before(end) {
		select {
		case <-exited:
			return errors.New("process exited before becoming ready")
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = proc // referenced for clarity; signalling is done by the caller
	return errors.New("timed out waiting for /health")
}

// TestBootSmoke compiles the identity binary, runs it with safe dev defaults,
// hits a few endpoints, and asserts a clean SIGTERM shutdown. Any non-zero
// exit before SIGTERM (e.g. a startup panic) fails the test with the
// captured stderr, which is the whole point of this test.
func TestBootSmoke(t *testing.T) {
	root := repoRoot(t)

	// 1. Build the binary.
	binPath := filepath.Join(t.TempDir(), "identity-smoke")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/identity")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	// 2. Pick free ports for the connect HTTP server and the metrics server.
	connectPort := freePort(t)
	metricsPort := freePort(t)

	// 3. Start the binary with dev-friendly env so it doesn't fatal on
	//    missing config. Each variable below is required:
	//
	//    GATEWAY_CONNECT_PORT  — main HTTP/Connect listener; randomised so
	//                            parallel runs don't collide and so the test
	//                            never needs root for port 80 (the default).
	//    GATEWAY_METRICS_PORT  — Prometheus metrics listener; same reasoning.
	//    GATEWAY_GRPC_PORT     — set even though the binary doesn't currently
	//                            bind a gRPC listener, to avoid the default
	//                            50051 colliding with anything else on the
	//                            host.
	//    GATEWAY_REPO_DRIVER=memory — boot against the in-process store so
	//                            the smoke test needs no external datastore.
	//    GATEWAY_DEFAULT_TENANT_ID — exercise the dev default explicitly.
	//    GATEWAY_JWT_SIGNER + GATEWAY_JWT_KEYS_FILE unset — triggers the
	//                            auto-generated dev RSA key path, which
	//                            is what we want to assert works.
	//    GATEWAY_TOTP_ENCRYPTION_KEY unset — falls back to the dev key.
	env := append(
		os.Environ(),
		"GATEWAY_CONNECT_PORT="+strconv.Itoa(connectPort),
		"GATEWAY_METRICS_PORT="+strconv.Itoa(metricsPort),
		"GATEWAY_GRPC_PORT="+strconv.Itoa(freePort(t)),
		"GATEWAY_REPO_DRIVER=memory",
		"GATEWAY_DEFAULT_TENANT_ID=smoke-test",
	)
	// Strip any pre-existing JWT/TOTP env so we genuinely exercise the
	// dev fallbacks the smoke test is meant to certify.
	env = append(env, "GATEWAY_JWT_SIGNER=", "GATEWAY_JWT_KEYS_FILE=", "GATEWAY_TOTP_ENCRYPTION_KEY=")

	cmd := exec.Command(binPath)
	cmd.Env = env
	cmd.Dir = root
	out := &captureBuf{}
	cmd.Stdout = out
	cmd.Stderr = out
	// Place the child in its own process group so we can clean it up
	// reliably even if it spawns helpers.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting binary: %v", err)
	}

	exited := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()

	// Always tidy up — kill the process group on early exit paths.
	t.Cleanup(func() {
		select {
		case <-exited:
			return
		default:
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
		}
	})

	baseURL := "http://127.0.0.1:" + strconv.Itoa(connectPort)

	// 4. Wait up to 15s for /health to come up, or fail fast if the
	//    process exits before that (which is the panic case we care about).
	if err := waitReady(t, baseURL+"/health", cmd.Process, exited, 15*time.Second); err != nil {
		t.Fatalf("readiness probe failed: %v\n--- captured output ---\n%s", err, out.String())
	}

	// 5a. /health → 200 with JSON body.
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("/health body unexpected: %s", body)
	}

	// 5b. /.well-known/jwks.json → 200 with a valid JWKS body containing at
	//     least one RSA key entry.
	resp, err = http.Get(baseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/.well-known/jwks.json status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("JWKS not valid JSON: %v\nbody=%s", err, body)
	}
	if len(jwks.Keys) == 0 {
		t.Fatalf("JWKS contains no keys; body=%s", body)
	}
	k := jwks.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Kid == "" || k.N == "" || k.E == "" {
		t.Fatalf("JWKS key is missing required fields: %+v", k)
	}

	// 5c. Connect-RPC PasswordSignup. Currently `cmd/identity/main.go` does
	//     NOT register the generated Connect handler with its mux (the
	//     registration is a TODO awaiting `buf generate` work). So the
	//     route falls through to the empty mux and we expect a 404.
	//
	//     What this assertion *does* prove:
	//       - the HTTP server is alive after handling /health and /jwks,
	//       - it can route a real Connect-RPC URL without crashing,
	//       - the binary is still running (we'll re-check below).
	//
	//     When the handler is wired up later, this assertion should be
	//     tightened to expect a Connect error response with the stub-
	//     persistence "service unavailable" message instead of 404.
	signupReq := bytes.NewBufferString(`{"email":"smoke@example.com","password":"unused-by-stub"}`)
	httpReq, err := http.NewRequest(http.MethodPost,
		baseURL+"/identity.v1.IdentityService/PasswordSignup", signupReq)
	if err != nil {
		t.Fatalf("build PasswordSignup request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("POST PasswordSignup: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("PasswordSignup returned 200 unexpectedly (handler should not be wired yet); body=%s", body)
	}
	if resp.StatusCode >= 500 && resp.StatusCode != http.StatusServiceUnavailable {
		// 5xx other than "service unavailable" indicates the server crashed
		// internally, which is exactly the kind of regression this test
		// exists to catch.
		t.Fatalf("PasswordSignup unexpected 5xx %d; body=%s\n--- captured output ---\n%s",
			resp.StatusCode, body, out.String())
	}

	// Sanity: ensure the process is still running before we send SIGTERM.
	select {
	case <-exited:
		t.Fatalf("process exited prematurely during smoke probes\n--- captured output ---\n%s", out.String())
	default:
	}

	// 6. Send SIGTERM and assert clean shutdown within 5 s.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("sending SIGTERM: %v", err)
	}
	select {
	case <-exited:
		// Identity binary exits 0 on a SIGTERM-driven graceful shutdown.
		if waitErr != nil {
			// Distinguish "killed by signal" (acceptable on some platforms)
			// from "non-zero exit" (a real failure).
			var ee *exec.ExitError
			if errors.As(waitErr, &ee) && ee.ExitCode() != 0 {
				t.Fatalf("non-zero exit after SIGTERM: %v\n--- captured output ---\n%s",
					waitErr, out.String())
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("process did not exit within 5s of SIGTERM\n--- captured output ---\n%s", out.String())
	}

	// 7. Final guard: even on a clean exit, panic text in stderr is a fail.
	captured := out.String()
	if strings.Contains(captured, "panic:") || strings.Contains(captured, "fatal error:") {
		t.Fatalf("binary printed panic/fatal during smoke run\n--- captured output ---\n%s", captured)
	}
}
