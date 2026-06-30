//go:build smoke

// Package smoke — config setup-matrix.
//
// This file complements boot_test.go with a table of "boot the real
// cmd/identity binary against a specific config and assert it either
// refuses to start or comes up clean". It exists because several of the
// service's conditionally-required config invariants are enforced at
// BOOT (inside identityserver.New / repo.Build), NOT inside
// config.Config.Validate(). A unit test that only calls Validate() would
// pass while the binary still fatals (or, worse, silently mis-wires) —
// exactly the doc/code mismatch class this matrix is meant to catch.
//
// Where each invariant is enforced (confirmed against the source):
//
//	TOTP recovery pepper required when encryption key set
//	    BOOT — identityserver/adapters.go decodeTOTPRecoveryPepper,
//	    called from identityserver/server.go New(). NOT in Validate().
//	sqlite driver requires a path
//	    BOOT — internal/repo/driver.go Build() (the guard fires before
//	    internal/repo/sqlite/config.go validate()). NOT in Validate().
//	jwt file signer must load a usable keys file
//	    BOOT — pkg/jwt/file New() via identityserver/adapters.go
//	    buildFileSigner. NOT in Validate().
//	Apple OAuth all-or-nothing
//	    BOOT — internal/app/oauth.go buildOAuthRegistry: a partial
//	    credential set is silently skipped (provider simply not
//	    registered), it does NOT fail boot.
//
// Reuses the harness helpers from boot_test.go (same package, same
// `smoke` tag): repoRoot, freePort, captureBuf, waitReady. New helpers
// added here are `cfg`-prefixed to avoid colliding with that file.
package smoke

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
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

// cfgBinOnce guards a single `go build` of the identity binary that every
// case in this file shares. Building once keeps the matrix fast.
var (
	cfgBinOnce sync.Once
	cfgBinPath string
	cfgBinErr  error
)

// cfgBuildBinary compiles cmd/identity exactly once (CGO disabled, matching
// boot_test.go and the scratch container image) and returns the path.
func cfgBuildBinary(t *testing.T) string {
	t.Helper()
	cfgBinOnce.Do(func() {
		root := repoRoot(t)
		// A process-wide temp dir (not t.TempDir) so the binary outlives the
		// test that happened to trigger the build under the shared sync.Once.
		dir, err := os.MkdirTemp("", "identity-cfg-smoke")
		if err != nil {
			cfgBinErr = err
			return
		}
		bin := filepath.Join(dir, "identity-cfg-smoke")
		build := exec.Command("go", "build", "-o", bin, "./cmd/identity")
		build.Dir = root
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, berr := build.CombinedOutput(); berr != nil {
			cfgBinErr = errors.New("go build failed: " + berr.Error() + "\n" + string(out))
			return
		}
		cfgBinPath = bin
	})
	if cfgBinErr != nil {
		t.Fatalf("building identity binary: %v", cfgBinErr)
	}
	return cfgBinPath
}

// cfgEnv builds the child process environment: the inherited environment
// with every GATEWAY_* var stripped (so the developer's own shell config
// can't perturb a case), then the shared boot defaults, then the
// case-specific overrides — later writes win.
func cfgEnv(t *testing.T, overrides map[string]string) (env []string, connectPort int) {
	t.Helper()
	connectPort = freePort(t)

	base := map[string]string{
		"GATEWAY_CONNECT_PORT":      strconv.Itoa(connectPort),
		"GATEWAY_METRICS_PORT":      strconv.Itoa(freePort(t)),
		"GATEWAY_GRPC_PORT":         strconv.Itoa(freePort(t)),
		"GATEWAY_REPO_DRIVER":       "memory",
		"GATEWAY_DEFAULT_TENANT_ID": "cfg-smoke",
	}
	for k, v := range overrides {
		base[k] = v
	}

	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GATEWAY_") {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range base {
		env = append(env, k+"="+v)
	}
	return env, connectPort
}

// cfgStart launches the binary with the given environment and wires up
// output capture, an exit channel, and a cleanup that kills the process
// group. It mirrors the lifecycle handling in boot_test.go's TestBootSmoke.
func cfgStart(t *testing.T, env []string) (out *captureBuf, exited <-chan struct{}, waitErr *error, cmd *exec.Cmd) {
	t.Helper()
	root := repoRoot(t)

	cmd = exec.Command(cfgBuildBinary(t))
	cmd.Env = env
	cmd.Dir = root
	out = &captureBuf{}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting binary: %v", err)
	}

	done := make(chan struct{})
	we := new(error)
	go func() {
		*we = cmd.Wait()
		close(done)
	}()

	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})

	return out, done, we, cmd
}

// cfgAssertContains fails the test unless every wanted substring is present
// in the captured output.
func cfgAssertContains(t *testing.T, out *captureBuf, want []string) {
	t.Helper()
	captured := out.String()
	for _, w := range want {
		if !strings.Contains(captured, w) {
			t.Fatalf("expected output to contain %q\n--- captured output ---\n%s", w, captured)
		}
	}
}

// cfgExpectBootFailure starts the binary and asserts it exits non-zero
// within the deadline, with every wanted substring in its output.
func cfgExpectBootFailure(t *testing.T, env []string, want []string) {
	t.Helper()
	out, exited, waitErr, _ := cfgStart(t, env)

	select {
	case <-exited:
	case <-time.After(20 * time.Second):
		t.Fatalf("expected boot to fail fast, but process is still running\n--- captured output ---\n%s", out.String())
	}

	var ee *exec.ExitError
	if !errors.As(*waitErr, &ee) || ee.ExitCode() == 0 {
		t.Fatalf("expected non-zero exit, got err=%v\n--- captured output ---\n%s", *waitErr, out.String())
	}
	cfgAssertContains(t, out, want)
}

// cfgExpectBootClean starts the binary, waits for /health, runs an optional
// extra probe, asserts wanted substrings, then SIGTERMs and asserts a clean
// (zero / signal) exit with no panic.
func cfgExpectBootClean(t *testing.T, env []string, connectPort int, want []string, onReady func(t *testing.T, baseURL string)) {
	t.Helper()
	out, exited, waitErr, cmd := cfgStart(t, env)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(connectPort)

	if err := waitReady(t, baseURL+"/health", cmd.Process, exited, 20*time.Second); err != nil {
		t.Fatalf("readiness probe failed: %v\n--- captured output ---\n%s", err, out.String())
	}

	if onReady != nil {
		onReady(t, baseURL)
	}
	cfgAssertContains(t, out, want)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("sending SIGTERM: %v", err)
	}
	select {
	case <-exited:
		var ee *exec.ExitError
		if errors.As(*waitErr, &ee) && ee.ExitCode() != 0 {
			t.Fatalf("non-zero exit after SIGTERM: %v\n--- captured output ---\n%s", *waitErr, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("process did not exit within 5s of SIGTERM\n--- captured output ---\n%s", out.String())
	}

	if captured := out.String(); strings.Contains(captured, "panic:") || strings.Contains(captured, "fatal error:") {
		t.Fatalf("binary printed panic/fatal during run\n--- captured output ---\n%s", captured)
	}
}

// cfgValidTOTPKey returns a base64-encoded 32-byte TOTP encryption key so
// decodeTOTPKey passes and the test exercises the *next* gate (the recovery
// pepper requirement) rather than failing on key decode.
func cfgValidTOTPKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

// cfgWriteKeysFile writes a one-entry pkg/jwt/file keys document with a
// freshly-generated RSA-2048 key, in-force now, and returns the file path
// and the kid it stamped. Format matches pkg/jwt/file/signer.go keysFile.
func cfgWriteKeysFile(t *testing.T, kid string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	now := time.Now().UTC()
	doc := map[string]any{
		"keys": []map[string]string{
			{
				"kid":             kid,
				"not_before":      now.Add(-time.Hour).Format(time.RFC3339),
				"expires_at":      now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
				"private_key_pem": string(privPEM),
			},
		},
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal keys file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
	return path
}

// cfgFetchJWKS fetches /.well-known/jwks.json and returns the decoded kids.
func cfgFetchJWKS(t *testing.T, baseURL string) []string {
	t.Helper()
	resp, err := http.Get(baseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("jwks not JSON: %v\nbody=%s", err, body)
	}
	kids := make([]string, 0, len(jwks.Keys))
	for _, k := range jwks.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

// TestConfigSetupMatrix is the table: each case boots the real binary with a
// targeted config and asserts the documented enforcement actually happens.
func TestConfigSetupMatrix(t *testing.T) {
	// Case 1 — NEGATIVE: TOTP encryption key set, recovery pepper unset.
	// Enforced at BOOT (adapters.go decodeTOTPRecoveryPepper), not Validate().
	t.Run("totp_encryption_key_without_recovery_pepper_fails", func(t *testing.T) {
		t.Parallel()
		env, _ := cfgEnv(t, map[string]string{
			"GATEWAY_TOTP_ENCRYPTION_KEY": cfgValidTOTPKey(),
			// GATEWAY_TOTP_RECOVERY_PEPPER deliberately unset.
		})
		cfgExpectBootFailure(t, env, []string{
			"GATEWAY_TOTP_RECOVERY_PEPPER is required when GATEWAY_TOTP_ENCRYPTION_KEY is set",
		})
	})

	// Case 2 — NEGATIVE: sqlite driver with no path.
	// Enforced at BOOT (repo/driver.go Build guard), not Validate().
	t.Run("sqlite_driver_without_path_fails", func(t *testing.T) {
		t.Parallel()
		env, _ := cfgEnv(t, map[string]string{
			"GATEWAY_REPO_DRIVER": "sqlite",
			// GATEWAY_SQLITE_PATH deliberately unset.
		})
		// The driver.go guard fires before sqlite/config.go's own check; pin
		// the message the code actually emits.
		cfgExpectBootFailure(t, env, []string{
			"sqlite driver requires SQLitePath",
		})
	})

	// Case 3 — POSITIVE: sqlite driver with an in-memory database boots clean.
	// modernc.org/sqlite is pure Go, so CGO_ENABLED=0 is fine; if a future
	// build needs CGO and lacks it, we detect the failure and skip.
	t.Run("sqlite_driver_with_memory_path_boots", func(t *testing.T) {
		t.Parallel()
		env, port := cfgEnv(t, map[string]string{
			"GATEWAY_REPO_DRIVER": "sqlite",
			"GATEWAY_SQLITE_PATH": ":memory:",
		})
		// Run the positive flow, but tolerate a CGO-unavailable environment.
		out, exited, waitErr, cmd := cfgStart(t, env)
		baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
		if err := waitReady(t, baseURL+"/health", cmd.Process, exited, 20*time.Second); err != nil {
			captured := out.String()
			if strings.Contains(strings.ToLower(captured), "cgo") || strings.Contains(captured, "requires cgo") {
				t.Skipf("sqlite driver unavailable without CGO in this build: %v", err)
			}
			t.Fatalf("sqlite boot readiness failed: %v\n--- captured output ---\n%s", err, captured)
		}
		// Healthy: tidy shutdown.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
			var ee *exec.ExitError
			if errors.As(*waitErr, &ee) && ee.ExitCode() != 0 {
				t.Fatalf("non-zero exit after SIGTERM: %v\n%s", *waitErr, out.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("sqlite process did not exit within 5s of SIGTERM\n%s", out.String())
		}
	})

	// Case 4 — POSITIVE: file JWT signer with a valid keys file boots, and the
	// configured kid is served on the JWKS endpoint.
	t.Run("jwt_file_signer_with_valid_keys_boots", func(t *testing.T) {
		t.Parallel()
		const kid = "cfg-matrix-key"
		keysPath := cfgWriteKeysFile(t, kid)
		env, port := cfgEnv(t, map[string]string{
			"GATEWAY_JWT_SIGNER":    "file",
			"GATEWAY_JWT_KEYS_FILE": keysPath,
		})
		cfgExpectBootClean(t, env, port,
			[]string{"jwt_signer_file"},
			func(t *testing.T, baseURL string) {
				kids := cfgFetchJWKS(t, baseURL)
				found := false
				for _, k := range kids {
					if k == kid {
						found = true
					}
				}
				if !found {
					t.Fatalf("JWKS did not advertise configured kid %q; got %v", kid, kids)
				}
			})
	})

	// Case 5 — NEGATIVE: file JWT signer pointed at a garbage (unparseable)
	// keys file. Enforced at BOOT (pkg/jwt/file New), not Validate().
	t.Run("jwt_file_signer_with_garbage_keys_fails", func(t *testing.T) {
		t.Parallel()
		badPath := filepath.Join(t.TempDir(), "garbage.json")
		if err := os.WriteFile(badPath, []byte("this is not json {{{"), 0o600); err != nil {
			t.Fatalf("write garbage keys file: %v", err)
		}
		env, _ := cfgEnv(t, map[string]string{
			"GATEWAY_JWT_SIGNER":    "file",
			"GATEWAY_JWT_KEYS_FILE": badPath,
		})
		cfgExpectBootFailure(t, env, []string{
			"parsing keys file",
		})
	})

	// Case 5b — NEGATIVE: file JWT signer pointed at a missing file.
	t.Run("jwt_file_signer_with_missing_keys_fails", func(t *testing.T) {
		t.Parallel()
		missingPath := filepath.Join(t.TempDir(), "does-not-exist.json")
		env, _ := cfgEnv(t, map[string]string{
			"GATEWAY_JWT_SIGNER":    "file",
			"GATEWAY_JWT_KEYS_FILE": missingPath,
		})
		cfgExpectBootFailure(t, env, []string{
			"reading keys file",
		})
	})

	// Case 6 — BEHAVIORAL: partial Apple OAuth credentials. buildOAuthRegistry
	// registers Apple only when ALL of client id / team id / key id / private
	// key are set; a partial set is SILENTLY skipped (not a boot failure). With
	// no other provider configured, the registry is empty and the binary logs
	// oauth_disabled_no_providers_configured and boots clean. This pins the
	// "silently not registered" behavior so a future change to fail-closed
	// would trip this test.
	t.Run("partial_apple_oauth_creds_silently_skipped_and_boots", func(t *testing.T) {
		t.Parallel()
		env, port := cfgEnv(t, map[string]string{
			"GATEWAY_OAUTH_APPLE_CLIENT_ID": "com.example.app",
			// team id / key id / private key deliberately unset.
		})
		cfgExpectBootClean(t, env, port,
			[]string{"oauth_disabled_no_providers_configured"},
			nil)
	})
}
