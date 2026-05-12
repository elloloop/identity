//go:build load

package load

import (
	"context"
	"fmt"
	"math"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passkeys"
)

const loadPassword = "Sw0rdfish!42"

type loadConfig struct {
	profile        string
	duration       time.Duration
	users          int
	loginRate      int
	refreshRate    int
	workers        int
	loginP99       time.Duration
	refreshP99     time.Duration
	maxErrorRate   float64
	minCountFactor float64
}

type loadHarness struct {
	client identityconnectgen.IdentityServiceClient
}

type loadUser struct {
	email        string
	refreshToken string
}

type opRecorder struct {
	mu      sync.Mutex
	latency map[string][]time.Duration
	errors  map[string]int
	errs    []string
}

func TestLoginRefreshHotPathLoad(t *testing.T) {
	cfg := loadConfigFromEnv(t)
	h := startLoadHarness(t)
	users := seedLoadUsers(t, h.client, cfg.users)

	t.Logf(
		"profile=%s duration=%s users=%d login_rps=%d refresh_rps=%d workers=%d login_p99=%s refresh_p99=%s max_error_rate=%.4f",
		cfg.profile,
		cfg.duration,
		cfg.users,
		cfg.loginRate,
		cfg.refreshRate,
		cfg.workers,
		cfg.loginP99,
		cfg.refreshP99,
		cfg.maxErrorRate,
	)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.duration+30*time.Second)
	defer cancel()

	rec := newOpRecorder()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runLoginLoad(ctx, h.client, users, cfg, rec)
	}()
	go func() {
		defer wg.Done()
		runRefreshLoad(ctx, h.client, users, cfg, rec)
	}()
	wg.Wait()

	assertOperation(t, rec, "login", cfg.loginRate, cfg.duration, cfg.minCountFactor, cfg.maxErrorRate, cfg.loginP99)
	assertOperation(t, rec, "refresh", cfg.refreshRate, cfg.duration, cfg.minCountFactor, cfg.maxErrorRate, cfg.refreshP99)
}

func loadConfigFromEnv(t *testing.T) loadConfig {
	t.Helper()

	profile := envString("IDENTITY_LOAD_PROFILE", "ci")
	cfg := loadConfig{
		profile:        profile,
		duration:       8 * time.Second,
		users:          64,
		loginRate:      20,
		refreshRate:    60,
		workers:        16,
		loginP99:       1500 * time.Millisecond,
		refreshP99:     1000 * time.Millisecond,
		maxErrorRate:   0,
		minCountFactor: 0.98,
	}
	if profile == "soak" {
		cfg.duration = 30 * time.Minute
		cfg.users = 512
		cfg.loginRate = 60
		cfg.refreshRate = 180
		cfg.workers = 96
		cfg.loginP99 = 450 * time.Millisecond
		cfg.refreshP99 = 350 * time.Millisecond
	} else if profile != "ci" {
		t.Fatalf("IDENTITY_LOAD_PROFILE must be ci or soak")
	}

	cfg.duration = envDuration(t, "IDENTITY_LOAD_DURATION", cfg.duration)
	cfg.users = envInt(t, "IDENTITY_LOAD_USERS", cfg.users)
	cfg.loginRate = envInt(t, "IDENTITY_LOAD_LOGIN_RPS", cfg.loginRate)
	cfg.refreshRate = envInt(t, "IDENTITY_LOAD_REFRESH_RPS", cfg.refreshRate)
	cfg.workers = envInt(t, "IDENTITY_LOAD_WORKERS", cfg.workers)
	cfg.loginP99 = time.Duration(envInt(t, "IDENTITY_LOAD_LOGIN_P99_MS", int(cfg.loginP99/time.Millisecond))) * time.Millisecond
	cfg.refreshP99 = time.Duration(envInt(t, "IDENTITY_LOAD_REFRESH_P99_MS", int(cfg.refreshP99/time.Millisecond))) * time.Millisecond
	cfg.maxErrorRate = envFloat(t, "IDENTITY_LOAD_MAX_ERROR_RATE", cfg.maxErrorRate)
	cfg.minCountFactor = envFloat(t, "IDENTITY_LOAD_MIN_COUNT_FACTOR", cfg.minCountFactor)

	if cfg.duration <= 0 {
		t.Fatalf("IDENTITY_LOAD_DURATION must be positive")
	}
	if cfg.users <= 0 {
		t.Fatalf("IDENTITY_LOAD_USERS must be positive")
	}
	if cfg.loginRate <= 0 {
		t.Fatalf("IDENTITY_LOAD_LOGIN_RPS must be positive")
	}
	if cfg.refreshRate <= 0 {
		t.Fatalf("IDENTITY_LOAD_REFRESH_RPS must be positive")
	}
	if cfg.workers <= 0 {
		t.Fatalf("IDENTITY_LOAD_WORKERS must be positive")
	}
	if cfg.workers > cfg.users {
		t.Fatalf("IDENTITY_LOAD_WORKERS (%d) must be <= IDENTITY_LOAD_USERS (%d)", cfg.workers, cfg.users)
	}
	if cfg.maxErrorRate < 0 || cfg.maxErrorRate > 1 {
		t.Fatalf("IDENTITY_LOAD_MAX_ERROR_RATE must be between 0 and 1")
	}
	if cfg.minCountFactor <= 0 || cfg.minCountFactor > 1 {
		t.Fatalf("IDENTITY_LOAD_MIN_COUNT_FACTOR must be in (0, 1]")
	}

	return cfg
}

func startLoadHarness(t *testing.T) *loadHarness {
	t.Helper()

	signingKey, err := jwt.GenerateKey("load-test-kid")
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	keyRing, err := jwt.NewKeyRing([]jwt.SigningKey{signingKey})
	if err != nil {
		t.Fatalf("build key ring: %v", err)
	}
	passkeysSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   "localhost",
		RPName: "IdentityLoadTests",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("init webauthn: %v", err)
	}

	cfg := &config.Config{
		DefaultTenantID:               "load-test",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "IdentityLoadTests",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Glassa Test",
		AllowedOrigins:                "http://localhost:9002",
		AppBaseURL:                    "https://app.test",
		EmailTokenExpirySeconds:       3600,
		SMTPFrom:                      "no-reply@test.local",
	}
	repo := memory.New()
	handler, stop, err := app.New(app.Deps{
		Config:         cfg,
		Logger:         zap.NewNop(),
		KeyRing:        keyRing,
		Repo:           repo,
		DB:             repo,
		Passkeys:       passkeysSvc,
		TOTPKey:        []byte("01234567890123456789012345678901"),
		EmailTransport: email.NewLogOnly(zap.NewNop()),
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(stop)

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	httpClient := server.Client()
	return &loadHarness{
		client: identityconnectgen.NewIdentityServiceClient(httpClient, server.URL),
	}
}

func seedLoadUsers(t *testing.T, client identityconnectgen.IdentityServiceClient, count int) []loadUser {
	t.Helper()

	users := make([]loadUser, count)
	for i := 0; i < count; i++ {
		email := fmt.Sprintf("load-%d@example.com", i)
		resp, err := client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
			Email:    email,
			Password: loadPassword,
		}))
		if err != nil {
			t.Fatalf("PasswordSignup(%s): %v", email, err)
		}
		if resp.Msg.GetAccessToken() == "" || resp.Msg.GetRefreshToken() == "" || resp.Msg.GetUser().GetId() == "" {
			t.Fatalf("PasswordSignup(%s) returned incomplete session", email)
		}
		users[i] = loadUser{
			email:        email,
			refreshToken: resp.Msg.GetRefreshToken(),
		}
	}
	return users
}

func runLoginLoad(
	ctx context.Context,
	client identityconnectgen.IdentityServiceClient,
	users []loadUser,
	cfg loadConfig,
	rec *opRecorder,
) {
	runRate(ctx, cfg.loginRate, cfg.duration, cfg.workers, func(worker, iteration int) {
		user := users[(worker+iteration)%len(users)]
		start := time.Now()
		resp, err := client.PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{
			Email:    user.email,
			Password: loadPassword,
		}))
		loginLatency := time.Since(start)
		if err != nil {
			rec.record("login", loginLatency, err)
			return
		}
		if resp.Msg.GetAccessToken() == "" || resp.Msg.GetRefreshToken() == "" || resp.Msg.GetUser().GetId() == "" {
			rec.record("login", loginLatency, fmt.Errorf("login returned incomplete session for %s", user.email))
			return
		}

		_, err = client.Logout(context.Background(), connect.NewRequest(&identitypb.LogoutRequest{
			RefreshToken: resp.Msg.GetRefreshToken(),
		}))
		rec.record("login", loginLatency, err)
	})
}

func runRefreshLoad(
	ctx context.Context,
	client identityconnectgen.IdentityServiceClient,
	users []loadUser,
	cfg loadConfig,
	rec *opRecorder,
) {
	type session struct {
		email        string
		refreshToken string
	}
	sessions := make([]session, cfg.workers)
	for i := range sessions {
		user := users[i%len(users)]
		sessions[i] = session{
			email:        user.email,
			refreshToken: user.refreshToken,
		}
	}

	var mu sync.Mutex
	runRate(ctx, cfg.refreshRate, cfg.duration, cfg.workers, func(worker, _ int) {
		mu.Lock()
		refreshToken := sessions[worker].refreshToken
		email := sessions[worker].email
		mu.Unlock()

		start := time.Now()
		resp, err := client.RefreshToken(context.Background(), connect.NewRequest(&identitypb.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}))
		if err != nil {
			rec.record("refresh", time.Since(start), err)
			return
		}
		if resp.Msg.GetAccessToken() == "" || resp.Msg.GetRefreshToken() == "" || resp.Msg.GetUser().GetId() == "" {
			rec.record("refresh", time.Since(start), fmt.Errorf("refresh returned incomplete session for %s", email))
			return
		}

		mu.Lock()
		sessions[worker].refreshToken = resp.Msg.GetRefreshToken()
		mu.Unlock()
		rec.record("refresh", time.Since(start), nil)
	})
}

func runRate(ctx context.Context, rate int, duration time.Duration, workers int, fn func(worker, iteration int)) {
	total := int(math.Floor(duration.Seconds() * float64(rate)))
	jobs := make([]chan int, workers)

	var wg sync.WaitGroup
	for i := range jobs {
		jobs[i] = make(chan int, total/workers+2)
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iteration := range jobs[worker] {
				fn(worker, iteration)
			}
		}(i)
	}

	interval := time.Second / time.Duration(rate)
	next := time.Now()
	for i := 0; i < total; i++ {
		select {
		case <-ctx.Done():
			for _, ch := range jobs {
				close(ch)
			}
			wg.Wait()
			return
		default:
		}

		sleepFor := time.Until(next)
		if sleepFor > 0 {
			timer := time.NewTimer(sleepFor)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				for _, ch := range jobs {
					close(ch)
				}
				wg.Wait()
				return
			}
		}
		jobs[i%workers] <- i
		next = next.Add(interval)
	}

	for _, ch := range jobs {
		close(ch)
	}
	wg.Wait()
}

func newOpRecorder() *opRecorder {
	return &opRecorder{
		latency: make(map[string][]time.Duration),
		errors:  make(map[string]int),
	}
}

func (r *opRecorder) record(name string, latency time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.latency[name] = append(r.latency[name], latency)
	if err != nil {
		r.errors[name]++
		if len(r.errs) < 10 {
			r.errs = append(r.errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
}

func assertOperation(
	t *testing.T,
	rec *opRecorder,
	name string,
	rate int,
	duration time.Duration,
	minCountFactor float64,
	maxErrorRate float64,
	maxP99 time.Duration,
) {
	t.Helper()

	rec.mu.Lock()
	samples := append([]time.Duration(nil), rec.latency[name]...)
	errors := rec.errors[name]
	errs := append([]string(nil), rec.errs...)
	rec.mu.Unlock()

	if len(samples) == 0 {
		t.Fatalf("%s recorded no samples", name)
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	total := len(samples)
	expected := int(math.Floor(duration.Seconds() * float64(rate) * minCountFactor))
	if total < expected {
		t.Fatalf("%s total samples = %d, want at least %d", name, total, expected)
	}

	errRate := float64(errors) / float64(total)
	if errRate > maxErrorRate {
		t.Fatalf("%s error rate = %.4f (%d/%d), want <= %.4f; first errors: %v", name, errRate, errors, total, maxErrorRate, errs)
	}

	p99 := percentile(samples, 0.99)
	if p99 > maxP99 {
		t.Fatalf("%s p99 = %s, want <= %s (samples=%d)", name, p99, maxP99, total)
	}

	t.Logf("%s samples=%d errors=%d p50=%s p95=%s p99=%s max=%s", name, total, errors, percentile(samples, 0.50), percentile(samples, 0.95), p99, samples[len(samples)-1])
}

func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(len(samples))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(samples) {
		idx = len(samples) - 1
	}
	return samples[idx]
}

func envString(name, fallback string) string {
	if raw := os.Getenv(name); raw != "" {
		return raw
	}
	return fallback
}

func envDuration(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()

	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		t.Fatalf("%s must be a Go duration: %v", name, err)
	}
	return value
}

func envInt(t *testing.T, name string, fallback int) int {
	t.Helper()

	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s must be an integer: %v", name, err)
	}
	return value
}

func envFloat(t *testing.T, name string, fallback float64) float64 {
	t.Helper()

	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("%s must be a number: %v", name, err)
	}
	return value
}
