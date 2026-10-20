package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/observability/otlplogtest"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/sms"
)

// runMainEnv, when set, makes this test binary run main() with the value's
// fields as its arguments, so a test can drive the real command's exit paths
// in a child process.
const runMainEnv = "IDENTITY_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if args, ok := os.LookupEnv(runMainEnv); ok {
		os.Args = append([]string{"identity"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runIdentity runs main() in a child process with args and env (on top of
// the test's environment) and returns its exit code and stderr.
func runIdentity(t *testing.T, args string, env ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // G204: re-runs this test binary itself
	cmd.Env = append(os.Environ(), append([]string{runMainEnv + "=" + args}, env...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stderr.String()
	default:
		t.Fatalf("run identity %s: %v", args, err)
		return 0, ""
	}
}

// exportOn is the environment that turns the log export on towards url.
func exportOn(url string) []string {
	return []string{"GATEWAY_OTEL_LOGS_ENABLED=true", "GATEWAY_OTEL_LOGS_ENDPOINT=" + url}
}

func bodies(c *otlplogtest.Collector) map[string]bool {
	got := map[string]bool{}
	for _, rec := range c.Records() {
		got[rec.Body] = true
	}
	return got
}

// Every early exit of the command flushes the export before os.Exit, which
// skips deferred calls: the migrate job's, a bad subcommand's, and Fatal's.
func TestMain_EveryExitPathFlushesTheExport(t *testing.T) {
	cases := []struct {
		name     string
		args     string
		env      []string
		wantCode int
		wantLogs []string
	}{
		{
			name:     "migrate job",
			args:     "migrate",
			env:      []string{"GATEWAY_POSTGRES_DSN="},
			wantCode: 1,
			wantLogs: []string{"log_export_enabled", "identity_migrate_starting", "identity_migrate_failed"},
		},
		{
			name:     "migrate with bad arguments",
			args:     "migrate bogus",
			wantCode: 2,
			wantLogs: []string{"identity_migrate_bad_arguments"},
		},
		{
			name:     "unknown subcommand",
			args:     "bogus",
			wantCode: 2,
			wantLogs: []string{"identity_unknown_subcommand"},
		},
		{
			name:     "fatal at boot",
			args:     "",
			env:      []string{"GATEWAY_REPO_DRIVER=bogus"},
			wantCode: 1,
			wantLogs: []string{"identity_service_starting", "identity_server_init_failed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector := otlplogtest.New(t)
			code, stderr := runIdentity(t, tc.args, append(exportOn(collector.URL), tc.env...)...)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, tc.wantCode, stderr)
			}
			got := bodies(collector)
			for _, want := range tc.wantLogs {
				if !got[want] {
					t.Errorf("collector did not receive %q (got %v)", want, got)
				}
				if !strings.Contains(stderr, `"msg":"`+want+`"`) {
					t.Errorf("stderr lacks %q; the process's own output must keep every line:\n%s", want, stderr)
				}
			}
		})
	}
}

// The export is on only when GATEWAY_OTEL_LOGS_ENABLED says so: an endpoint
// alone, or the SDK's standard variable a platform may inject, changes nothing.
func TestMain_WithoutTheSwitchNothingIsExported(t *testing.T) {
	collector := otlplogtest.New(t)
	for name, env := range map[string][]string{
		"switch unset, endpoint set":   {"GATEWAY_OTEL_LOGS_ENABLED=", "GATEWAY_OTEL_LOGS_ENDPOINT=" + collector.URL},
		"switch false, endpoint set":   {"GATEWAY_OTEL_LOGS_ENABLED=false", "GATEWAY_OTEL_LOGS_ENDPOINT=" + collector.URL},
		"standard SDK variable only":   {"GATEWAY_OTEL_LOGS_ENABLED=", "OTEL_EXPORTER_OTLP_ENDPOINT=" + collector.URL},
		"standard SDK variable, bogus": {"GATEWAY_OTEL_LOGS_ENABLED=", "OTEL_EXPORTER_OTLP_ENDPOINT=collector.example.test:4317"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stderr := runIdentity(t, "bogus", env...)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2; stderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, `"level":"error"`) || !strings.Contains(stderr, `"msg":"identity_unknown_subcommand"`) {
				t.Fatalf("stderr lacks the production JSON line:\n%s", stderr)
			}
			if strings.Contains(stderr, "log_export_enabled") {
				t.Fatalf("the export turned on without its switch:\n%s", stderr)
			}
		})
	}
	if n := len(collector.Records()); n != 0 {
		t.Fatalf("collector received %d records without the switch, want 0", n)
	}
}

func TestMain_AnEnabledExportWithABadEndpointStopsBoot(t *testing.T) {
	for _, endpoint := range []string{"", "user:s3cret@collector.example.test:4318"} {
		t.Run(fmt.Sprintf("endpoint %q", endpoint), func(t *testing.T) {
			code, stderr := runIdentity(t, "", "GATEWAY_OTEL_LOGS_ENABLED=true", "GATEWAY_OTEL_LOGS_ENDPOINT="+endpoint)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1; stderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, "identity: build the logger") || !strings.Contains(stderr, "GATEWAY_OTEL_LOGS_ENDPOINT") {
				t.Fatalf("stderr does not name the bad setting:\n%s", stderr)
			}
			if strings.Contains(stderr, "s3cret") {
				t.Fatalf("the boot error repeats the endpoint's credential:\n%s", stderr)
			}
			if strings.Contains(stderr, "identity_service_starting") {
				t.Fatalf("the service started with a bad export endpoint:\n%s", stderr)
			}
		})
	}
}

func TestNewLogger_ExportsTheLinesTheLoggerKeeps(t *testing.T) {
	prev := otel.GetErrorHandler()
	t.Cleanup(func() { otel.SetErrorHandler(prev) })
	collector := otlplogtest.New(t)

	logger, closeLogger, err := newLogger(context.Background(), &config.Config{OTelLogsEnabled: true, OTelLogsEndpoint: collector.URL})
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	logger.Debug("below_production_level")
	logger.Info("kept_line")
	const repeats = 300
	for range repeats {
		logger.Info("repeated_line")
	}
	closeLogger()

	var kept, repeated int
	for _, rec := range collector.Records() {
		switch rec.Body {
		case "kept_line":
			kept++
		case "repeated_line":
			repeated++
		case "below_production_level":
			t.Errorf("a debug line was exported; the production logger drops it")
		}
	}
	if kept != 1 {
		t.Errorf("kept_line exported %d times, want 1", kept)
	}
	if repeated == 0 || repeated >= repeats {
		t.Errorf("repeated_line exported %d of %d times, want the production sampler to thin it", repeated, repeats)
	}
}

// A message dropped by the log-only email or SMS sender (no provider, or every
// SMTP provider failed) holds a live credential; with the export on, neither
// it nor the full recipient may reach the collector.
func TestNewLogger_ADroppedSignInMessageNeverExportsItsCredential(t *testing.T) {
	prev := otel.GetErrorHandler()
	t.Cleanup(func() { otel.SetErrorHandler(prev) })
	collector := otlplogtest.New(t)

	logger, closeLogger, err := newLogger(context.Background(), &config.Config{OTelLogsEnabled: true, OTelLogsEndpoint: collector.URL})
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	const (
		address = "alice@example.com"
		number  = "+14155550123"
		code    = "731904"
		token   = "s3cr3t-reset-token"
	)
	ctx := context.Background()
	if err := email.NewLogOnly(logger).Send(ctx, email.Message{To: address, Subject: "Your sign-in code", Text: "Your code is " + code}); err != nil {
		t.Fatalf("email Send: %v", err)
	}
	if err := email.NewLogOnly(logger).Send(ctx, email.Message{To: address, Subject: "Reset your password", HTML: `<a href="https://auth.example.test/reset?token=` + token + `">Reset</a>`}); err != nil {
		t.Fatalf("email Send: %v", err)
	}
	if err := sms.NewLogOnly(logger).Send(ctx, sms.Message{To: number, Body: "Your verification code is " + code}); err != nil {
		t.Fatalf("sms Send: %v", err)
	}
	closeLogger()

	got := collector.Records()
	dropped := 0
	for _, rec := range got {
		if rec.Body == "email_disabled_no_transport" || rec.Body == "sms_disabled_no_sender" {
			dropped++
		}
		values := []string{rec.Body}
		for _, v := range rec.Attributes {
			values = append(values, v)
		}
		for _, v := range values {
			for _, secret := range []string{code, token, address, number} {
				if strings.Contains(v, secret) {
					t.Errorf("record %q exported %q", rec.Body, secret)
				}
			}
		}
	}
	if dropped != 3 {
		t.Fatalf("collector received %d dropped-message lines (records %+v), want 3", dropped, got)
	}
}

func TestFlushThenExit_FlushesBeforeExiting(t *testing.T) {
	var calls []string
	hook := flushThenExit{
		flush: func() { calls = append(calls, "flush") },
		exit:  func(code int) { calls = append(calls, fmt.Sprintf("exit %d", code)) },
	}
	hook.OnWrite(nil, nil)
	if len(calls) != 2 || calls[0] != "flush" || calls[1] != "exit 1" {
		t.Fatalf("calls = %v, want flush then exit 1", calls)
	}
}
