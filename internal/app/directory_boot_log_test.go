package app

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// The boot log says whether LookupUsers is served, the way SCIM's does, and
// when it is, with the throttle and verified-email rule it runs under — so an
// operator can confirm the effective limit without reading the environment.
func TestBuildDirectoryService_LogsBootState(t *testing.T) {
	cfg := &config.Config{
		RateLimitDirectoryPerIP:  250,
		RateLimitWindowSeconds:   30,
		AuthRequireVerifiedEmail: true,
	}

	t.Run("enabled", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		deps := Deps{Config: cfg, DirectoryCredentials: chainCredentials{cred: &service.AdminProjectCredential{}}}
		if svc := buildDirectoryService(deps, memory.New(), nil, zap.New(core)); svc == nil {
			t.Fatal("a build with directory credentials must serve LookupUsers")
		}
		entries := logs.FilterMessage("directory_lookup_enabled").All()
		if len(entries) != 1 {
			t.Fatalf("directory_lookup_enabled logged %d times, want once", len(entries))
		}
		fields := entries[0].ContextMap()
		if fields["rate_limit_per_ip"] != int64(250) || fields["rate_limit_window"] != 30*time.Second ||
			fields["require_verified_email"] != true {
			t.Fatalf("directory_lookup_enabled fields = %v", fields)
		}
		if n := logs.FilterMessage("directory_lookup_disabled").Len(); n != 0 {
			t.Fatalf("an enabled build also logged directory_lookup_disabled")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		if svc := buildDirectoryService(Deps{Config: cfg}, memory.New(), nil, zap.New(core)); svc != nil {
			t.Fatal("a build without directory credentials must not serve LookupUsers")
		}
		if n := logs.FilterMessage("directory_lookup_disabled").Len(); n != 1 {
			t.Fatalf("directory_lookup_disabled logged %d times, want once", n)
		}
		if n := logs.FilterMessage("directory_lookup_enabled").Len(); n != 0 {
			t.Fatalf("a disabled build also logged directory_lookup_enabled")
		}
	})
}
