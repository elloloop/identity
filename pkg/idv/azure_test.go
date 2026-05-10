package idv_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/idv"
)

func newAzureFake(t *testing.T, handler http.HandlerFunc) (*idv.AzureProvider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p, err := idv.NewAzureProvider(idv.AzureConfig{
		Endpoint:   srv.URL,
		Key:        "test-key",
		SessionTTL: 30 * time.Second,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewAzureProvider: %v", err)
	}
	return p, srv
}

func TestAzure_NewAzureProvider_RequiresEndpointAndKey(t *testing.T) {
	t.Parallel()

	if _, err := idv.NewAzureProvider(idv.AzureConfig{Key: "k"}); err == nil {
		t.Fatal("missing endpoint should error")
	}
	if _, err := idv.NewAzureProvider(idv.AzureConfig{Endpoint: "https://x"}); err == nil {
		t.Fatal("missing key should error")
	}
}

func TestAzure_Name(t *testing.T) {
	t.Parallel()
	p, _ := idv.NewAzureProvider(idv.AzureConfig{Endpoint: "https://x", Key: "k"})
	if p.Name() != "azure" {
		t.Fatalf("Name = %q; want azure", p.Name())
	}
}

func TestAzure_BeginVerification_Success(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/detectLiveness/singleModal/sessions") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Ocp-Apim-Subscription-Key"); got != "test-key" {
			t.Errorf("subscription key = %q", got)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["livenessOperationMode"] != "Passive" {
			t.Errorf("operation mode = %v", body["livenessOperationMode"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"sessionId": "sess-1",
			"authToken": "tok-1",
		})
	})

	got, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if err != nil {
		t.Fatalf("BeginVerification: %v", err)
	}
	if got.ProviderSessionID != "sess-1" || got.SessionToken != "tok-1" {
		t.Fatalf("session: %+v", got)
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Fatalf("ExpiresAt not in future: %v", got.ExpiresAt)
	}
}

func TestAzure_BeginVerification_HTTPError(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	})

	_, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if !errors.Is(err, idv.ErrProviderUnavailable) {
		t.Fatalf("err = %v; want ErrProviderUnavailable", err)
	}
}

func TestAzure_BeginVerification_EmptyResponse(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	})

	_, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if !errors.Is(err, idv.ErrProviderUnavailable) {
		t.Fatalf("err = %v; want ErrProviderUnavailable on empty response", err)
	}
}

func TestAzure_GetVerification_RealFace(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{
		  "status": "Succeeded",
		  "results": { "result": { "response": { "body": {
		    "livenessDecision": "realface"
		  }}}}}`)
	})

	got, err := p.GetVerification(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != idv.StatusApproved {
		t.Fatalf("Status = %q; want approved", got.Status)
	}
	if got.CompletedAt.IsZero() {
		t.Fatal("CompletedAt unset")
	}
}

func TestAzure_GetVerification_SpoofFace(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{
		  "status": "Succeeded",
		  "results": { "result": { "response": { "body": {
		    "livenessDecision": "spoofface"
		  }}}}}`)
	})

	got, err := p.GetVerification(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != idv.StatusRejected || got.RejectionReason != "spoof_face" {
		t.Fatalf("got = %+v", got)
	}
}

func TestAzure_GetVerification_Uncertain(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{
		  "status": "Succeeded",
		  "results": { "result": { "response": { "body": {
		    "livenessDecision": "uncertain"
		  }}}}}`)
	})

	got, _ := p.GetVerification(context.Background(), "sess-1")
	if got.Status != idv.StatusRejected || got.RejectionReason != "liveness_uncertain" {
		t.Fatalf("got = %+v", got)
	}
}

func TestAzure_GetVerification_Pending(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"NotStarted"}`)
	})

	got, _ := p.GetVerification(context.Background(), "sess-1")
	if got.Status != idv.StatusPending {
		t.Fatalf("Status = %q; want pending", got.Status)
	}
}

func TestAzure_GetVerification_Running(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"Running"}`)
	})

	got, _ := p.GetVerification(context.Background(), "sess-1")
	if got.Status != idv.StatusInReview {
		t.Fatalf("Status = %q; want in_review", got.Status)
	}
}

func TestAzure_GetVerification_Failed(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{
		  "status": "Failed",
		  "results": { "attemptStatus": "TimedOut" }
		}`)
	})

	got, _ := p.GetVerification(context.Background(), "sess-1")
	if got.Status != idv.StatusRejected || !strings.Contains(got.RejectionReason, "TimedOut") {
		t.Fatalf("got = %+v", got)
	}
}

func TestAzure_GetVerification_NotFound(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, err := p.GetVerification(context.Background(), "sess-1")
	if !errors.Is(err, idv.ErrSessionNotFound) {
		t.Fatalf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestAzure_GetVerification_Empty(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := p.GetVerification(context.Background(), "")
	if !errors.Is(err, idv.ErrSessionNotFound) {
		t.Fatalf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestAzure_GetVerification_HTTPError(t *testing.T) {
	t.Parallel()

	p, _ := newAzureFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := p.GetVerification(context.Background(), "sess-1")
	if !errors.Is(err, idv.ErrProviderUnavailable) {
		t.Fatalf("err = %v; want ErrProviderUnavailable", err)
	}
}
