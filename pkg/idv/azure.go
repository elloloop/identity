package idv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AzureConfig configures an AzureProvider. Endpoint is the Cognitive
// Services endpoint URL (e.g. https://my-face.cognitiveservices.azure.com)
// and Key is the subscription key.
type AzureConfig struct {
	Endpoint   string
	Key        string
	SessionTTL time.Duration // session token validity; default 10m
	HTTPClient *http.Client  // optional override for tests
}

// AzureProvider implements Provider using Azure AI Face Liveness
// Detection (passive + active liveness). Document OCR + face-match
// against the document can be layered on top in a follow-up.
//
// API reference:
//
//	POST {endpoint}/face/v1.2-preview.1/detectLiveness/singleModal/sessions
//	GET  {endpoint}/face/v1.2-preview.1/detectLiveness/singleModal/sessions/{id}
type AzureProvider struct {
	endpoint   string
	key        string
	sessionTTL time.Duration
	client     *http.Client
}

// NewAzureProvider returns an AzureProvider. Endpoint and Key are
// required; everything else is filled in with sensible defaults.
func NewAzureProvider(cfg AzureConfig) (*AzureProvider, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("idv/azure: endpoint required")
	}
	if cfg.Key == "" {
		return nil, errors.New("idv/azure: key required")
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	return &AzureProvider{
		endpoint:   strings.TrimRight(cfg.Endpoint, "/"),
		key:        cfg.Key,
		sessionTTL: ttl,
		client:     c,
	}, nil
}

// Name implements Provider.
func (p *AzureProvider) Name() string { return "azure" }

// BeginVerification creates a liveness session against Azure Face API
// and returns the AuthToken as the client-facing SessionToken.
func (p *AzureProvider) BeginVerification(ctx context.Context, req Request) (*Session, error) {
	body, err := json.Marshal(map[string]any{
		"livenessOperationMode":        "Passive",
		"sendResultsToClient":          false,
		"deviceCorrelationId":          deviceCorrelation(req),
		"authTokenTimeToLiveInSeconds": int(p.sessionTTL / time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("idv/azure: marshal request: %w", err)
	}

	url := p.endpoint + "/face/v1.2-preview.1/detectLiveness/singleModal/sessions"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("idv/azure: build request: %w", err)
	}
	hreq.Header.Set("Ocp-Apim-Subscription-Key", p.key)
	hreq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrProviderUnavailable, resp.StatusCode, snippet)
	}

	var out struct {
		SessionID string `json:"sessionId"`
		AuthToken string `json:"authToken"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("idv/azure: decode response: %w", err)
	}
	if out.SessionID == "" || out.AuthToken == "" {
		return nil, fmt.Errorf("%w: empty session id or token", ErrProviderUnavailable)
	}

	return &Session{
		ProviderSessionID: out.SessionID,
		SessionToken:      out.AuthToken,
		ExpiresAt:         time.Now().Add(p.sessionTTL),
	}, nil
}

// GetVerification queries the session for a liveness decision.
func (p *AzureProvider) GetVerification(ctx context.Context, providerSessionID string) (*StatusResult, error) {
	if providerSessionID == "" {
		return nil, ErrSessionNotFound
	}

	url := p.endpoint + "/face/v1.2-preview.1/detectLiveness/singleModal/sessions/" + providerSessionID
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("idv/azure: build request: %w", err)
	}
	hreq.Header.Set("Ocp-Apim-Subscription-Key", p.key)

	resp, err := p.client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSessionNotFound
	}
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrProviderUnavailable, resp.StatusCode, snippet)
	}

	var out struct {
		Status  string `json:"status"` // "NotStarted" | "Running" | "Succeeded" | "Failed"
		Results struct {
			AttemptStatus string `json:"attemptStatus"`
			Result        struct {
				Response struct {
					Body struct {
						LivenessDecision string `json:"livenessDecision"` // "realface" | "spoofface" | "uncertain"
					} `json:"body"`
				} `json:"response"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("idv/azure: decode response: %w", err)
	}

	now := time.Now()
	switch out.Status {
	case "NotStarted":
		return &StatusResult{Status: StatusPending}, nil
	case "Running":
		return &StatusResult{Status: StatusInReview}, nil
	case "Failed":
		return &StatusResult{
			Status:          StatusRejected,
			RejectionReason: "azure_session_failed:" + out.Results.AttemptStatus,
			CompletedAt:     now,
		}, nil
	case "Succeeded":
		switch strings.ToLower(out.Results.Result.Response.Body.LivenessDecision) {
		case "realface":
			return &StatusResult{Status: StatusApproved, CompletedAt: now}, nil
		case "spoofface":
			return &StatusResult{
				Status:          StatusRejected,
				RejectionReason: "spoof_face",
				CompletedAt:     now,
			}, nil
		case "uncertain", "":
			return &StatusResult{
				Status:          StatusRejected,
				RejectionReason: "liveness_uncertain",
				CompletedAt:     now,
			}, nil
		}
	}
	// Defensive: unknown status string. Treat as in_review so the
	// caller can poll again rather than failing the request.
	return &StatusResult{Status: StatusInReview}, nil
}

// deviceCorrelation derives a stable identifier Azure stores against
// the session for cross-attempt linking. We use the user id; falling
// back to a per-call value keeps anonymous flows working.
func deviceCorrelation(req Request) string {
	if req.UserID != "" {
		return req.UserID
	}
	return "anonymous"
}
