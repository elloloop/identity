package sms

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// twilioDefaultBaseURL is the Twilio REST API root. The account SID is
// appended to form the per-account Messages resource. Injectable via
// TwilioConfig.BaseURL so tests can point at an httptest server.
const twilioDefaultBaseURL = "https://api.twilio.com"

// twilioHTTPTimeout bounds a single Twilio send when the caller does
// not supply an HTTP client of its own.
const twilioHTTPTimeout = 15 * time.Second

// twilioResponseLimit caps how much of an error/success body is read so
// a misbehaving endpoint cannot stream an unbounded response.
const twilioResponseLimit = 1 << 16

// TwilioConfig configures a Twilio Sender. AccountSID, AuthToken, and
// From are required.
type TwilioConfig struct {
	// AccountSID is the Twilio account identifier (the "AC..." string).
	// It forms both the basic-auth username and the URL path segment.
	AccountSID string

	// AuthToken is the Twilio auth token (basic-auth password).
	AuthToken string

	// From is the originating number or messaging-service sender id used
	// when Message.From is empty.
	From string

	// BaseURL overrides the REST API root for tests. Empty uses
	// twilioDefaultBaseURL.
	BaseURL string

	// HTTPClient overrides the HTTP client (and thus the timeout) for
	// tests. Empty uses a client with twilioHTTPTimeout.
	HTTPClient *http.Client
}

type twilioSender struct {
	accountSID string
	authToken  string
	from       string
	baseURL    string
	client     *http.Client
}

// NewTwilio builds a Twilio Sender from cfg. It returns a wrapped
// ErrTransport if a required credential is missing.
func NewTwilio(cfg TwilioConfig) (Sender, error) {
	if strings.TrimSpace(cfg.AccountSID) == "" {
		return nil, fmt.Errorf("%w: twilio account sid is required", ErrTransport)
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return nil, fmt.Errorf("%w: twilio auth token is required", ErrTransport)
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("%w: twilio from is required", ErrTransport)
	}
	base := cfg.BaseURL
	if base == "" {
		base = twilioDefaultBaseURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: twilioHTTPTimeout}
	}
	return &twilioSender{
		accountSID: cfg.AccountSID,
		authToken:  cfg.AuthToken,
		from:       cfg.From,
		baseURL:    strings.TrimRight(base, "/"),
		client:     client,
	}, nil
}

func (s *twilioSender) Send(ctx context.Context, m Message) error {
	if m.From == "" {
		m.From = s.from
	}
	if err := m.Validate(); err != nil {
		return err
	}

	form := url.Values{}
	form.Set("To", m.To)
	form.Set("From", m.From)
	form.Set("Body", m.Body)

	endpoint := fmt.Sprintf("%s/2010-04-01/Accounts/%s/Messages.json", s.baseURL, s.accountSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrTransport, err)
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, twilioResponseLimit))
		return fmt.Errorf("%w: twilio HTTP %d: %s", ErrTransport, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	// Drain so the connection can be reused; the success payload is not
	// needed (the verification flow stores its own record).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, twilioResponseLimit))
	return nil
}
