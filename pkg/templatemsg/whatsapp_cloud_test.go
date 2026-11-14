package templatemsg

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
)

const (
	testAccessToken   = "EAAG-test-token"
	testPhoneNumberID = "106540352242922"
	testRecipient     = "+14155550123"
	testCode          = "482915"
)

// capturedSend is one request the fake Graph API received.
type capturedSend struct {
	method, path, authorization, contentType string
	body                                     map[string]any
}

// newGraphAPI is a fake Graph API that records each request and answers with
// status and body.
func newGraphAPI(t *testing.T, status int, body string) (*httptest.Server, *[]capturedSend) {
	t.Helper()
	var got []capturedSend
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c := capturedSend{
			method: r.Method, path: r.URL.Path,
			authorization: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type"),
		}
		if err := json.Unmarshal(raw, &c.body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		got = append(got, c)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func newTestWhatsApp(t *testing.T, srv *httptest.Server, mutate func(*WhatsAppCloudConfig)) Sender {
	t.Helper()
	cfg := WhatsAppCloudConfig{
		AccessToken: testAccessToken, PhoneNumberID: testPhoneNumberID, APIVersion: "v26.0",
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := NewWhatsAppCloud(cfg)
	if err != nil {
		t.Fatalf("NewWhatsAppCloud: %v", err)
	}
	return s
}

const acceptedBody = `{"messaging_product":"whatsapp","contacts":[{"input":"+14155550123","wa_id":"14155550123"}],"messages":[{"id":"wamid.HBgL","message_status":"accepted"}]}`

func TestWhatsAppCloud_SendsTheTemplate(t *testing.T) {
	t.Parallel()
	bodyOnly := []any{map[string]any{
		"type":       "body",
		"parameters": []any{map[string]any{"type": "text", "text": testCode}},
	}}
	withButton := append(append([]any(nil), bodyOnly...), map[string]any{
		"type": "button", "sub_type": "url", "index": "0",
		"parameters": []any{map[string]any{"type": "text", "text": testCode}},
	})
	cases := []struct {
		name           string
		mutate         func(*WhatsAppCloudConfig)
		msg            Message
		wantLanguage   string
		wantComponents []any
	}{
		{
			name:           "an authentication template carries the code in its body and its copy-code button",
			mutate:         func(c *WhatsAppCloudConfig) { c.CodeButton = true },
			msg:            Message{To: testRecipient, Template: "verification_code", Language: "en_US", Params: []string{testCode}},
			wantLanguage:   "en_US",
			wantComponents: withButton,
		},
		{
			name:           "a template without a button carries the code in its body only",
			msg:            Message{To: testRecipient, Template: "verification_code", Language: "en", Params: []string{testCode}},
			wantLanguage:   "en",
			wantComponents: bodyOnly,
		},
		{
			name:           "a message naming no language uses the sender's default",
			mutate:         func(c *WhatsAppCloudConfig) { c.DefaultLanguage = "en_GB" },
			msg:            Message{To: testRecipient, Template: "verification_code", Params: []string{testCode}},
			wantLanguage:   "en_GB",
			wantComponents: bodyOnly,
		},
		{
			name:         "a message's own language wins over the default",
			mutate:       func(c *WhatsAppCloudConfig) { c.DefaultLanguage = "en_GB" },
			msg:          Message{To: testRecipient, Template: "verification_code", Language: "hi", Params: []string{testCode}},
			wantLanguage: "hi", wantComponents: bodyOnly,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, got := newGraphAPI(t, http.StatusOK, acceptedBody)
			if err := newTestWhatsApp(t, srv, tc.mutate).Send(context.Background(), tc.msg); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if len(*got) != 1 {
				t.Fatalf("got %d requests, want 1", len(*got))
			}
			req := (*got)[0]
			if req.method != http.MethodPost || req.path != "/v26.0/"+testPhoneNumberID+"/messages" {
				t.Errorf("request = %s %s, want POST /v26.0/%s/messages", req.method, req.path, testPhoneNumberID)
			}
			if req.authorization != "Bearer "+testAccessToken || req.contentType != "application/json" {
				t.Errorf("headers: authorization %q, content-type %q", req.authorization, req.contentType)
			}
			want := map[string]any{
				"messaging_product": "whatsapp",
				"recipient_type":    "individual",
				"to":                testRecipient,
				"type":              "template",
				"template": map[string]any{
					"name":       "verification_code",
					"language":   map[string]any{"code": tc.wantLanguage},
					"components": tc.wantComponents,
				},
			}
			if !jsonEqual(t, req.body, want) {
				t.Errorf("body = %v\nwant   %v", req.body, want)
			}
		})
	}
}

func TestWhatsAppCloud_RefusesAMessageItCannotSend(t *testing.T) {
	t.Parallel()
	withCodeButton := func(c *WhatsAppCloudConfig) { c.CodeButton = true }
	cases := []struct {
		name   string
		mutate func(*WhatsAppCloudConfig)
		msg    Message
	}{
		{"not E.164", nil, Message{To: "14155550123", Template: "t", Language: "en", Params: []string{testCode}}},
		{"no template", nil, Message{To: testRecipient, Language: "en", Params: []string{testCode}}},
		{"no language and no default", nil, Message{To: testRecipient, Template: "t", Params: []string{testCode}}},
		{"a code button and no code", withCodeButton, Message{To: testRecipient, Template: "t", Language: "en"}},
		{
			"a code button and two parameters", withCodeButton,
			Message{To: testRecipient, Template: "t", Language: "en", Params: []string{testCode, "5 minutes"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, got := newGraphAPI(t, http.StatusOK, acceptedBody)
			err := newTestWhatsApp(t, srv, tc.mutate).Send(context.Background(), tc.msg)
			if !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
			if len(*got) != 0 {
				t.Errorf("a refused message reached the API (%d requests)", len(*got))
			}
		})
	}
}

// A refusal is reported by the provider's error code, never by the error's
// message or details, which can quote the recipient, and never with the
// token or the code.
func TestWhatsAppCloud_AFailureNamesTheErrorCodeAndNothingPersonal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		status   int
		body     string
		wantText string
	}{
		{
			name:   "a Graph API error",
			status: http.StatusBadRequest,
			body: `{"error":{"message":"(#131026) Message undeliverable to +14155550123","type":"OAuthException","code":131026,` +
				`"error_data":{"messaging_product":"whatsapp","details":"+14155550123 is not on WhatsApp"},"fbtrace_id":"AbC123"}}`,
			wantText: `whatsapp cloud HTTP 400, error code 131026 (fbtrace_id "AbC123")`,
		},
		{
			name:     "an expired token",
			status:   http.StatusUnauthorized,
			body:     `{"error":{"message":"Error validating access token","type":"OAuthException","code":190,"fbtrace_id":"Xy9"}}`,
			wantText: `whatsapp cloud HTTP 401, error code 190 (fbtrace_id "Xy9")`,
		},
		{
			name:     "a body that is not a Graph API error",
			status:   http.StatusBadGateway,
			body:     `<html>upstream for +14155550123 failed</html>`,
			wantText: "whatsapp cloud HTTP 502",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := newGraphAPI(t, tc.status, tc.body)
			err := newTestWhatsApp(t, srv, nil).Send(context.Background(),
				Message{To: testRecipient, Template: "verification_code", Language: "en", Params: []string{testCode}})
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("want ErrTransport, got %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantText) {
				t.Errorf("error %q does not contain %q", msg, tc.wantText)
			}
			for _, secret := range []string{testRecipient, "14155550123", testCode, testAccessToken} {
				if strings.Contains(msg, secret) {
					t.Errorf("error %q carries %q", msg, secret)
				}
			}
		})
	}
}

func TestWhatsAppCloud_ARoundTripFailureIsATransportError(t *testing.T) {
	t.Parallel()
	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		base, client := srv.URL, srv.Client()
		srv.Close()
		s, err := NewWhatsAppCloud(WhatsAppCloudConfig{
			AccessToken: testAccessToken, PhoneNumberID: testPhoneNumberID, APIVersion: "v26.0",
			BaseURL: base, HTTPClient: client,
		})
		if err != nil {
			t.Fatalf("NewWhatsAppCloud: %v", err)
		}
		err = s.Send(context.Background(), Message{To: testRecipient, Template: "t", Language: "en", Params: []string{testCode}})
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("want ErrTransport, got %v", err)
		}
		if strings.Contains(err.Error(), testAccessToken) {
			t.Errorf("error %q carries the token", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		t.Cleanup(func() { close(release); srv.Close() })
		client := srv.Client()
		client.Timeout = 50 * time.Millisecond
		s := newTestWhatsApp(t, srv, func(c *WhatsAppCloudConfig) { c.HTTPClient = client })
		err := s.Send(context.Background(), Message{To: testRecipient, Template: "t", Language: "en", Params: []string{testCode}})
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("want ErrTransport, got %v", err)
		}
	})
}

func TestNewWhatsAppCloud_RefusesAnIncompleteConfig(t *testing.T) {
	t.Parallel()
	ok := WhatsAppCloudConfig{AccessToken: testAccessToken, PhoneNumberID: testPhoneNumberID, APIVersion: "v26.0"}
	if _, err := NewWhatsAppCloud(ok); err != nil {
		t.Fatalf("a complete config: %v", err)
	}
	cases := map[string]func(*WhatsAppCloudConfig){
		"no access token":                  func(c *WhatsAppCloudConfig) { c.AccessToken = "" },
		"an access token with a space":     func(c *WhatsAppCloudConfig) { c.AccessToken = "EAAG token" },
		"no phone number id":               func(c *WhatsAppCloudConfig) { c.PhoneNumberID = "" },
		"a phone number id with a path":    func(c *WhatsAppCloudConfig) { c.PhoneNumberID = "123/../456" },
		"a phone number that is not an id": func(c *WhatsAppCloudConfig) { c.PhoneNumberID = "+14155550123" },
		"no api version":                   func(c *WhatsAppCloudConfig) { c.APIVersion = "" },
		"an api version without its v":     func(c *WhatsAppCloudConfig) { c.APIVersion = "26.0" },
		"an api version with a path":       func(c *WhatsAppCloudConfig) { c.APIVersion = "v26.0/x" },
		"a default language with a space":  func(c *WhatsAppCloudConfig) { c.DefaultLanguage = "en US" },
	}
	for name, mutate := range cases {
		cfg := ok
		mutate(&cfg)
		if _, err := NewWhatsAppCloud(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		} else if strings.Contains(err.Error(), testAccessToken) {
			t.Errorf("%s: error %q carries the token", name, err)
		}
	}
}

// jsonEqual compares two JSON-shaped values by their encoding.
func jsonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(ja) == string(jb)
}
