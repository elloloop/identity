package sms

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestMessageValidate(t *testing.T) {
	cases := []struct {
		name    string
		msg     Message
		wantErr error
	}{
		{"ok", Message{To: "+14155550123", Body: "hi"}, nil},
		{"missing to", Message{Body: "hi"}, ErrInvalidMessage},
		{"missing body", Message{To: "+14155550123"}, ErrInvalidMessage},
		{"not e164 no plus", Message{To: "14155550123", Body: "hi"}, ErrInvalidMessage},
		{"not e164 letters", Message{To: "+1415555ABCD", Body: "hi"}, ErrInvalidMessage},
		{"too long", Message{To: "+1234567890123456", Body: "hi"}, ErrInvalidMessage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.msg.Validate()
			if tc.wantErr == nil && err != nil {
				t.Fatalf("Validate: unexpected error %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate: want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLogOnlySender(t *testing.T) {
	s := NewLogOnly(zap.NewNop())
	if err := s.Send(context.Background(), Message{To: "+14155550123", Body: "code 123456"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Invalid message still validates and returns the sentinel.
	if err := s.Send(context.Background(), Message{To: "", Body: "x"}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("Send invalid: want ErrInvalidMessage, got %v", err)
	}
}

// ── Twilio ────────────────────────────────────────────────────────────

func TestTwilioSend_Success(t *testing.T) {
	var gotPath, gotAuthUser, gotTo, gotFrom, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthUser, _, _ = r.BasicAuth()
		_ = r.ParseForm()
		gotTo = r.PostFormValue("To")
		gotFrom = r.PostFormValue("From")
		gotBody = r.PostFormValue("Body")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"sid":"SM123","status":"queued"}`)
	}))
	defer srv.Close()

	s, err := NewTwilio(TwilioConfig{
		AccountSID: "AC_test", AuthToken: "tok", From: "+15005550006", BaseURL: srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewTwilio: %v", err)
	}
	if err := s.Send(context.Background(), Message{To: "+14155550123", Body: "code 123456"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotPath != "/2010-04-01/Accounts/AC_test/Messages.json" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuthUser != "AC_test" {
		t.Fatalf("basic-auth user = %q", gotAuthUser)
	}
	if gotTo != "+14155550123" || gotFrom != "+15005550006" || gotBody != "code 123456" {
		t.Fatalf("form: to=%q from=%q body=%q", gotTo, gotFrom, gotBody)
	}
}

func TestTwilioSend_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":20003,"message":"Authenticate"}`)
	}))
	defer srv.Close()

	s, _ := NewTwilio(TwilioConfig{AccountSID: "AC", AuthToken: "bad", From: "+1", BaseURL: srv.URL, HTTPClient: srv.Client()})
	err := s.Send(context.Background(), Message{To: "+14155550123", Body: "x"})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestTwilioSend_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // close so the connection is refused

	s, _ := NewTwilio(TwilioConfig{AccountSID: "AC", AuthToken: "t", From: "+1", BaseURL: url, HTTPClient: srv.Client()})
	err := s.Send(context.Background(), Message{To: "+14155550123", Body: "x"})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("want ErrProviderUnavailable, got %v", err)
	}
}

func TestNewTwilio_MissingCreds(t *testing.T) {
	if _, err := NewTwilio(TwilioConfig{AuthToken: "t", From: "+1"}); !errors.Is(err, ErrTransport) {
		t.Fatalf("missing sid: want ErrTransport, got %v", err)
	}
	if _, err := NewTwilio(TwilioConfig{AccountSID: "AC", From: "+1"}); !errors.Is(err, ErrTransport) {
		t.Fatalf("missing token: want ErrTransport, got %v", err)
	}
	if _, err := NewTwilio(TwilioConfig{AccountSID: "AC", AuthToken: "t"}); !errors.Is(err, ErrTransport) {
		t.Fatalf("missing from: want ErrTransport, got %v", err)
	}
}

// ── SNS ───────────────────────────────────────────────────────────────

func TestSNSSend_Success(t *testing.T) {
	var gotAuth, gotAmzDate, gotPhone, gotMessage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAmzDate = r.Header.Get("X-Amz-Date")
		_ = r.ParseForm()
		gotPhone = r.PostFormValue("PhoneNumber")
		gotMessage = r.PostFormValue("Message")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<PublishResponse><PublishResult><MessageId>m-1</MessageId></PublishResult></PublishResponse>`)
	}))
	defer srv.Close()

	s, err := NewSNS(SNSConfig{
		Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: "secret",
		SenderID: "Identity", BaseURL: srv.URL + "/", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewSNS: %v", err)
	}
	if err := s.Send(context.Background(), Message{To: "+14155550123", Body: "code 123456"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasPrefix(gotAuth, snsSigningAlgorithm+" Credential=AKID/") {
		t.Fatalf("authorization header = %q", gotAuth)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=") || !strings.Contains(gotAuth, "Signature=") {
		t.Fatalf("authorization header missing fields: %q", gotAuth)
	}
	if gotAmzDate == "" {
		t.Fatal("X-Amz-Date not set")
	}
	if gotPhone != "+14155550123" || gotMessage != "code 123456" {
		t.Fatalf("form: phone=%q message=%q", gotPhone, gotMessage)
	}
}

func TestSNSSend_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`)
	}))
	defer srv.Close()

	s, _ := NewSNS(SNSConfig{Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: "s", BaseURL: srv.URL + "/", HTTPClient: srv.Client()})
	err := s.Send(context.Background(), Message{To: "+14155550123", Body: "x"})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestSNSSend_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()
	s, _ := NewSNS(SNSConfig{Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: "s", BaseURL: addr + "/", HTTPClient: srv.Client()})
	err := s.Send(context.Background(), Message{To: "+14155550123", Body: "x"})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("want ErrProviderUnavailable, got %v", err)
	}
}

func TestSNSSigningKeyKnownVector(t *testing.T) {
	// AWS-published SigV4 signing-key test vector (Signature V4 docs):
	// secret "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", date 20150830,
	// region us-east-1, service iam → known signing key hex.
	key := sigV4SigningKey(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830", "us-east-1", "iam",
	)
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got := hexEncode(key); got != want {
		t.Fatalf("signing key = %s, want %s", got, want)
	}
}

func TestNewSNS_MissingCreds(t *testing.T) {
	if _, err := NewSNS(SNSConfig{AccessKeyID: "a", SecretAccessKey: "s"}); !errors.Is(err, ErrTransport) {
		t.Fatalf("missing region: want ErrTransport, got %v", err)
	}
	if _, err := NewSNS(SNSConfig{Region: "us-east-1", SecretAccessKey: "s"}); !errors.Is(err, ErrTransport) {
		t.Fatalf("missing access key: want ErrTransport, got %v", err)
	}
}

// ── Azure ─────────────────────────────────────────────────────────────

func TestAzureSend_Success(t *testing.T) {
	var gotAuth, gotDate, gotContentHash, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("x-ms-date")
		gotContentHash = r.Header.Get("x-ms-content-sha256")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"value":[{"to":"+14155550123","httpStatusCode":202,"successful":true}]}`)
	}))
	defer srv.Close()

	s, err := NewAzure(AzureConfig{
		Endpoint: srv.URL, AccessKey: "c2VjcmV0LWtleQ==", From: "+15005550006",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewAzure: %v", err)
	}
	if err := s.Send(context.Background(), Message{To: "+14155550123", Body: "code 123456"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "HMAC-SHA256 SignedHeaders=") || !strings.Contains(gotAuth, "Signature=") {
		t.Fatalf("authorization header = %q", gotAuth)
	}
	if gotDate == "" || gotContentHash == "" {
		t.Fatalf("missing signing headers: date=%q hash=%q", gotDate, gotContentHash)
	}
	if gotPath != "/sms" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, `"+14155550123"`) || !strings.Contains(gotBody, "code 123456") {
		t.Fatalf("body = %q", gotBody)
	}
}

func TestAzureSend_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"Unauthorized"}}`)
	}))
	defer srv.Close()

	s, _ := NewAzure(AzureConfig{Endpoint: srv.URL, AccessKey: "c2VjcmV0", From: "+1", HTTPClient: srv.Client()})
	err := s.Send(context.Background(), Message{To: "+14155550123", Body: "x"})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestAzureSend_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()
	s, _ := NewAzure(AzureConfig{Endpoint: addr, AccessKey: "c2VjcmV0", From: "+1", HTTPClient: srv.Client()})
	err := s.Send(context.Background(), Message{To: "+14155550123", Body: "x"})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("want ErrProviderUnavailable, got %v", err)
	}
}

func TestParseAzureConnectionString(t *testing.T) {
	ep, key, err := ParseAzureConnectionString("endpoint=https://x.communication.azure.com/;accesskey=YWJj")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ep != "https://x.communication.azure.com/" || key != "YWJj" {
		t.Fatalf("parsed: ep=%q key=%q", ep, key)
	}
	if _, _, err := ParseAzureConnectionString("endpoint=https://x/"); !errors.Is(err, ErrTransport) {
		t.Fatalf("missing accesskey: want ErrTransport, got %v", err)
	}
}

func TestNewAzure_BadKey(t *testing.T) {
	if _, err := NewAzure(AzureConfig{Endpoint: "https://x", AccessKey: "!!!notbase64!!!", From: "+1"}); !errors.Is(err, ErrTransport) {
		t.Fatalf("bad key: want ErrTransport, got %v", err)
	}
}

// hexEncode is a tiny local helper so the signing-key vector test does
// not need to import encoding/hex (which the package files already use).
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
