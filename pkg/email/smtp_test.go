package email

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSMTPServer is a minimal SMTP responder good enough to drive
// net/smtp.SendMail (and our smtp.go). It supports plain mode, optional
// AUTH PLAIN, optional STARTTLS upgrade, and can be configured to reject
// MAIL FROM with a 4xx error.
type fakeSMTPServer struct {
	t           *testing.T
	listener    net.Listener
	tlsCfg      *tls.Config
	requireAuth bool
	starttls    bool
	rejectMail  bool
	implicitTLS bool

	// authMechs controls the mechanism list advertised after "250-AUTH".
	// Empty means "PLAIN" for backwards compatibility with existing tests.
	authMechs string

	// loginUserPrompt / loginPassPrompt let a test override the prompt
	// strings the server sends during AUTH LOGIN. Defaults match the most
	// common real-world prompts. Used to verify the client doesn't parse
	// the prompt text.
	loginUserPrompt string
	loginPassPrompt string

	wantUser, wantPass string

	mu          sync.Mutex
	gotFrom     string
	gotRcpt     string
	gotData     string
	gotAuth     bool
	gotAuthMech string
	connDone    int32
}

func (s *fakeSMTPServer) addr() string { return s.listener.Addr().String() }
func (s *fakeSMTPServer) host() string {
	h, _, _ := net.SplitHostPort(s.addr())
	return h
}

func (s *fakeSMTPServer) port() int {
	_, p, _ := net.SplitHostPort(s.addr())
	var n int
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}

func (s *fakeSMTPServer) close() { _ = s.listener.Close() }

func (s *fakeSMTPServer) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *fakeSMTPServer) handle(c net.Conn) {
	defer func() {
		_ = c.Close()
		atomic.AddInt32(&s.connDone, 1)
	}()

	if s.implicitTLS {
		tlsConn := tls.Server(c, s.tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		c = tlsConn
	}

	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	write := func(line string) {
		_, _ = bw.WriteString(line + "\r\n")
		_ = bw.Flush()
	}

	write("220 fake.local ESMTP ready")

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			write("250-fake.local")
			if s.starttls {
				write("250-STARTTLS")
			}
			if s.requireAuth {
				mech := s.authMechs
				if mech == "" {
					mech = "PLAIN"
				}
				write("250-AUTH " + mech)
			}
			write("250 8BITMIME")
		case strings.HasPrefix(up, "STARTTLS"):
			if !s.starttls {
				write("502 not supported")
				continue
			}
			write("220 Ready to start TLS")
			tlsConn := tls.Server(c, s.tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			c = tlsConn
			br = bufio.NewReader(c)
			bw = bufio.NewWriter(c)
			write = func(line string) {
				_, _ = bw.WriteString(line + "\r\n")
				_ = bw.Flush()
			}
		case strings.HasPrefix(up, "AUTH PLAIN"):
			// Either inline ("AUTH PLAIN <b64>") or two-step.
			var creds string
			if rest := strings.TrimSpace(line[len("AUTH PLAIN"):]); rest != "" {
				creds = rest
			} else {
				write("334 ")
				cl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				creds = strings.TrimRight(cl, "\r\n")
			}
			raw, err := base64.StdEncoding.DecodeString(creds)
			if err != nil {
				write("535 bad base64")
				continue
			}
			parts := strings.Split(string(raw), "\x00")
			if len(parts) != 3 {
				write("535 bad credential format")
				continue
			}
			user, pass := parts[1], parts[2]
			if user != s.wantUser || pass != s.wantPass {
				write("535 auth failed")
				continue
			}
			s.mu.Lock()
			s.gotAuth = true
			s.gotAuthMech = "PLAIN"
			s.mu.Unlock()
			write("235 ok")
		case strings.HasPrefix(up, "AUTH LOGIN"):
			userPrompt := s.loginUserPrompt
			if userPrompt == "" {
				userPrompt = "Username:"
			}
			passPrompt := s.loginPassPrompt
			if passPrompt == "" {
				passPrompt = "Password:"
			}
			write("334 " + base64.StdEncoding.EncodeToString([]byte(userPrompt)))
			ul, err := br.ReadString('\n')
			if err != nil {
				return
			}
			userRaw, err := base64.StdEncoding.DecodeString(strings.TrimRight(ul, "\r\n"))
			if err != nil {
				write("535 bad base64")
				continue
			}
			write("334 " + base64.StdEncoding.EncodeToString([]byte(passPrompt)))
			pl, err := br.ReadString('\n')
			if err != nil {
				return
			}
			passRaw, err := base64.StdEncoding.DecodeString(strings.TrimRight(pl, "\r\n"))
			if err != nil {
				write("535 bad base64")
				continue
			}
			if string(userRaw) != s.wantUser || string(passRaw) != s.wantPass {
				write("535 auth failed")
				continue
			}
			s.mu.Lock()
			s.gotAuth = true
			s.gotAuthMech = "LOGIN"
			s.mu.Unlock()
			write("235 ok")
		case strings.HasPrefix(up, "MAIL FROM"):
			if s.rejectMail {
				write("450 mailbox unavailable")
				continue
			}
			s.mu.Lock()
			s.gotFrom = line
			s.mu.Unlock()
			write("250 ok")
		case strings.HasPrefix(up, "RCPT TO"):
			s.mu.Lock()
			s.gotRcpt = line
			s.mu.Unlock()
			write("250 ok")
		case strings.HasPrefix(up, "DATA"):
			write("354 end with .")
			var sb strings.Builder
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				sb.WriteString(dl)
			}
			s.mu.Lock()
			s.gotData = sb.String()
			s.mu.Unlock()
			write("250 ok queued")
		case strings.HasPrefix(up, "QUIT"):
			write("221 bye")
			return
		case strings.HasPrefix(up, "NOOP"):
			write("250 ok")
		case strings.HasPrefix(up, "RSET"):
			write("250 ok")
		default:
			write("502 not implemented")
		}
	}
}

// genTestCert returns a self-signed cert/key for a given host.
func genTestCert(t *testing.T, host string) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return cert
}

func startFake(t *testing.T, s *fakeSMTPServer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.listener = ln
	s.t = t
	go s.serve()
	t.Cleanup(s.close)
}

func TestSMTPPlainSend(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{}
	startFake(t, s)

	tr, err := NewSMTP(SMTPConfig{Host: s.host(), Port: s.port(), From: "noreply@example.com"})
	if err != nil {
		t.Fatalf("NewSMTP: %v", err)
	}
	err = tr.Send(context.Background(), Message{
		To:      "user@example.com",
		Subject: "Hi",
		Text:    "hello",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.gotData, "Subject: Hi") {
		t.Errorf("missing subject in data: %q", s.gotData)
	}
	if !strings.Contains(s.gotData, "hello") {
		t.Errorf("missing body in data: %q", s.gotData)
	}
	if !strings.Contains(s.gotFrom, "noreply@example.com") {
		t.Errorf("MAIL FROM did not include sender: %q", s.gotFrom)
	}
	if !strings.Contains(s.gotRcpt, "user@example.com") {
		t.Errorf("RCPT TO did not include recipient: %q", s.gotRcpt)
	}
}

func TestSMTPMultipart(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{Host: s.host(), Port: s.port(), From: "f@example.com"})
	err := tr.Send(context.Background(), Message{
		To:      "u@example.com",
		Subject: "Hello",
		HTML:    "<p>html</p>",
		Text:    "plain",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.gotData, "multipart/alternative") {
		t.Errorf("expected multipart/alternative, got %q", s.gotData)
	}
	if !strings.Contains(s.gotData, "<p>html</p>") || !strings.Contains(s.gotData, "plain") {
		t.Errorf("missing parts: %q", s.gotData)
	}
}

func TestSMTPHTMLOnly(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{Host: s.host(), Port: s.port(), From: "f@example.com"})
	err := tr.Send(context.Background(), Message{
		To:      "u@example.com",
		Subject: "Hello",
		HTML:    "<p>html only</p>",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.gotData, "Content-Type: text/html") {
		t.Errorf("expected text/html, got %q", s.gotData)
	}
}

func TestSMTPAuth(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{requireAuth: true, wantUser: "alice", wantPass: "secret"}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gotAuth {
		t.Errorf("server did not see AUTH success")
	}
}

func TestSMTPAuthLoginOnly(t *testing.T) {
	// Mirrors Azure Communication Services Email's SMTP relay, which
	// advertises only AUTH LOGIN. Regression test for the bug where
	// hardcoded smtp.PlainAuth caused every send to fail with
	// 504 5.7.4 Unrecognized authentication type.
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "LOGIN",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gotAuth {
		t.Fatalf("server did not see AUTH success")
	}
	if s.gotAuthMech != "LOGIN" {
		t.Errorf("got mech %q, want LOGIN", s.gotAuthMech)
	}
}

func TestSMTPAuthPlainPreferredWhenBothAdvertised(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "PLAIN LOGIN",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gotAuthMech != "PLAIN" {
		t.Errorf("got mech %q, want PLAIN (preferred when both advertised)", s.gotAuthMech)
	}
}

func TestSMTPAuthNoExtension(t *testing.T) {
	// User configured creds but the server doesn't advertise AUTH at all.
	// We should surface a clear error rather than try to send unauth'd.
	t.Parallel()

	s := &fakeSMTPServer{} // requireAuth: false => no AUTH line
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected auth-selection error")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestSMTPAuthFailure(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{requireAuth: true, wantUser: "alice", wantPass: "secret"}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "wrong",
		From: "f@example.com",
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

// TestSMTPAuthLoginWithStartTLS exercises the actual prod path for Azure
// Communication Services Email: port 587 → STARTTLS → AUTH LOGIN only.
func TestSMTPAuthLoginWithStartTLS(t *testing.T) {
	t.Parallel()

	cert := genTestCert(t, "127.0.0.1")
	s := &fakeSMTPServer{
		starttls:    true,
		tlsCfg:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		requireAuth: true,
		authMechs:   "LOGIN",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From:               "f@example.com",
		StartTLS:           true,
		InsecureSkipVerify: true,
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gotAuth || s.gotAuthMech != "LOGIN" {
		t.Errorf("got auth=%v mech=%q, want LOGIN", s.gotAuth, s.gotAuthMech)
	}
}

// TestSMTPAuthLoginWithImplicitTLS covers the port-465 style path: TLS on
// dial, then EHLO + AUTH LOGIN inside the TLS tunnel.
func TestSMTPAuthLoginWithImplicitTLS(t *testing.T) {
	t.Parallel()

	cert := genTestCert(t, "127.0.0.1")
	s := &fakeSMTPServer{
		implicitTLS: true,
		tlsCfg:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		requireAuth: true,
		authMechs:   "LOGIN",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From:               "f@example.com",
		TLS:                true,
		InsecureSkipVerify: true,
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gotAuth || s.gotAuthMech != "LOGIN" {
		t.Errorf("got auth=%v mech=%q, want LOGIN", s.gotAuth, s.gotAuthMech)
	}
}

// TestSMTPAuthLoginLocalizedPrompts guards against the temptation to parse
// the challenge text. Some relays send non-English or non-standard prompts
// ("Nom d'utilisateur:", "User Name", "USER NAME"); loginAuth must drive the
// exchange purely by step count.
func TestSMTPAuthLoginLocalizedPrompts(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{ //nolint:gosec // G101: localized SMTP prompt strings, not credentials
		requireAuth:     true,
		authMechs:       "LOGIN",
		loginUserPrompt: "Nom d'utilisateur",
		loginPassPrompt: "Mot de passe",
		wantUser:        "alice",
		wantPass:        "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gotAuth {
		t.Errorf("LOGIN with non-English prompts did not succeed")
	}
}

// TestSMTPAuthLoginWrongPassword verifies that a 535 after the password
// challenge propagates as a wrapped ErrTransport.
func TestSMTPAuthLoginWrongPassword(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "LOGIN",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "wrong",
		From: "f@example.com",
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected LOGIN auth failure")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

// TestSMTPAuthOnlyUnsupportedMechs exercises the case where the server
// advertises auth but offers no mechanism we implement (e.g. CRAM-MD5
// only). Must return a clear ErrTransport, not a panic or a silent
// unauthenticated send.
func TestSMTPAuthOnlyUnsupportedMechs(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "CRAM-MD5 DIGEST-MD5",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected error for unsupported-only mechanisms")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

// TestSMTPAuthMechParsingIgnoresExtraMechs confirms that unsupported
// mechanisms interleaved with LOGIN do not confuse selection.
func TestSMTPAuthMechParsingIgnoresExtraMechs(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "CRAM-MD5 LOGIN XOAUTH2",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gotAuthMech != "LOGIN" {
		t.Errorf("got mech %q, want LOGIN", s.gotAuthMech)
	}
}

// TestSMTPAuthMechParsingCaseInsensitive guards against a future
// refactor that drops the strings.ToUpper on the mechanism list. RFC
// 5321 says ESMTP keywords are case-insensitive.
func TestSMTPAuthMechParsingCaseInsensitive(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "plain login",
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gotAuthMech != "PLAIN" {
		t.Errorf("got mech %q, want PLAIN (lowercase advertisement should still match)", s.gotAuthMech)
	}
}

// TestSMTPNoAuthWhenUserEmpty confirms that omitting User skips the entire
// auth-selection path even if the server is advertising mechanisms — we
// don't ever want a silent half-configured send.
func TestSMTPNoAuthWhenUserEmpty(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		// Advertise auth but don't require it — server accepts MAIL FROM
		// without an AUTH step. This mirrors a misconfigured deployment
		// where the operator forgot to set User; we want delivery to
		// proceed (not error) so the higher-level chain can still log.
		authMechs: "PLAIN LOGIN",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		From: "f@example.com",
		// User intentionally empty.
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gotAuth {
		t.Errorf("auth attempted despite empty User")
	}
}

// TestLoginAuthStartResetsState ensures loginAuth is reusable across
// retries — Start must zero the step counter so a second Auth() doesn't
// immediately answer "Username:" with the password.
func TestLoginAuthStartResetsState(t *testing.T) {
	t.Parallel()

	a := &loginAuth{user: "u", pass: "p", host: "h"}
	info := &smtp.ServerInfo{Name: "h", TLS: true}

	if _, _, err := a.Start(info); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if _, err := a.Next([]byte("Username:"), true); err != nil {
		t.Fatalf("Next user: %v", err)
	}
	if _, err := a.Next([]byte("Password:"), true); err != nil {
		t.Fatalf("Next pass: %v", err)
	}
	// Simulate a retry: Start again, the next Next must answer with the
	// username, not error out as "extra challenge".
	if _, _, err := a.Start(info); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	got, err := a.Next([]byte("Username:"), true)
	if err != nil {
		t.Fatalf("Next after restart: %v", err)
	}
	if string(got) != "u" {
		t.Errorf("got %q after restart, want %q", got, "u")
	}
}

// TestLoginAuthNoMoreSentinel — when the server signals end-of-challenge
// (more=false), Next must return (nil, nil) so smtp.Client.Auth exits the
// loop cleanly.
func TestLoginAuthNoMoreSentinel(t *testing.T) {
	t.Parallel()

	a := &loginAuth{user: "u", pass: "p", host: "h"}
	got, err := a.Next(nil, false)
	if err != nil {
		t.Fatalf("Next(_, false): %v", err)
	}
	if got != nil {
		t.Errorf("got %q, want nil response on end-of-challenge", got)
	}
}

// TestLoginAuthExtraChallenge — a misbehaving server that sends a third
// challenge must produce a clear error, not silently leak credentials or
// loop forever.
func TestLoginAuthExtraChallenge(t *testing.T) {
	t.Parallel()

	a := &loginAuth{user: "u", pass: "p", host: "h"}
	info := &smtp.ServerInfo{Name: "h", TLS: true}
	if _, _, err := a.Start(info); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := a.Next([]byte("Username:"), true); err != nil {
		t.Fatalf("Next user: %v", err)
	}
	if _, err := a.Next([]byte("Password:"), true); err != nil {
		t.Fatalf("Next pass: %v", err)
	}
	if _, err := a.Next([]byte("Surprise:"), true); err == nil {
		t.Fatal("expected error on third challenge")
	}
}

// TestLoginAuthRejectsUnencryptedWhenNotAdvertised — the safety guard
// inherited from PlainAuth. If the connection is plaintext and the server
// did not put LOGIN in its advertised list, refuse to send credentials.
func TestLoginAuthRejectsUnencryptedWhenNotAdvertised(t *testing.T) {
	t.Parallel()

	a := &loginAuth{user: "u", pass: "p", host: "h"}
	info := &smtp.ServerInfo{Name: "h", TLS: false, Auth: []string{"PLAIN"}}
	if _, _, err := a.Start(info); err == nil {
		t.Fatal("expected refusal on unencrypted conn without LOGIN advertised")
	}
}

// TestLoginAuthAllowsUnencryptedWhenAdvertised — operator opt-in case.
// If the plaintext server explicitly says LOGIN, we honor that (mirrors
// PlainAuth's behavior, useful for localhost dev relays).
func TestLoginAuthAllowsUnencryptedWhenAdvertised(t *testing.T) {
	t.Parallel()

	a := &loginAuth{user: "u", pass: "p", host: "h"}
	info := &smtp.ServerInfo{Name: "h", TLS: false, Auth: []string{"LOGIN"}}
	if _, _, err := a.Start(info); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// TestLoginAuthAdvertisementMatchIsCaseInsensitive — SMTP AUTH mechanism
// names are case-insensitive (RFC 4954) and net/smtp.Client preserves
// whatever case the server sent. The plaintext-channel guard must use a
// case-insensitive compare, otherwise a server advertising `login`
// (lowercase) gets rejected as "not advertised" even though selectAuth
// (which uppercases) already chose this path. Regression test for that
// inconsistency.
func TestLoginAuthAdvertisementMatchIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	cases := []string{"LOGIN", "login", "Login", "LoGiN"}
	for _, advertised := range cases {
		t.Run(advertised, func(t *testing.T) {
			t.Parallel()
			a := &loginAuth{user: "u", pass: "p", host: "h"}
			info := &smtp.ServerInfo{Name: "h", TLS: false, Auth: []string{advertised}}
			if _, _, err := a.Start(info); err != nil {
				t.Errorf("Start with advertised %q: %v", advertised, err)
			}
		})
	}
}

// TestSMTPAuthLoginLowercaseAdvertisement is the integration-level guard
// against the same bug: a plaintext server that advertises `login` in
// lowercase should still succeed end-to-end. Without the EqualFold fix
// in loginAuth.Start, selectAuth selects LOGIN, then loginAuth.Start
// fails with "unencrypted connection" because the lowercase token
// doesn't match the literal "LOGIN".
func TestSMTPAuthLoginLowercaseAdvertisement(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{
		requireAuth: true,
		authMechs:   "login", // lowercase on purpose
		wantUser:    "alice",
		wantPass:    "secret",
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		User: "alice", Pass: "secret",
		From: "f@example.com",
	})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gotAuth || s.gotAuthMech != "LOGIN" {
		t.Errorf("got auth=%v mech=%q, want LOGIN", s.gotAuth, s.gotAuthMech)
	}
}

// TestLoginAuthWrongHostname — a defense in depth: the server name the
// stdlib client constructed itself with must match the host we configured
// with. Mismatch is treated as a misconfiguration, not a silent send.
func TestLoginAuthWrongHostname(t *testing.T) {
	t.Parallel()

	a := &loginAuth{user: "u", pass: "p", host: "expected.example.com"}
	info := &smtp.ServerInfo{Name: "attacker.example.com", TLS: true}
	if _, _, err := a.Start(info); err == nil {
		t.Fatal("expected wrong-hostname rejection")
	}
}

func TestSMTPStartTLS(t *testing.T) {
	t.Parallel()

	cert := genTestCert(t, "127.0.0.1")
	s := &fakeSMTPServer{
		starttls: true,
		tlsCfg:   &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		From:               "f@example.com",
		StartTLS:           true,
		InsecureSkipVerify: true,
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.gotData, "Subject: s") {
		t.Errorf("expected message delivered after STARTTLS, got %q", s.gotData)
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	t.Parallel()

	cert := genTestCert(t, "127.0.0.1")
	s := &fakeSMTPServer{
		implicitTLS: true,
		tlsCfg:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{
		Host: s.host(), Port: s.port(),
		From:               "f@example.com",
		TLS:                true,
		InsecureSkipVerify: true,
	})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.gotData, "Subject: s") {
		t.Errorf("implicit TLS delivery missing data: %q", s.gotData)
	}
}

func TestSMTPRejectsMail(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{rejectMail: true}
	startFake(t, s)

	tr, _ := NewSMTP(SMTPConfig{Host: s.host(), Port: s.port(), From: "f@example.com"})
	err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected error from server 4xx")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestSMTPContextCancel(t *testing.T) {
	t.Parallel()

	// Listener that accepts and never replies, so the dial succeeds but the
	// 220 banner read blocks indefinitely.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Drain reads forever to keep client busy.
		_, _ = io.Copy(io.Discard, c)
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	var pn int
	for _, ch := range port {
		pn = pn*10 + int(ch-'0')
	}
	tr, _ := NewSMTP(SMTPConfig{Host: host, Port: pn, From: "f@example.com"})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = tr.Send(ctx, Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected ctx error")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("ctx cancel did not unblock within 2s, took %v", time.Since(start))
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestSMTPDialFailure(t *testing.T) {
	t.Parallel()

	// Reserve a port and immediately close so dialing it fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	host, port, _ := net.SplitHostPort(addr)
	var pn int
	for _, ch := range port {
		pn = pn*10 + int(ch-'0')
	}
	tr, _ := NewSMTP(SMTPConfig{Host: host, Port: pn, From: "f@example.com", DialTimeout: 200 * time.Millisecond})
	err = tr.Send(context.Background(), Message{To: "u@example.com", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

func TestSMTPInvalidConfig(t *testing.T) {
	t.Parallel()

	cases := []SMTPConfig{
		{Host: "", Port: 25},
		{Host: "h", Port: 0},
		{Host: "h", Port: 70000},
		{Host: "h", Port: 25, TLS: true, StartTLS: true},
	}
	for i, c := range cases {
		_, err := NewSMTP(c)
		if err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestSMTPInvalidMessage(t *testing.T) {
	t.Parallel()

	tr, _ := NewSMTP(SMTPConfig{Host: "h", Port: 25, From: "f@example.com"})
	err := tr.Send(context.Background(), Message{}) // missing required fields
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("want ErrInvalidMessage, got %v", err)
	}
}

func TestSMTPDefaultFromInjected(t *testing.T) {
	t.Parallel()

	s := &fakeSMTPServer{}
	startFake(t, s)
	tr, _ := NewSMTP(SMTPConfig{Host: s.host(), Port: s.port(), From: "default@example.com"})
	if err := tr.Send(context.Background(), Message{To: "u@example.com", Subject: "x", Text: "y"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.gotFrom, "default@example.com") {
		t.Errorf("expected default From injected, got %q", s.gotFrom)
	}
}

func TestSMTPAddressOnly(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"a@b.com":                 "a@b.com",
		"Alice <alice@b.com>":     "alice@b.com",
		"\"Alice\" <alice@b.com>": "alice@b.com",
		"no-brackets":             "no-brackets",
	}
	for in, want := range cases {
		if got := addressOnly(in); got != want {
			t.Errorf("addressOnly(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestBuildBody_ReplyToAndListUnsubscribe(t *testing.T) {
	m := Message{
		To:              "u@example.com",
		From:            "no-reply@example.com",
		Subject:         "Hi",
		Text:            "body",
		ReplyTo:         "help@example.com",
		ListUnsubscribe: "<mailto:unsub@example.com>",
	}
	got := string(buildBody(m))
	if !strings.Contains(got, "Reply-To: help@example.com\r\n") {
		t.Fatalf("expected Reply-To header, got:\n%s", got)
	}
	if !strings.Contains(got, "List-Unsubscribe: <mailto:unsub@example.com>\r\n") {
		t.Fatalf("expected List-Unsubscribe header, got:\n%s", got)
	}
}

func TestBuildBody_OmitsHeadersWhenUnset(t *testing.T) {
	m := Message{
		To:      "u@example.com",
		From:    "no-reply@example.com",
		Subject: "Hi",
		Text:    "body",
	}
	got := string(buildBody(m))
	if strings.Contains(got, "Reply-To:") {
		t.Fatalf("did not expect Reply-To header, got:\n%s", got)
	}
	if strings.Contains(got, "List-Unsubscribe:") {
		t.Fatalf("did not expect List-Unsubscribe header, got:\n%s", got)
	}
}
