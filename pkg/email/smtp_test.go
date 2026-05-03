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

	wantUser, wantPass string

	mu       sync.Mutex
	gotFrom  string
	gotRcpt  string
	gotData  string
	gotAuth  bool
	connDone int32
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
				write("250-AUTH PLAIN")
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
	defer ln.Close()
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
		"a@b.com":                  "a@b.com",
		"Alice <alice@b.com>":      "alice@b.com",
		"\"Alice\" <alice@b.com>":  "alice@b.com",
		"no-brackets":              "no-brackets",
	}
	for in, want := range cases {
		if got := addressOnly(in); got != want {
			t.Errorf("addressOnly(%q)=%q, want %q", in, got, want)
		}
	}
}
