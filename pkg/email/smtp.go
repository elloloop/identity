package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig configures an SMTP transport. The zero value is not valid; use
// NewSMTP.
type SMTPConfig struct {
	// Host is the SMTP server hostname (e.g. "smtp.gmail.com").
	Host string

	// Port is the SMTP server port. Common values:
	//   25  - plain (dev / on-prem only).
	//   587 - submission with STARTTLS upgrade.
	//   465 - implicit TLS (a.k.a. SMTPS).
	Port int

	// User and Pass are credentials for PLAIN auth. If User is empty, no auth
	// is attempted.
	User string
	Pass string

	// From is the default From address used when Message.From is empty.
	From string

	// TLS enables implicit TLS on dial (use with port 465).
	TLS bool

	// StartTLS issues a STARTTLS upgrade after EHLO (use with port 587).
	StartTLS bool

	// InsecureSkipVerify disables TLS certificate verification. ONLY use this
	// in tests against self-signed servers; never enable it in production.
	InsecureSkipVerify bool

	// DialTimeout caps how long Dial may block. Defaults to 10s.
	DialTimeout time.Duration
}

type smtpTransport struct {
	cfg SMTPConfig
}

// NewSMTP builds an SMTP transport from cfg.
func NewSMTP(cfg SMTPConfig) (Transport, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("%w: smtp host is required", ErrTransport)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("%w: smtp port %d out of range", ErrTransport, cfg.Port)
	}
	if cfg.TLS && cfg.StartTLS {
		return nil, fmt.Errorf("%w: TLS and StartTLS are mutually exclusive", ErrTransport)
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &smtpTransport{cfg: cfg}, nil
}

func (s *smtpTransport) Send(ctx context.Context, m Message) error {
	if m.From == "" {
		m.From = s.cfg.From
	}
	if err := m.Validate(); err != nil {
		return err
	}

	// Run the blocking SMTP exchange in a goroutine so we can honor ctx.
	done := make(chan error, 1)
	go func() {
		done <- s.send(ctx, m)
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", ErrTransport, ctx.Err())
	case err := <-done:
		return err
	}
}

func (s *smtpTransport) send(ctx context.Context, m Message) error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	if dl, ok := ctx.Deadline(); ok {
		dialer.Deadline = dl
	}

	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{
		ServerName:         s.cfg.Host,
		InsecureSkipVerify: s.cfg.InsecureSkipVerify, //nolint:gosec // honored only when explicitly opted in
		MinVersion:         tls.VersionTLS12,
	}
	if s.cfg.TLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("%w: dial %s: %v", ErrTransport, addr, err)
	}

	// Apply ctx deadline to the underlying conn so reads/writes don't hang
	// past the caller's deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("%w: smtp handshake: %v", ErrTransport, err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello(localHostname()); err != nil {
		return fmt.Errorf("%w: EHLO: %v", ErrTransport, err)
	}

	if s.cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%w: server does not advertise STARTTLS", ErrTransport)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("%w: STARTTLS: %v", ErrTransport, err)
		}
	}

	if s.cfg.User != "" {
		auth := smtp.PlainAuth("", s.cfg.User, s.cfg.Pass, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("%w: auth: %v", ErrTransport, err)
		}
	}

	if err := c.Mail(addressOnly(m.From)); err != nil {
		return fmt.Errorf("%w: MAIL FROM: %v", ErrTransport, err)
	}
	if err := c.Rcpt(addressOnly(m.To)); err != nil {
		return fmt.Errorf("%w: RCPT TO: %v", ErrTransport, err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("%w: DATA: %v", ErrTransport, err)
	}
	if _, err := w.Write(buildBody(m)); err != nil {
		_ = w.Close()
		return fmt.Errorf("%w: write body: %v", ErrTransport, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: close body: %v", ErrTransport, err)
	}

	if err := c.Quit(); err != nil {
		// Many servers close the connection abruptly after QUIT; only log via
		// returned error so callers may choose to ignore.
		return fmt.Errorf("%w: QUIT: %v", ErrTransport, err)
	}
	return nil
}

// localHostname is the value sent in EHLO. We default to "localhost" because
// some hosts return a name that fails strict reverse-DNS validation and
// upstream servers may reject the EHLO.
func localHostname() string { return "localhost" }

// addressOnly extracts the bare email out of a possibly-named address such as
// "Name <user@example.com>". Falls back to the input if parsing fails.
func addressOnly(s string) string {
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			return s[i+1 : j]
		}
	}
	return s
}

// buildBody renders the RFC 5322 message body. If both HTML and Text are
// provided, a multipart/alternative is built; otherwise a single-part body is
// emitted with the matching Content-Type.
func buildBody(m Message) []byte {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(m.From)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(m.To)
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(m.Subject)
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	hasHTML := strings.TrimSpace(m.HTML) != ""
	hasText := strings.TrimSpace(m.Text) != ""

	switch {
	case hasHTML && hasText:
		boundary := "----=_Part_email_pkg_boundary"
		b.WriteString("Content-Type: multipart/alternative; boundary=\"")
		b.WriteString(boundary)
		b.WriteString("\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(m.Text)
		b.WriteString("\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(m.HTML)
		b.WriteString("\r\n")
		b.WriteString("--" + boundary + "--\r\n")
	case hasHTML:
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(m.HTML)
	default:
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(m.Text)
	}
	return []byte(b.String())
}
