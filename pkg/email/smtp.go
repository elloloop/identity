package email

import (
	"context"
	"crypto/tls"
	"errors"
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
		return fmt.Errorf("%w: %w", ErrTransport, ctx.Err())
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
		return fmt.Errorf("%w: dial %s: %w", ErrTransport, addr, err)
	}

	// Apply ctx deadline to the underlying conn so reads/writes don't hang
	// past the caller's deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("%w: smtp handshake: %w", ErrTransport, err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello(localHostname()); err != nil {
		return fmt.Errorf("%w: EHLO: %w", ErrTransport, err)
	}

	if s.cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%w: server does not advertise STARTTLS", ErrTransport)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("%w: STARTTLS: %w", ErrTransport, err)
		}
	}

	if s.cfg.User != "" {
		auth, err := selectAuth(c, s.cfg.Host, s.cfg.User, s.cfg.Pass)
		if err != nil {
			return fmt.Errorf("%w: auth: %w", ErrTransport, err)
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("%w: auth: %w", ErrTransport, err)
		}
	}

	if err := c.Mail(addressOnly(m.From)); err != nil {
		return fmt.Errorf("%w: MAIL FROM: %w", ErrTransport, err)
	}
	if err := c.Rcpt(addressOnly(m.To)); err != nil {
		return fmt.Errorf("%w: RCPT TO: %w", ErrTransport, err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("%w: DATA: %w", ErrTransport, err)
	}
	if _, err := w.Write(buildBody(m)); err != nil {
		_ = w.Close()
		return fmt.Errorf("%w: write body: %w", ErrTransport, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: close body: %w", ErrTransport, err)
	}

	if err := c.Quit(); err != nil {
		// Many servers close the connection abruptly after QUIT; only log via
		// returned error so callers may choose to ignore.
		return fmt.Errorf("%w: QUIT: %w", ErrTransport, err)
	}
	return nil
}

// selectAuth picks an smtp.Auth implementation based on the AUTH mechanisms
// the server advertised in its (post-STARTTLS) EHLO response. PLAIN is
// preferred when available — it's atomic (one round trip) and is the Go
// stdlib's well-tested path. LOGIN is used as a fallback for relays like
// Azure Communication Services Email, which advertise only AUTH LOGIN.
func selectAuth(c *smtp.Client, host, user, pass string) (smtp.Auth, error) {
	ok, params := c.Extension("AUTH")
	if !ok {
		return nil, errors.New("server does not advertise AUTH")
	}
	mechs := strings.Fields(strings.ToUpper(params))
	has := func(m string) bool {
		for _, x := range mechs {
			if x == m {
				return true
			}
		}
		return false
	}
	switch {
	case has("PLAIN"):
		return smtp.PlainAuth("", user, pass, host), nil
	case has("LOGIN"):
		return &loginAuth{user: user, pass: pass, host: host}, nil
	default:
		return nil, fmt.Errorf("no supported AUTH mechanism (server offers: %q)", params)
	}
}

// loginAuth implements the SASL LOGIN mechanism, which is not in the Go
// standard library. Some relays (notably Azure Communication Services Email)
// accept only AUTH LOGIN, so we ship our own.
//
// The mechanism is a simple two-step challenge: the server prompts for the
// username, then the password, each base64-encoded. We track state by step
// rather than parsing the prompt text, since servers send different strings
// ("Username:", "User Name", localized variants, …).
type loginAuth struct {
	user, pass, host string
	step             int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// Mirror smtp.PlainAuth's safety checks. Don't send credentials over an
	// unencrypted connection unless the server explicitly advertised LOGIN
	// on the plaintext channel (in which case the operator is opting in,
	// e.g. for a localhost dev relay).
	if !server.TLS {
		advertised := false
		for _, m := range server.Auth {
			// SMTP AUTH mechanism names are case-insensitive (RFC 4954),
			// and net/smtp.Client preserves whatever case the server sent.
			// selectAuth itself uppercases before matching; mirror that
			// here so a server advertising `login` (lowercase) on a
			// plaintext channel isn't treated as "not advertised".
			if strings.EqualFold(m, "LOGIN") {
				advertised = true
				break
			}
		}
		if !advertised {
			return "", nil, errors.New("unencrypted connection")
		}
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.user), nil
	case 2:
		return []byte(a.pass), nil
	default:
		return nil, fmt.Errorf("unexpected LOGIN challenge: %q", fromServer)
	}
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
	if rt := strings.TrimSpace(m.ReplyTo); rt != "" {
		b.WriteString("Reply-To: ")
		b.WriteString(rt)
		b.WriteString("\r\n")
	}
	if lu := strings.TrimSpace(m.ListUnsubscribe); lu != "" {
		b.WriteString("List-Unsubscribe: ")
		b.WriteString(lu)
		b.WriteString("\r\n")
	}
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
