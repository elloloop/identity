package templatemsg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// whatsAppCloudDefaultBaseURL is the Graph API root the Cloud API is served
// from. Injectable via WhatsAppCloudConfig.BaseURL so tests can point Send at
// an httptest server.
const whatsAppCloudDefaultBaseURL = "https://graph.facebook.com"

// whatsAppCloudHTTPTimeout bounds a single send when the caller supplies no
// HTTP client of its own.
const whatsAppCloudHTTPTimeout = 15 * time.Second

// whatsAppCloudResponseLimit caps how much of a response body is read, so a
// misbehaving endpoint cannot stream an unbounded response.
const whatsAppCloudResponseLimit = 1 << 16

// whatsAppCloudAPIVersionPattern is the shape of a Graph API version
// ("v26.0"). The version and the phone number id form the request path, so
// both are held to a shape that cannot change it.
var whatsAppCloudAPIVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+$`)

// WhatsAppCloudConfig configures a Sender for the WhatsApp Business Cloud
// API. AccessToken, PhoneNumberID and APIVersion are required.
type WhatsAppCloudConfig struct {
	// AccessToken is the bearer token the Graph API authenticates the send
	// with: a system user's token with the whatsapp_business_messaging
	// permission.
	AccessToken string

	// PhoneNumberID is the id (digits) of the business phone number the
	// messages are sent from, as the WhatsApp Manager shows it. It is not the
	// phone number itself.
	PhoneNumberID string

	// APIVersion is the Graph API version called, e.g. "v26.0". There is no
	// default: a caller pins the version it was tested against.
	APIVersion string

	// DefaultLanguage is the template language code (e.g. "en_US") used when
	// a Message names none. Empty means every Message must name its own.
	DefaultLanguage string

	// CodeButton says the template has a one-time-password button (copy
	// code, as authentication templates do): the send then carries the code
	// a second time, as the button's parameter, which such a template
	// refuses a send without. A Message to such a template has exactly one
	// parameter, the code.
	CodeButton bool

	// BaseURL overrides the Graph API root for tests. Empty uses
	// whatsAppCloudDefaultBaseURL.
	BaseURL string

	// HTTPClient overrides the HTTP client (and thus the timeout) for tests.
	// Empty uses a client with whatsAppCloudHTTPTimeout.
	HTTPClient *http.Client
}

type whatsAppCloudSender struct {
	endpoint        string
	accessToken     string
	defaultLanguage string
	codeButton      bool
	client          *http.Client
}

// Validate reports the first value a send needs that cfg is missing or has
// malformed: an access token with no spaces, a phone number id of digits, an
// API version shaped like "v26.0", and a default language, when set, with no
// spaces. The errors never quote the token.
func (cfg WhatsAppCloudConfig) Validate() error {
	if cfg.AccessToken == "" || strings.ContainsFunc(cfg.AccessToken, isSpaceOrControl) {
		return errors.New("templatemsg: whatsapp cloud access token is required and must have no spaces or line breaks")
	}
	if !isDigits(cfg.PhoneNumberID) {
		return fmt.Errorf("templatemsg: whatsapp cloud phone number id %q must be the id WhatsApp Manager shows, digits only, not the number",
			cfg.PhoneNumberID)
	}
	if !whatsAppCloudAPIVersionPattern.MatchString(cfg.APIVersion) {
		return fmt.Errorf("templatemsg: whatsapp cloud api version %q must look like v26.0", cfg.APIVersion)
	}
	if strings.ContainsFunc(cfg.DefaultLanguage, isSpaceOrControl) {
		return fmt.Errorf("templatemsg: whatsapp cloud default language %q must be a language code such as en_US", cfg.DefaultLanguage)
	}
	return nil
}

// NewWhatsAppCloud builds a Sender that delivers template messages through
// the WhatsApp Business Cloud API. It returns Validate's error for a config
// a send cannot use.
func NewWhatsAppCloud(cfg WhatsAppCloudConfig) (Sender, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	base := cfg.BaseURL
	if base == "" {
		base = whatsAppCloudDefaultBaseURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: whatsAppCloudHTTPTimeout}
	}
	return &whatsAppCloudSender{
		endpoint:        fmt.Sprintf("%s/%s/%s/messages", strings.TrimRight(base, "/"), cfg.APIVersion, cfg.PhoneNumberID),
		accessToken:     cfg.AccessToken,
		defaultLanguage: cfg.DefaultLanguage,
		codeButton:      cfg.CodeButton,
		client:          client,
	}, nil
}

// whatsAppSendBody is the Cloud API's template-message request.
type whatsAppSendBody struct {
	MessagingProduct string           `json:"messaging_product"`
	RecipientType    string           `json:"recipient_type"`
	To               string           `json:"to"`
	Type             string           `json:"type"`
	Template         whatsAppTemplate `json:"template"`
}

type whatsAppTemplate struct {
	Name       string              `json:"name"`
	Language   whatsAppLanguage    `json:"language"`
	Components []whatsAppComponent `json:"components,omitempty"`
}

type whatsAppLanguage struct {
	Code string `json:"code"`
}

type whatsAppComponent struct {
	Type       string              `json:"type"`
	SubType    string              `json:"sub_type,omitempty"`
	Index      string              `json:"index,omitempty"`
	Parameters []whatsAppParameter `json:"parameters"`
}

type whatsAppParameter struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// whatsAppErrorBody is the part of a Graph API error response a failure is
// reported with. The error's message and details are left out: they can
// quote the recipient.
type whatsAppErrorBody struct {
	Error struct {
		Code      int    `json:"code"`
		FBTraceID string `json:"fbtrace_id"`
	} `json:"error"`
}

func (s *whatsAppCloudSender) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	language := m.Language
	if language == "" {
		language = s.defaultLanguage
	}
	if language == "" {
		return fmt.Errorf("%w: language is required (the sender has no default)", ErrInvalidMessage)
	}
	if s.codeButton && len(m.Params) != 1 {
		return fmt.Errorf("%w: a template with a code button takes exactly one parameter, the code", ErrInvalidMessage)
	}

	body, err := json.Marshal(whatsAppSendBody{
		MessagingProduct: "whatsapp",
		RecipientType:    "individual",
		To:               m.To,
		Type:             "template",
		Template: whatsAppTemplate{
			Name:       m.Template,
			Language:   whatsAppLanguage{Code: language},
			Components: s.components(m.Params),
		},
	})
	if err != nil {
		return fmt.Errorf("%w: marshal request: %w", ErrTransport, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: whatsapp cloud: %w", ErrTransport, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return whatsAppCloudFailure(resp)
	}
	// Drain so the connection can be reused; the message id in the payload is
	// not needed (the verification flow keeps its own record).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, whatsAppCloudResponseLimit))
	return nil
}

// components are the template's body parameters and, for a template with a
// code button, the button's parameter: the code again.
func (s *whatsAppCloudSender) components(params []string) []whatsAppComponent {
	var out []whatsAppComponent
	if len(params) > 0 {
		body := whatsAppComponent{Type: "body", Parameters: make([]whatsAppParameter, len(params))}
		for i, p := range params {
			body.Parameters[i] = whatsAppParameter{Type: "text", Text: p}
		}
		out = append(out, body)
	}
	if s.codeButton {
		out = append(out, whatsAppComponent{
			Type: "button", SubType: "url", Index: "0",
			Parameters: []whatsAppParameter{{Type: "text", Text: params[0]}},
		})
	}
	return out
}

// whatsAppCloudFailure reports a refused send by its HTTP status and the
// Graph API's error code and trace id, which say what went wrong without
// carrying the recipient.
func whatsAppCloudFailure(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, whatsAppCloudResponseLimit))
	var parsed whatsAppErrorBody
	if json.Unmarshal(raw, &parsed) != nil || parsed.Error.Code == 0 {
		return fmt.Errorf("%w: whatsapp cloud HTTP %d", ErrTransport, resp.StatusCode)
	}
	return fmt.Errorf("%w: whatsapp cloud HTTP %d, error code %d (fbtrace_id %q)",
		ErrTransport, resp.StatusCode, parsed.Error.Code, parsed.Error.FBTraceID)
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func isSpaceOrControl(r rune) bool {
	return r <= ' ' || r == 0x7f
}
