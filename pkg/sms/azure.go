package sms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// azureAPIVersion pins the Azure Communication Services SMS REST API
// version. Pinned (not floating) per AGENTS.md §10.
const azureAPIVersion = "2021-03-07"

// azureHTTPTimeout bounds a single ACS send when the caller supplies no
// HTTP client.
const azureHTTPTimeout = 15 * time.Second

// azureResponseLimit caps how much of a response body is read.
const azureResponseLimit = 1 << 16

// AzureConfig configures an Azure Communication Services SMS Sender.
// Endpoint, AccessKey, and From are required. The endpoint + access key
// are typically supplied together as a connection string of the form
// "endpoint=https://x.communication.azure.com/;accesskey=BASE64" —
// ParseAzureConnectionString splits one into the two fields.
type AzureConfig struct {
	// Endpoint is the ACS resource endpoint, e.g.
	// "https://my-resource.communication.azure.com".
	Endpoint string

	// AccessKey is the base64-encoded HMAC key from the connection
	// string. It signs each request.
	AccessKey string

	// From is the originating number (alphanumeric sender id or E.164)
	// used when Message.From is empty.
	From string

	// HTTPClient overrides the HTTP client for tests. Empty uses a
	// client with azureHTTPTimeout.
	HTTPClient *http.Client
}

// ParseAzureConnectionString splits an ACS connection string into its
// endpoint and accesskey halves. It returns a wrapped ErrTransport when
// either part is missing.
func ParseAzureConnectionString(cs string) (endpoint, accessKey string, err error) {
	for _, part := range strings.Split(cs, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "endpoint":
			endpoint = strings.TrimSpace(kv[1])
		case "accesskey":
			accessKey = strings.TrimSpace(kv[1])
		}
	}
	if endpoint == "" || accessKey == "" {
		return "", "", fmt.Errorf("%w: azure connection string must contain endpoint= and accesskey=", ErrTransport)
	}
	return endpoint, accessKey, nil
}

type azureSender struct {
	endpoint  string
	accessKey []byte
	from      string
	client    *http.Client
}

// NewAzure builds an Azure Communication Services SMS Sender from cfg.
// It returns a wrapped ErrTransport on missing/invalid credentials.
func NewAzure(cfg AzureConfig) (Sender, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, fmt.Errorf("%w: azure endpoint is required", ErrTransport)
	}
	if strings.TrimSpace(cfg.AccessKey) == "" {
		return nil, fmt.Errorf("%w: azure access key is required", ErrTransport)
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("%w: azure from is required", ErrTransport)
	}
	key, err := base64.StdEncoding.DecodeString(cfg.AccessKey)
	if err != nil {
		return nil, fmt.Errorf("%w: azure access key is not base64: %w", ErrTransport, err)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: azureHTTPTimeout}
	}
	return &azureSender{
		endpoint:  strings.TrimRight(cfg.Endpoint, "/"),
		accessKey: key,
		from:      cfg.From,
		client:    client,
	}, nil
}

// azureSendBody is the ACS /sms request payload.
type azureSendBody struct {
	From        string           `json:"from"`
	Recipients  []azureRecipient `json:"smsRecipients"`
	Message     string           `json:"message"`
	SendOptions azureSendOptions `json:"smsSendOptions"`
}

type azureRecipient struct {
	To string `json:"to"`
}

type azureSendOptions struct {
	EnableDeliveryReport bool `json:"enableDeliveryReport"`
}

func (s *azureSender) Send(ctx context.Context, m Message) error {
	if m.From == "" {
		m.From = s.from
	}
	if err := m.Validate(); err != nil {
		return err
	}

	body, err := json.Marshal(azureSendBody{
		From:        m.From,
		Recipients:  []azureRecipient{{To: m.To}},
		Message:     m.Body,
		SendOptions: azureSendOptions{EnableDeliveryReport: false},
	})
	if err != nil {
		return fmt.Errorf("%w: marshal request: %w", ErrTransport, err)
	}

	endpoint := fmt.Sprintf("%s/sms?api-version=%s", s.endpoint, azureAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrTransport, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := s.signHMAC(req, body); err != nil {
		return fmt.Errorf("%w: sign request: %w", ErrTransport, err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, azureResponseLimit))
		return fmt.Errorf("%w: azure HTTP %d: %s", ErrTransport, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, azureResponseLimit))
	return nil
}

// signHMAC applies the ACS HMAC-SHA256 request signature
// (Azure "HMAC-SHA256 SignedHeaders=...&Signature=...") to req. The
// signed string is "VERB\npath-and-query\ndate;host;contenthash".
func (s *azureSender) signHMAC(req *http.Request, body []byte) error {
	u, err := url.Parse(req.URL.String())
	if err != nil {
		return err
	}
	pathAndQuery := u.RequestURI()

	contentHashRaw := sha256.Sum256(body)
	contentHash := base64.StdEncoding.EncodeToString(contentHashRaw[:])

	dateStr := time.Now().UTC().Format(http.TimeFormat)
	host := u.Host

	stringToSign := strings.Join([]string{
		req.Method,
		pathAndQuery,
		dateStr + ";" + host + ";" + contentHash,
	}, "\n")

	mac := hmac.New(sha256.New, s.accessKey)
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("x-ms-date", dateStr)
	req.Header.Set("x-ms-content-sha256", contentHash)
	req.Header.Set("Authorization",
		"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+signature)
	return nil
}
