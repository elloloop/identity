package sms

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// snsService and snsSigningAlgorithm are SigV4 constants for the SNS
// Publish call. Pinned per AGENTS.md §10.
const (
	snsService          = "sns"
	snsSigningAlgorithm = "AWS4-HMAC-SHA256"
)

// snsHTTPTimeout bounds a single SNS Publish when the caller supplies
// no HTTP client.
const snsHTTPTimeout = 15 * time.Second

// snsResponseLimit caps how much of a response body is read.
const snsResponseLimit = 1 << 16

// SNSConfig configures an AWS SNS Sender. Region, AccessKeyID, and
// SecretAccessKey are required; SenderID is an optional originating id.
type SNSConfig struct {
	// Region is the AWS region, e.g. "us-east-1". It selects the
	// regional SNS endpoint and is part of the SigV4 credential scope.
	Region string

	// AccessKeyID and SecretAccessKey are the IAM credentials used to
	// SigV4-sign the Publish request.
	AccessKeyID     string
	SecretAccessKey string

	// SessionToken, when set, is sent as X-Amz-Security-Token for
	// temporary credentials. Optional.
	SessionToken string

	// SenderID is the optional originating sender id, applied as the
	// AWS.SNS.SMS.SenderID message attribute and as the From fallback.
	SenderID string

	// BaseURL overrides the regional endpoint for tests. Empty derives
	// "https://sns.{region}.amazonaws.com/" from Region.
	BaseURL string

	// HTTPClient overrides the HTTP client for tests. Empty uses a
	// client with snsHTTPTimeout.
	HTTPClient *http.Client

	// now is an injectable clock for deterministic SigV4 timestamps in
	// tests. nil uses time.Now.
	now func() time.Time
}

type snsSender struct {
	region    string
	accessKey string
	secretKey string
	sessTok   string
	senderID  string
	baseURL   string
	client    *http.Client
	now       func() time.Time
}

// NewSNS builds an AWS SNS Sender from cfg. SigV4 signing is done with
// the standard library (crypto/hmac + crypto/sha256); no AWS SDK
// dependency is pulled in. Returns a wrapped ErrTransport on missing
// credentials.
func NewSNS(cfg SNSConfig) (Sender, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, fmt.Errorf("%w: sns region is required", ErrTransport)
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" {
		return nil, fmt.Errorf("%w: sns access key id is required", ErrTransport)
	}
	if strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, fmt.Errorf("%w: sns secret access key is required", ErrTransport)
	}
	base := cfg.BaseURL
	if base == "" {
		base = fmt.Sprintf("https://sns.%s.amazonaws.com/", cfg.Region)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: snsHTTPTimeout}
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &snsSender{
		region:    cfg.Region,
		accessKey: cfg.AccessKeyID,
		secretKey: cfg.SecretAccessKey,
		sessTok:   cfg.SessionToken,
		senderID:  cfg.SenderID,
		baseURL:   base,
		client:    client,
		now:       nowFn,
	}, nil
}

func (s *snsSender) Send(ctx context.Context, m Message) error {
	if m.From == "" {
		m.From = s.senderID
	}
	if err := m.Validate(); err != nil {
		return err
	}

	form := url.Values{}
	form.Set("Action", "Publish")
	form.Set("Version", "2010-03-31")
	form.Set("PhoneNumber", m.To)
	form.Set("Message", m.Body)
	if s.senderID != "" {
		form.Set("MessageAttributes.entry.1.Name", "AWS.SNS.SMS.SenderID")
		form.Set("MessageAttributes.entry.1.Value.DataType", "String")
		form.Set("MessageAttributes.entry.1.Value.StringValue", s.senderID)
	}
	payload := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrTransport, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := s.signV4(req, []byte(payload)); err != nil {
		return fmt.Errorf("%w: sign request: %w", ErrTransport, err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, snsResponseLimit))
		return fmt.Errorf("%w: sns HTTP %d: %s", ErrTransport, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, snsResponseLimit))
	return nil
}

// signV4 applies AWS Signature Version 4 to req for the SNS service.
// The implementation follows the canonical-request → string-to-sign →
// signing-key → Authorization-header pipeline from the AWS docs, using
// only crypto/hmac and crypto/sha256.
func (s *snsSender) signV4(req *http.Request, payload []byte) error {
	now := s.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	host := req.URL.Host
	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	if s.sessTok != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessTok)
	}

	payloadHashRaw := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadHashRaw[:])

	// Canonical headers must be sorted by lowercased name. We always
	// sign host, content-type, x-amz-date (+ security token when set).
	signed := map[string]string{
		"host":         host,
		"content-type": req.Header.Get("Content-Type"),
		"x-amz-date":   amzDate,
	}
	if s.sessTok != "" {
		signed["x-amz-security-token"] = s.sessTok
	}
	names := make([]string, 0, len(signed))
	for k := range signed {
		names = append(names, k)
	}
	sort.Strings(names)

	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(signed[n]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		"/", // SNS uses the root path; query string is empty (params are in the body).
		"",
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, s.region, snsService, "aws4_request"}, "/")
	canonicalRequestHashRaw := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		snsSigningAlgorithm,
		amzDate,
		credentialScope,
		hex.EncodeToString(canonicalRequestHashRaw[:]),
	}, "\n")

	signingKey := sigV4SigningKey(s.secretKey, dateStamp, s.region, snsService)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authorization := fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		snsSigningAlgorithm, s.accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authorization)
	return nil
}

// sigV4SigningKey derives the SigV4 signing key by chaining HMAC-SHA256
// over the date, region, service, and the "aws4_request" terminator.
func sigV4SigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
