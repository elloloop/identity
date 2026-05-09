package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func generateRandomValue(numBytes int) (string, error) {
	if numBytes <= 0 {
		return "", errors.New("oauth: random value size must be positive")
	}
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateState returns a high-entropy OAuth state string.
func GenerateState() (string, error) {
	return generateRandomValue(32)
}

// GenerateCodeVerifier returns a PKCE code verifier.
func GenerateCodeVerifier() (string, error) {
	return generateRandomValue(32)
}

// CodeChallengeS256 returns the PKCE S256 code challenge for verifier.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func buildAuthorizationURL(baseURL string, params url.Values) (string, error) {
	if strings.TrimSpace(baseURL) == "" {
		return "", fmt.Errorf("%w: provider authorization URL is not configured", ErrCodeExchangeFailed)
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: parse authorization URL: %w", ErrCodeExchangeFailed, err)
	}
	query := u.Query()
	for key, values := range params {
		if len(values) == 0 {
			continue
		}
		query.Del(key)
		for _, value := range values {
			query.Add(key, value)
		}
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func addPKCEParams(params url.Values, state, codeChallenge string) error {
	if strings.TrimSpace(state) == "" {
		return fmt.Errorf("%w: state is required", ErrStateValidation)
	}
	if strings.TrimSpace(codeChallenge) == "" {
		return fmt.Errorf("%w: code challenge is required", ErrCodeExchangeFailed)
	}
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	return nil
}

// Compile-time assertions: provider exchangers must also know how to start
// an OAuth authorization flow.
var (
	_ Authorizer = (*googleExchanger)(nil)
	_ Authorizer = (*microsoftExchanger)(nil)
	_ Authorizer = (*githubExchanger)(nil)
)
