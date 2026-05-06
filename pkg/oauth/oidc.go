package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type oidcDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	Issuer           string `json:"issuer"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	JWKSURI          string `json:"jwks_uri"`
}

type oidcUserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	PreferredUsername string `json:"preferred_username"`
}

func fetchOIDCDiscovery(ctx context.Context, client *http.Client, discoveryURL string) (*oidcDiscoveryDocument, error) {
	if strings.TrimSpace(discoveryURL) == "" {
		return nil, fmt.Errorf("%w: discovery endpoint is required", ErrCodeExchangeFailed)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build discovery request: %v", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeExchangeFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read discovery body: %v", ErrCodeExchangeFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: discovery HTTP %d", ErrCodeExchangeFailed, resp.StatusCode)
	}

	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse discovery document: %v", ErrCodeExchangeFailed, err)
	}
	if strings.TrimSpace(doc.TokenEndpoint) == "" {
		return nil, fmt.Errorf("%w: discovery document missing token_endpoint", ErrCodeExchangeFailed)
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return nil, fmt.Errorf("%w: discovery document missing jwks_uri", ErrCodeExchangeFailed)
	}
	return &doc, nil
}

func fetchOIDCUserInfo(ctx context.Context, client *http.Client, userinfoURL, accessToken string) (*oidcUserInfo, error) {
	if strings.TrimSpace(userinfoURL) == "" || strings.TrimSpace(accessToken) == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build userinfo request: %v", ErrIdentityVerification, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityVerification, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read userinfo body: %v", ErrIdentityVerification, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: userinfo HTTP %d", ErrIdentityVerification, resp.StatusCode)
	}

	var info oidcUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("%w: parse userinfo: %v", ErrIdentityVerification, err)
	}
	return &info, nil
}
