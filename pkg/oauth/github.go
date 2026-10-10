package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Default GitHub OAuth endpoints.
const (
	githubAuthorizationURL = "https://github.com/login/oauth/authorize"
	githubTokenURL         = "https://github.com/login/oauth/access_token" // #nosec G101 -- OAuth token endpoint, not a credential.
	githubUserURL          = "https://api.github.com/user"
	githubUserMailURL      = "https://api.github.com/user/emails"
)

// GitHubConfig configures a GitHub Exchanger.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string

	HTTPClient *http.Client

	AuthorizationURL string
	TokenURL         string
	UserURL          string
	UserMailURL      string
}

type githubExchanger struct {
	cfg    GitHubConfig
	client *http.Client
}

// NewGitHub returns an Exchanger for GitHub. Note that GitHub does
// not implement OIDC; this exchanger calls the user/userEmails APIs
// directly using the access token returned by the token endpoint.
func NewGitHub(cfg GitHubConfig) Exchanger {
	if cfg.TokenURL == "" {
		cfg.TokenURL = githubTokenURL
	}
	if cfg.UserURL == "" {
		cfg.UserURL = githubUserURL
	}
	if cfg.UserMailURL == "" {
		cfg.UserMailURL = githubUserMailURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	return &githubExchanger{cfg: cfg, client: client}
}

func (g *githubExchanger) AuthorizationURL(_ context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if g.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	authURL := g.cfg.AuthorizationURL
	if authURL == "" {
		authURL = githubAuthorizationURL
	}

	params := url.Values{}
	params.Set("client_id", g.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "read:user user:email")
	if err := addPKCEParams(params, state, codeChallenge); err != nil {
		return "", err
	}
	return buildAuthorizationURL(authURL, params)
}

type githubTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (g *githubExchanger) Exchange(ctx context.Context, params ExchangeParams) (*Identity, error) {
	if params.Code == "" {
		return nil, fmt.Errorf("%w: missing authorization code", ErrCodeExchangeFailed)
	}
	if g.cfg.ClientID == "" || g.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	form := url.Values{}
	form.Set("client_id", g.cfg.ClientID)
	form.Set("client_secret", g.cfg.ClientSecret)
	form.Set("code", params.Code)
	if params.RedirectURI != "" {
		form.Set("redirect_uri", params.RedirectURI)
	}
	if params.CodeVerifier != "" {
		form.Set("code_verifier", params.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCodeExchangeFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrCodeExchangeFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: provider HTTP %d", ErrCodeExchangeFailed, resp.StatusCode)
	}
	var tr githubTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", ErrCodeExchangeFailed, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchangeFailed, tr.Error)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("%w: provider returned no access_token", ErrCodeExchangeFailed)
	}

	user, err := g.fetchUser(ctx, tr.AccessToken)
	if err != nil {
		return nil, err
	}

	email, err := g.fetchVerifiedEmail(ctx, tr.AccessToken)
	if err != nil {
		return nil, err
	}

	return &Identity{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Email:          strings.ToLower(strings.TrimSpace(email)),
		EmailVerified:  true,
		Name:           displayNameForGitHub(user),
		AvatarURL:      user.AvatarURL,
		Provider:       "github",
	}, nil
}

func displayNameForGitHub(u *githubUser) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Login
}

func (g *githubExchanger) fetchUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.UserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build user request: %w", ErrIdentityVerification, err)
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("%w: user HTTP %d", ErrIdentityVerification, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read user body: %w", ErrIdentityVerification, err)
	}
	var u githubUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("%w: parse user: %w", ErrIdentityVerification, err)
	}
	if u.ID == 0 {
		return nil, fmt.Errorf("%w: user missing id", ErrIdentityVerification)
	}
	return &u, nil
}

// fetchVerifiedEmail returns the user's verified primary address, else
// their first verified address. The profile's public email is never used:
// GitHub lets a user set it to any address without proving it.
func (g *githubExchanger) fetchVerifiedEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.UserMailURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: build emails request: %w", ErrIdentityVerification, err)
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrIdentityVerification, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("%w: emails HTTP %d", ErrIdentityVerification, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: read emails: %w", ErrIdentityVerification, err)
	}
	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("%w: parse emails: %w", ErrIdentityVerification, err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("%w: no verified address", ErrEmailNotVerified)
}
