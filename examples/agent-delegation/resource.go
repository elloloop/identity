package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type introspection struct {
	Active  bool   `json:"active"`
	Subject string `json:"sub"`
	Kind    string `json:"kind"`
	Actor   struct {
		Subject string `json:"sub"`
	} `json:"act"`
	Issuer    string   `json:"iss"`
	Project   string   `json:"project"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope"`
	GrantID   string   `json:"grant_id"`
	SID       string   `json:"sid"`
	ExpiresAt int64    `json:"exp"`
	IsMinor   bool     `json:"is_minor"`
}

func resourceHandler(s settings, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/agent-demo" {
			http.NotFound(w, r)
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") || len(headers[0]) > 16384 {
			http.Error(w, "delegated access required", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(headers[0], "Bearer ")
		if token == "" || strings.ContainsAny(token, " \t\r\n") {
			http.Error(w, "delegated access required", http.StatusUnauthorized)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.issuer+"/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
		if err != nil {
			http.Error(w, "resource unavailable", http.StatusServiceUnavailable)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(s.resourceID, s.resourceSecret)
		response, err := client.Do(req)
		if err != nil {
			http.Error(w, "resource unavailable", http.StatusServiceUnavailable)
			return
		}
		defer func() { _ = response.Body.Close() }()
		var principal introspection
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&principal) != nil {
			http.Error(w, "resource unavailable", http.StatusServiceUnavailable)
			return
		}
		if !principal.Active || principal.Kind != "agent" || principal.Subject == "" || principal.Actor.Subject == "" || principal.Actor.Subject == principal.Subject || principal.Issuer != s.issuer || principal.Project != s.project || len(principal.Audience) != 1 || principal.Audience[0] != s.resource || principal.ClientID != s.clientID || principal.GrantID == "" || principal.SID == "" || principal.IsMinor || principal.ExpiresAt <= time.Now().Unix() || !slices.Contains(strings.Fields(principal.Scope), "files:read") {
			http.Error(w, "delegated access is not current", http.StatusUnauthorized)
			return
		}
		// The authenticated introspection endpoint verifies signature and current
		// authority on every request. Never cache an active result until JWT expiry.
		_ = json.NewEncoder(w).Encode(struct {
			Agent   string `json:"agent"`
			Actor   string `json:"actor"`
			Message string `json:"message"`
		}{principal.Subject, principal.Actor.Subject, "Example files read completed"})
	})
}
