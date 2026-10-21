package ui

import (
	"net/http"
	"net/url"
)

// RequestOrigin is the scheme and host r reached, as the reverse proxy in
// front of this server reports them: X-Forwarded-Proto and X-Forwarded-Host
// when set, else TLS and the Host header. The hosted flow builds each
// provider's redirect URI from it, so in any deployment where hosted sign-in
// works it names this server as the browser sees it.
func RequestOrigin(r *http.Request) *url.URL {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	host := r.Host
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = forwarded
	}
	return &url.URL{Scheme: scheme, Host: host}
}
