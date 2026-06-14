package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/elloloop/identity/internal/config"
)

//go:embed static/*
var staticFS embed.FS

// configData holds the serialized configuration injected into the template.
type configData struct {
	PasswordSignupEnabled bool `json:"passwordSignupEnabled"`
}

// Handler returns an http.Handler that serves the embedded static files.
// It parses index.html as a template and injects the server configuration
// into it. The result is cached in memory on startup.
func Handler(cfg *config.Config) http.Handler {
	tmpl, err := template.ParseFS(staticFS, "static/index.html")
	if err != nil {
		panic(err)
	}

	data := configData{
		PasswordSignupEnabled: cfg.PasswordSignupEnabled,
	}

	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{
		"JSONConfig": template.JS("window.serverConfig = " + string(b) + ";"),
	}); err != nil {
		panic(err)
	}

	indexBytes := buf.Bytes()
	indexTime := time.Now() // Use startup time for caching

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fsHandler := http.StripPrefix("/auth/", http.FileServer(http.FS(sub)))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/auth/" || path == "/auth/index.html" {
			// Do not cache the dynamic HTML heavily, but use If-Modified-Since locally
			http.ServeContent(w, r, "index.html", indexTime, bytes.NewReader(indexBytes))
			return
		}
		fsHandler.ServeHTTP(w, r)
	})
}
