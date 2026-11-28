package ui

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

//go:embed console_assets/index.html
var consoleFS embed.FS

// ConsolePath is where the project console is served.
const ConsolePath = "/console/"

// consolePageFile is the console's one document: markup, style and script.
const consolePageFile = "console_assets/index.html"

// consoleNonceBytes is the size of the random value a response's inline style
// and script are admitted by.
const consoleNonceBytes = 24

// consoleAllowedMethods is what the page answers to; it changes nothing.
const consoleAllowedMethods = http.MethodGet + ", " + http.MethodHead

// The console's Content-Security-Policy, one directive each. The page is a
// single document that signs a person in and holds their tokens in memory, so
// it runs nothing but its own inline style and script, each admitted by a
// nonce minted for the response, and talks to nothing but this server.
const (
	consoleCSPDefault = "default-src 'none'"
	consoleCSPScript  = "script-src "
	consoleCSPStyle   = "style-src "
	consoleCSPConnect = "connect-src 'self'"
	consoleCSPImages  = "img-src 'self' data:"
	consoleCSPBaseURI = "base-uri 'none'"
	consoleCSPForms   = "form-action 'none'"
	consoleCSPFraming = "frame-ancestors 'none'"
	consoleCSPJoin    = "; "
)

// ConsoleOptions is what the server tells the page at render time.
type ConsoleOptions struct {
	// SelfServiceProjects reports whether a signed-in account may create a project.
	SelfServiceProjects bool `json:"selfServiceProjects"`
	// SettingsApplyWithinSeconds is how long a saved change can take to govern
	// sign-ins: the lifetime of the server's project-resolution cache, which
	// goes on answering from the settings it read until then. 0 means a saved
	// change applies immediately. The page tells the person, so that a setting
	// they just saved and do not yet see enforced is not taken for a failure.
	SettingsApplyWithinSeconds int `json:"settingsApplyWithinSeconds"`
}

// consolePage is what the page template renders.
type consolePage struct {
	Nonce string
	// Options reaches the page's script as a JSON object. html/template
	// encodes a value in a script as JSON and escapes what could end the
	// script, so the options are data there whatever they hold.
	Options ConsoleOptions
}

// ConsoleHandler serves the project console page.
func ConsoleHandler(opts ConsoleOptions) http.Handler {
	page := template.Must(template.ParseFS(consoleFS, consolePageFile))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The page builds every address it calls relative to ConsolePath, so
		// it is served there and nowhere else under it.
		if r.URL.Path != ConsolePath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", consoleAllowedMethods)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		nonceBytes := make([]byte, consoleNonceBytes)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// The URL-safe alphabet, so html/template has nothing to escape in
		// the nonce attributes.
		nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
		var body bytes.Buffer
		if err := page.Execute(&body, consolePage{Nonce: nonce, Options: opts}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", consoleCSP(nonce))
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Length", strconv.Itoa(body.Len()))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body.Bytes())
	})
}

// consoleCSP is the page's policy for a response whose inline style and
// script carry nonce.
func consoleCSP(nonce string) string {
	source := "'nonce-" + nonce + "'"
	return strings.Join([]string{
		consoleCSPDefault,
		consoleCSPScript + source,
		consoleCSPStyle + source,
		consoleCSPConnect,
		consoleCSPImages,
		consoleCSPBaseURI,
		consoleCSPForms,
		consoleCSPFraming,
	}, consoleCSPJoin)
}
