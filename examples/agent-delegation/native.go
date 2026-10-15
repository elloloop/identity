package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func randomValue() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return errors.New("identity request failed; no credentials were logged")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return errors.New("identity refused the request; restart consent rather than substituting a human token")
	}
	if out == nil {
		return nil
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out); err != nil {
		return errors.New("invalid bounded Identity response")
	}
	return nil
}

func callbackHandler(state, issuer string, result chan<- string) http.Handler {
	var consumed atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		q := r.URL.Query()
		valid := r.Method == http.MethodGet && r.URL.Path == "/callback" && len(q["state"]) == 1 && len(q["iss"]) == 1 && q.Get("iss") == issuer && subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) == 1
		if !valid {
			http.Error(w, "Invalid app callback", http.StatusBadRequest)
			return
		}
		if consumed.Load() {
			http.Error(w, "Callback already used", http.StatusConflict)
			return
		}
		if q.Get("error") != "" {
			if !consumed.CompareAndSwap(false, true) {
				http.Error(w, "Callback already used", http.StatusConflict)
				return
			}
			http.Error(w, "Access was not granted. Close this page.", http.StatusForbidden)
			select {
			case result <- "":
			default:
			}
			return
		}
		code := q.Get("code")
		if len(q["code"]) != 1 || code == "" || len(code) > 1024 {
			http.Error(w, "Invalid app callback", http.StatusBadRequest)
			return
		}
		if !consumed.CompareAndSwap(false, true) {
			http.Error(w, "Callback already used", http.StatusConflict)
			return
		}
		select {
		case result <- code:
			_, _ = io.WriteString(w, "Authorization received. You can close this page.")
		default:
			http.Error(w, "Callback already used", http.StatusConflict)
		}
	})
}

func runNative(ctx context.Context, s settings, client *http.Client, output io.Writer) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	verifier, state := randomValue(), randomValue()
	sum := sha256.Sum256([]byte(verifier))
	callback := "http://" + listener.Addr().String() + "/callback"
	result := make(chan string, 1)
	server := &http.Server{Handler: callbackHandler(state, s.issuer, result), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	defer func() { _ = server.Close() }()
	go func() { _ = server.Serve(listener) }()
	params := url.Values{"response_type": {"code"}, "client_id": {s.clientID}, "redirect_uri": {callback}, "resource": {s.resource}, "scope": {"files:read"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "state": {state}}
	_, _ = fmt.Fprintln(output, "Open this URL yourself, sign in, select your agent and review its access:")
	_, _ = fmt.Fprintln(output, s.issuer+"/oauth/authorize?"+params.Encode())
	var code string
	select {
	case code = <-result:
	case <-ctx.Done():
		return errors.New("consent timed out; no agent access was used")
	}
	shutdownContext, stopShutdown := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stopShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		return errors.New("native callback could not finish cleanly")
	}
	if code == "" {
		return errors.New("human declined agent access")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {s.clientID}, "redirect_uri": {callback}, "resource": {s.resource}, "code": {code}, "code_verifier": {verifier}}
	var tokens tokenResponse
	if err = postForm(ctx, client, s.issuer+"/oauth/token", form, &tokens); err != nil {
		return err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || !strings.EqualFold(tokens.TokenType, "Bearer") {
		return errors.New("invalid native token response")
	}
	defer func() {
		_ = postForm(ctx, client, s.issuer+"/oauth/revoke", url.Values{"client_id": {s.clientID}, "token": {tokens.RefreshToken}, "token_type_hint": {"refresh_token"}}, nil)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.resource, "/")+"/agent-demo", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response, err := client.Do(req)
	if err != nil {
		return errors.New("resource request failed")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("resource denied current delegated access")
	}
	var rotated tokenResponse
	if err = postForm(ctx, client, s.issuer+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {s.clientID}, "resource": {s.resource}, "refresh_token": {tokens.RefreshToken}}, &rotated); err != nil {
		return err
	}
	if rotated.AccessToken == "" || rotated.RefreshToken == "" || rotated.RefreshToken == tokens.RefreshToken {
		return errors.New("invalid refresh rotation")
	}
	tokens = rotated
	if err = postForm(ctx, client, s.issuer+"/oauth/revoke", url.Values{"client_id": {s.clientID}, "token": {tokens.RefreshToken}, "token_type_hint": {"refresh_token"}}, nil); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(output, "Agent resource read succeeded. Refresh rotated and grant revoked. No tokens were saved or displayed.")
	return nil
}
