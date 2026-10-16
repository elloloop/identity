// Command agent-delegation demonstrates a public native client and a resource
// server. It requires an operator-configured Identity issuer and registration;
// it never creates accounts or approves consent itself.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

type settings struct{ issuer, project, clientID, resource, resourceID, resourceSecret string }

func loadSettings() (settings, error) {
	s := settings{issuer: os.Getenv("DEMO_IDENTITY_ISSUER"), project: os.Getenv("DEMO_PROJECT_ID"), clientID: os.Getenv("DEMO_CLIENT_ID"), resource: os.Getenv("DEMO_RESOURCE"), resourceID: os.Getenv("DEMO_RESOURCE_ID"), resourceSecret: os.Getenv("DEMO_RESOURCE_SECRET")}
	u, err := url.Parse(s.issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return s, errors.New("configure an HTTPS DEMO_IDENTITY_ISSUER origin")
	}
	r, err := url.Parse(s.resource)
	if err != nil || r.Scheme != "https" || r.Hostname() == "" || r.User != nil || r.RawQuery != "" || r.Fragment != "" || s.project == "" || s.clientID == "" {
		return s, errors.New("configure DEMO_PROJECT_ID, DEMO_CLIENT_ID and HTTPS DEMO_RESOURCE")
	}
	return s, nil
}

func protocolClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func main() {
	mode := flag.String("mode", "native", "native or resource")
	flag.Parse()
	if err := run(*mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(mode string) error {
	s, err := loadSettings()
	if err != nil {
		return err
	}
	switch mode {
	case "native":
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return runNative(ctx, s, protocolClient(), os.Stdout)
	case "resource":
		if s.resourceID == "" || s.resourceSecret == "" {
			return errors.New("resource mode needs dedicated DEMO_RESOURCE_ID and DEMO_RESOURCE_SECRET")
		}
		server := &http.Server{Addr: "127.0.0.1:8099", Handler: resourceHandler(s, protocolClient()), ReadHeaderTimeout: 5 * time.Second}
		fmt.Println("Example resource listening on 127.0.0.1:8099; put it behind your configured HTTPS resource origin")
		return server.ListenAndServe()
	default:
		return errors.New("mode must be native or resource")
	}
}
