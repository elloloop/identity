package config

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateLogExport checks the log export settings: when GATEWAY_OTEL_LOGS_ENABLED
// is true, GATEWAY_OTEL_LOGS_ENDPOINT must be an absolute http or https URL with
// a host and no query or fragment. Validate runs it, and so does the identity
// command before it builds its logger, since the logger exists before Validate
// runs. The error never repeats the value, which may carry a credential.
func (c *Config) ValidateLogExport() error {
	if !c.OTelLogsEnabled {
		return nil
	}
	endpoint := strings.TrimSpace(c.OTelLogsEndpoint)
	if endpoint == "" {
		return errors.New("config: GATEWAY_OTEL_LOGS_ENABLED=true but GATEWAY_OTEL_LOGS_ENDPOINT is empty")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("config: GATEWAY_OTEL_LOGS_ENDPOINT must be an absolute http or https URL with a host and no query or fragment")
	}
	return nil
}
