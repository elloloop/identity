package config

import (
	"strings"
	"testing"
)

func TestValidateLogExport_OffIgnoresTheEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "not a url"} {
		c := &Config{OTelLogsEnabled: false, OTelLogsEndpoint: endpoint}
		if err := c.ValidateLogExport(); err != nil {
			t.Errorf("disabled export with endpoint %q: %v, want nil", endpoint, err)
		}
	}
}

func TestValidateLogExport_AcceptsAnHTTPBaseURL(t *testing.T) {
	for _, endpoint := range []string{
		"http://collector.example.test:4318",
		"https://collector.example.test/",
		" http://collector.example.test:4318/otlp ",
	} {
		c := &Config{OTelLogsEnabled: true, OTelLogsEndpoint: endpoint}
		if err := c.ValidateLogExport(); err != nil {
			t.Errorf("endpoint %q: %v, want nil", endpoint, err)
		}
	}
}

func TestValidateLogExport_RefusesWhatCannotBeACollectorBaseURL(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"   ",
		"not a url",
		"collector.example.test:4318",
		"ftp://collector.example.test",
		"http://",
		"://collector.example.test",
		"http://[::1",
		"http://collector.example.test:4318?x=1",
		"http://collector.example.test:4318#frag",
		"user:s3cret@collector.example.test:4318",
	} {
		c := &Config{OTelLogsEnabled: true, OTelLogsEndpoint: endpoint}
		err := c.ValidateLogExport()
		if err == nil {
			t.Errorf("endpoint %q: want an error", endpoint)
			continue
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("endpoint %q: the error repeats the value: %v", endpoint, err)
		}
	}
}

func TestValidate_RunsTheLogExportCheck(t *testing.T) {
	c := baseValidConfig()
	c.OTelLogsEnabled = true
	c.OTelLogsEndpoint = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "GATEWAY_OTEL_LOGS_ENDPOINT") {
		t.Fatalf("Validate() = %v, want the log export error", err)
	}
}

func TestLoad_ReadsTheLogExportSettings(t *testing.T) {
	t.Setenv("GATEWAY_OTEL_LOGS_ENABLED", "true")
	t.Setenv("GATEWAY_OTEL_LOGS_ENDPOINT", "http://collector.example.test:4318")
	c := Load()
	if !c.OTelLogsEnabled || c.OTelLogsEndpoint != "http://collector.example.test:4318" {
		t.Fatalf("Load() = enabled %v, endpoint %q", c.OTelLogsEnabled, c.OTelLogsEndpoint)
	}
}
