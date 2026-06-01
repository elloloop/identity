package app

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

func TestBuildSMSSender(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "disabled returns a usable (log-only) sender",
			cfg:  &config.Config{SMSEnabled: false},
		},
		{
			name: "twilio builds",
			cfg: &config.Config{
				SMSEnabled:          true,
				SMSProvider:         config.SMSProviderTwilio,
				SMSTwilioAccountSID: "AC123",
				SMSTwilioAuthToken:  "tok",
				SMSTwilioFrom:       "+15550000000",
			},
		},
		{
			name: "sns builds",
			cfg: &config.Config{
				SMSEnabled:            true,
				SMSProvider:           config.SMSProviderSNS,
				SMSAWSRegion:          "us-east-1",
				SMSAWSAccessKeyID:     "AKIA",
				SMSAWSSecretAccessKey: "secret",
			},
		},
		{
			name: "azure builds from connection string",
			cfg: &config.Config{
				SMSEnabled:               true,
				SMSProvider:              config.SMSProviderAzure,
				SMSAzureConnectionString: "endpoint=https://acs.example.com;accesskey=YWJjZGVm",
				SMSAzureFrom:             "+15550000000",
			},
		},
		{
			name: "azure with bad connection string errors",
			cfg: &config.Config{
				SMSEnabled:               true,
				SMSProvider:              config.SMSProviderAzure,
				SMSAzureConnectionString: "not-a-valid-conn-string",
				SMSAzureFrom:             "+15550000000",
			},
			wantErr: true,
		},
		{
			name: "unsupported provider errors",
			cfg: &config.Config{
				SMSEnabled:  true,
				SMSProvider: "carrier-pigeon",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := buildSMSSender(tc.cfg, zap.NewNop())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got sender %#v", s)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s == nil {
				t.Fatal("expected non-nil sender")
			}
		})
	}
}

func TestBuildSMSSender_NilLogger(t *testing.T) {
	s, err := buildSMSSender(&config.Config{SMSEnabled: false}, nil)
	if err != nil || s == nil {
		t.Fatalf("nil logger: err=%v s=%v", err, s)
	}
}
