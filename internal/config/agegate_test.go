package config

import "testing"

func TestValidate_AgeGate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:   "disabled needs no thresholds",
			mutate: func(c *Config) { *c = Config{AgeGateEnabled: false} },
		},
		{
			name: "enabled happy path",
			mutate: func(c *Config) {
				*c = Config{AgeGateEnabled: true, AgeGateChildMaxAge: 12, AgeGateAdultAge: 18}
			},
		},
		{
			name: "negative child max age",
			mutate: func(c *Config) {
				*c = Config{AgeGateEnabled: true, AgeGateChildMaxAge: -1, AgeGateAdultAge: 18}
			},
			wantErr: true,
		},
		{
			name: "adult age equal to child max",
			mutate: func(c *Config) {
				*c = Config{AgeGateEnabled: true, AgeGateChildMaxAge: 18, AgeGateAdultAge: 18}
			},
			wantErr: true,
		},
		{
			name: "adult age below child max",
			mutate: func(c *Config) {
				*c = Config{AgeGateEnabled: true, AgeGateChildMaxAge: 18, AgeGateAdultAge: 13}
			},
			wantErr: true,
		},
		{
			// Fail closed: every DOB enforcement site short-circuits on the
			// gate, so this pair would boot clean and enforce nothing while
			// the operator believes every session is age-known.
			name: "require DOB without the gate is refused",
			mutate: func(c *Config) {
				*c = Config{AgeGateEnabled: false, AgeGateRequireDOB: true}
			},
			wantErr: true,
		},
		{
			name: "require DOB with the gate on is fine",
			mutate: func(c *Config) {
				*c = Config{AgeGateEnabled: true, AgeGateRequireDOB: true, AgeGateChildMaxAge: 12, AgeGateAdultAge: 18}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil; want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v; want nil", err)
			}
		})
	}
}

// A disabled deployment must never be rejected for nonsensical thresholds.
func TestValidate_AgeGateDisabledIgnoresThresholds(t *testing.T) {
	cfg := &Config{AgeGateEnabled: false, AgeGateChildMaxAge: 99, AgeGateAdultAge: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; want nil when age-gate disabled", err)
	}
}
