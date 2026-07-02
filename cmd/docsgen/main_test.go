package main

import (
	"go/ast"
	"go/parser"
	"strings"
	"testing"
)

// TestIsConditionalAntecedent covers both antecedent shapes of a conditional
// requirement (the value-equality "=" form and the "when X is set" state form),
// and crucially the regression that a consequent var phrased as "X is empty"
// WITHOUT a preceding "when" (the OTLP endpoint check) is NOT mistaken for an
// antecedent — and that the antecedent "...when GATEWAY_TOTP_ENCRYPTION_KEY is
// set" is skipped so only GATEWAY_TOTP_RECOVERY_PEPPER stays required.
func TestIsConditionalAntecedent(t *testing.T) {
	tests := []struct {
		name  string
		val   string
		token string
		want  bool
	}{
		{
			"value-equality antecedent",
			"GATEWAY_JWT_KMS_KEYS is required when GATEWAY_JWT_SIGNER=kms_aws",
			"GATEWAY_JWT_SIGNER", true,
		},
		{
			"value-equality consequent stays required",
			"GATEWAY_JWT_KMS_KEYS is required when GATEWAY_JWT_SIGNER=kms_aws",
			"GATEWAY_JWT_KMS_KEYS", false,
		},
		{
			"when-is-set antecedent is skipped",
			"GATEWAY_TOTP_RECOVERY_PEPPER is required when GATEWAY_TOTP_ENCRYPTION_KEY is set",
			"GATEWAY_TOTP_ENCRYPTION_KEY", true,
		},
		{
			"when-is-set consequent stays required",
			"GATEWAY_TOTP_RECOVERY_PEPPER is required when GATEWAY_TOTP_ENCRYPTION_KEY is set",
			"GATEWAY_TOTP_RECOVERY_PEPPER", false,
		},
		{
			"is-empty without when is a genuine requirement, not an antecedent",
			"observability: GATEWAY_OTEL_ENABLED=true but GATEWAY_OTEL_EXPORTER_ENDPOINT is empty",
			"GATEWAY_OTEL_EXPORTER_ENDPOINT", false,
		},
		{
			"when-is-empty antecedent is skipped",
			"GATEWAY_X is required when GATEWAY_Y is empty",
			"GATEWAY_Y", true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx := strings.Index(tc.val, tc.token)
			if idx < 0 {
				t.Fatalf("token %q not found in %q", tc.token, tc.val)
			}
			loc := []int{idx, idx + len(tc.token)}
			if got := isConditionalAntecedent(tc.val, loc); got != tc.want {
				t.Errorf("isConditionalAntecedent(%q, token=%q) = %v, want %v",
					tc.val, tc.token, got, tc.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		fieldName string
		want      string
	}{
		{"empty", "", "Foo", ""},
		{"strips leading field name and keeps verb", "Foo is the thing.", "Foo", "is the thing."},
		{
			// The old allowlist missed verbs like "denotes"; the literal
			// field-name strip must handle any opening word.
			name: "non-allowlisted verb does not leak field name",
			raw:  "ConnectPort denotes the listener port. Extra detail.", fieldName: "ConnectPort",
			want: "denotes the listener port.",
		},
		{"keeps only first sentence", "Foo is short. Then more prose follows.", "Foo", "is short."},
		{"strips default parenthetical", "Foo is the pool size (default 25).", "Foo", "is the pool size."},
		{"strips inline gateway token", "Foo holds GATEWAY_BAR config.", "Foo", "holds config."},
		{
			name: "e.g. is not a sentence terminator",
			raw:  "Foo is the URL (e.g. https://x.example.com). Second sentence.", fieldName: "Foo",
			want: `is the URL (e.g. https://x.example.com).`,
		},
		{"comma after field name", "Foo, when true, rejects the request.", "Foo", "when true, rejects the request."},
		{"field name not a prefix is untouched", "When set, gates the flow.", "Foo", "When set, gates the flow."},
		{
			// A gateway token written as "GATEWAY_X=value" expresses a condition
			// and must be KEPT intact, not stripped — otherwise the description
			// trails off at "required when".
			name:      "keeps gateway token assignment as a condition",
			raw:       `JWTKMSKeys is a CSV of "kid=keyARN" entries for the "kms_aws" signer; required when GATEWAY_JWT_SIGNER=kms_aws.`,
			fieldName: "JWTKMSKeys",
			want:      `is a CSV of "kid=keyARN" entries for the "kms_aws" signer; required when GATEWAY_JWT_SIGNER=kms_aws.`,
		},
		{
			// A "required in prod" caveat in the SECOND sentence is security
			// relevant and must survive truncation, not be dropped.
			name:      "preserves required-in-prod second-sentence caveat",
			raw:       "TOTPEncryptionKey is the base64-encoded 32-byte AES-256 key that encrypts TOTP secrets at rest. Throwaway dev key if unset; required in prod.",
			fieldName: "TOTPEncryptionKey",
			want:      "is the base64-encoded 32-byte AES-256 key that encrypts TOTP secrets at rest. Throwaway dev key if unset; required in prod.",
		},
		{
			// An ordinary (non-caveat) second sentence is still dropped.
			name:      "drops non-caveat second sentence",
			raw:       "Foo is the issuer name shown in apps. Some extra prose here.",
			fieldName: "Foo",
			want:      "is the issuer name shown in apps.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(tc.raw, tc.fieldName); got != tc.want {
				t.Errorf("summarize(%q, %q) = %q, want %q", tc.raw, tc.fieldName, got, tc.want)
			}
		})
	}
}

func TestFirstSentenceEnd(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"simple", "abc. def", 4},
		{"no terminator", "no terminator here", -1},
		{"bang", "Hello! World", 6},
		{"question", "Really? Yes", 7},
		{"eg abbreviation skipped", "see e.g. foo bar", -1},
		{"ie abbreviation skipped then real end", "x i.e. y. z", 9},
		{"trailing period no space", "ends here.", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstSentenceEnd(tc.in); got != tc.want {
				t.Errorf("firstSentenceEnd(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestFirstSentenceWithCaveat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no terminator returns whole", "just one clause here", "just one clause here"},
		{"single sentence", "Only one. ", "Only one."},
		{"drops ordinary second sentence", "First one. Second one.", "First one."},
		{
			"keeps required-in-prod caveat",
			"Key encrypts secrets. Required in prod.",
			"Key encrypts secrets. Required in prod.",
		},
		{
			"keeps required-in-production caveat",
			"Dev key if unset. It is required in production.",
			"Dev key if unset. It is required in production.",
		},
		{
			// "not required" alone (no production requirement) is dropped.
			"drops not-required default explanation",
			"Flag gates the flow. The default is false, not required normally.",
			"Flag gates the flow.",
		},
		{
			// "produces" must not be mistaken for the "prod" caveat word.
			"drops sentence mentioning produces",
			"Queue depth for the flusher. Drops happen when it produces fast.",
			"Queue depth for the flusher.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstSentenceWithCaveat(tc.in); got != tc.want {
				t.Errorf("firstSentenceWithCaveat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"JWT & tokens", "jwt-and-tokens"},
		{"Passkeys / WebAuthn", "passkeys-webauthn"},
		{"Server & ports", "server-and-ports"},
		{"TOTP / 2FA", "totp-2fa"},
		{"Age gating (COPPA)", "age-gating-coppa"},
		{"Other", "other"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := slugify(tc.in); got != tc.want {
				t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCategoryFor(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"GATEWAY_OAUTH_GOOGLE_CLIENT_ID", "OAuth"},
		{"GATEWAY_MICROSOFT_TENANT_ID", "OAuth"},
		{"GATEWAY_PROJECT_SECRETS_KEY", "Projects & tenancy"},
		{"GATEWAY_JWT_SIGNER", "JWT & tokens"},
		{"GATEWAY_METRICS_PORT", "Server & ports"},
		{"GATEWAY_SMS_TWILIO_FROM", "Phone / SMS verification"},
		{"GATEWAY_OTEL_SAMPLE_RATIO", "OpenTelemetry"},
		{"GATEWAY_SWEEPER_BATCH_SIZE", "Sweeper (GC)"},
		{"GATEWAY_WAT_UNKNOWN", "Other"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := categoryFor(tc.in); got != tc.want {
				t.Errorf("categoryFor(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func mustParseExpr(t *testing.T, src string) ast.Expr {
	t.Helper()
	e, err := parser.ParseExpr(src)
	if err != nil {
		t.Fatalf("ParseExpr(%q): %v", src, err)
	}
	return e
}

func TestEvalConst(t *testing.T) {
	consts := map[string]ast.Expr{
		"DefaultChildMaxAge": mustParseExpr(t, "12"),
	}
	tests := []struct {
		name    string
		src     string
		wantStr string // constant.Value.String(), or "" for nil
	}{
		{"int literal", "42", "42"},
		{"binary add", "2 + 3", "5"},
		{"shift", "1 << 20", "1048576"},
		{"paren", "(7)", "7"},
		{"bool true", "true", "true"},
		{"const reference", "DefaultChildMaxAge", "12"},
		{"unknown ident", "Nope", ""},
		{"type conversion wrapper", "int64(5)", "5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := evalConst(mustParseExpr(t, tc.src), consts, map[string]bool{})
			got := ""
			if v != nil {
				got = v.String()
			}
			if got != tc.wantStr {
				t.Errorf("evalConst(%q) = %q, want %q", tc.src, got, tc.wantStr)
			}
		})
	}
}

func TestRenderDefault(t *testing.T) {
	consts := map[string]ast.Expr{
		"DefaultChildMaxAge": mustParseExpr(t, "12"),
		"DefaultScore":       mustParseExpr(t, "0.5"),
	}
	tests := []struct {
		name string
		src  string
		typ  string
		want string
	}{
		{"integer", "900", "integer", "900"},
		{"integer shift", "1 << 20", "integer", "1048576"},
		{"boolean true", "true", "boolean", "true"},
		{"boolean false", "false", "boolean", "false"},
		{"string", `"hello"`, "string", "hello"},
		{"empty string", `""`, "string", ""},
		// 0.1 is not exactly representable as float64; it must still render.
		{"number inexact", "0.1", "number", "0.1"},
		{"number exact", "0.5", "number", "0.5"},
		{"number from const", "DefaultScore", "number", "0.5"},
		{"integer from const", "DefaultChildMaxAge", "integer", "12"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := renderDefault(mustParseExpr(t, tc.src), tc.typ, consts)
			if got != tc.want {
				t.Errorf("renderDefault(%q, %q) = %q, want %q", tc.src, tc.typ, got, tc.want)
			}
		})
	}
}
