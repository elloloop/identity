package main

import (
	"go/ast"
	"go/parser"
	"testing"
)

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

func TestCategoryFor(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"GATEWAY_OAUTH_GOOGLE_CLIENT_ID", "OAuth"},
		{"GATEWAY_MICROSOFT_TENANT_ID", "OAuth"},
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
