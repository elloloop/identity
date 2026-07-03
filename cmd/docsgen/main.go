// Command docsgen generates the reference-data JSON that the docs site
// renders, so those tables can never drift from the implementation.
//
// It derives, straight from the Go source of truth:
//
//   - docs-site/src/data/generated/config.json — every GATEWAY_* environment
//     variable, extracted from internal/config/config.go (name, inferred
//     type, default value, required flag, description, grouping category).
//   - docs-site/src/data/generated/audit-events.json — every audit event-type
//     string, extracted from the EventType constants in pkg/audit/logger.go.
//
// Run it via `make docs-gen` or `go generate ./...`. The emitted files are
// generated artifacts: do not hand-edit them.
//
//go:generate go run .
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fail(err)
	}

	configVars, err := parseConfig(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		fail(fmt.Errorf("parse config: %w", err))
	}

	required, err := scanRequired(root)
	if err != nil {
		fail(fmt.Errorf("scan required: %w", err))
	}
	for i := range configVars {
		if required[configVars[i].Name] {
			configVars[i].Required = true
		}
	}

	// Guard: every env var must carry a description. An empty one means the
	// corresponding Config field lost (or never had) a doc comment, which
	// silently degrades the operator-facing reference. Fail loudly here rather
	// than emit a blank row.
	if missing := missingDescriptions(configVars); len(missing) > 0 {
		fail(fmt.Errorf(
			"%d env var(s) have an empty description; add a one-line Go doc comment to the "+
				"matching Config field in internal/config/config.go:\n  - %s",
			len(missing), strings.Join(missing, "\n  - ")))
	}

	events, err := parseAuditEvents(filepath.Join(root, "pkg", "audit", "logger.go"))
	if err != nil {
		fail(fmt.Errorf("parse audit events: %w", err))
	}

	outDir := filepath.Join(root, "docs-site", "src", "data", "generated")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail(err)
	}
	if err := writeJSON(filepath.Join(outDir, "config.json"), configVars); err != nil {
		fail(err)
	}
	if err := writeJSON(filepath.Join(outDir, "audit-events.json"), events); err != nil {
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "README.md"), []byte(readmeText), 0o644); err != nil {
		fail(err)
	}

	fmt.Printf("docsgen: wrote %d config vars and %d audit events to %s\n",
		len(configVars), len(events), outDir)
}

// ConfigVar is one GATEWAY_* environment variable as rendered by the docs.
type ConfigVar struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Category    string `json:"category"`
	// Anchor is the URL fragment of the category section that renders this var
	// (slugify(Category)). It is emitted here so the configuration page and the
	// deep-link anti-drift test consume one authoritative slug instead of each
	// re-deriving it.
	Anchor string `json:"anchor"`
}

// missingDescriptions returns the names of env vars whose description is empty
// (after trimming), in input order. Used as a generation-time guard.
func missingDescriptions(vars []ConfigVar) []string {
	var missing []string
	for _, v := range vars {
		if strings.TrimSpace(v.Description) == "" {
			missing = append(missing, v.Name)
		}
	}
	return missing
}

// envHelperType maps each config env-reading helper to the type it yields.
// These are the helper function names defined in internal/config/config.go.
var envHelperType = map[string]string{
	"envStr":                "string",
	"envInt":                "integer",
	"envFloat":              "number",
	"envBool":               "boolean",
	"revocationModeFromEnv": "string",
}

// parseConfig walks config.go, finds every call to an env-reading helper,
// and records the literal GATEWAY_* name, default, inferred type, and the
// description taken from the surrounding struct field's doc comment.
func parseConfig(path string) ([]ConfigVar, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	consts := collectConsts(file)
	descByField := collectFieldDocs(file)

	var out []ConfigVar
	seen := map[string]bool{}

	// Each env var is the value of a `FieldName: env*("GATEWAY_...", def)`
	// entry in the Config composite literal returned by Load(). Walk every
	// KeyValueExpr so we capture the owning field name for the description.
	ast.Inspect(file, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		fieldName, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}
		call, typ := findEnvCall(kv.Value)
		if call == nil || len(call.Args) < 2 {
			return true
		}
		name, ok := stringLit(call.Args[0])
		if !ok || !strings.HasPrefix(name, "GATEWAY_") || seen[name] {
			return true
		}
		seen[name] = true

		def := renderDefault(call.Args[1], typ, consts)
		category := categoryFor(name)
		out = append(out, ConfigVar{
			Name:        name,
			Type:        typ,
			Default:     def,
			Description: descByField[fieldName.Name],
			Category:    category,
			Anchor:      slugify(category),
		})
		return true
	})

	if len(out) == 0 {
		return nil, fmt.Errorf("no GATEWAY_* env vars found in %s", path)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// findEnvCall descends through wrappers like int64(...) and strings.ToLower(...)
// to the underlying env-helper CallExpr, returning it and its value type.
func findEnvCall(expr ast.Expr) (*ast.CallExpr, string) {
	var found *ast.CallExpr
	var typ string
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if t, ok := envHelperType[id.Name]; ok {
			found, typ = call, t
			return false
		}
		return true
	})
	return found, typ
}

// collectConsts records every top-level constant's value expression so a
// default that references a named constant (e.g. DefaultAgeGateChildMaxAge)
// can be resolved to its literal value.
func collectConsts(file *ast.File) map[string]ast.Expr {
	consts := map[string]ast.Expr{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, nm := range vs.Names {
				if i < len(vs.Values) {
					consts[nm.Name] = vs.Values[i]
				}
			}
		}
	}
	return consts
}

// collectFieldDocs maps each Config struct field name to a short description
// taken from its doc comment (preferred) or trailing line comment.
func collectFieldDocs(file *ast.File) map[string]string {
	docs := map[string]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "Config" {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, fld := range st.Fields.List {
				raw := ""
				if fld.Doc != nil {
					raw = fld.Doc.Text()
				} else if fld.Comment != nil {
					raw = fld.Comment.Text()
				}
				for _, nm := range fld.Names {
					if desc := summarize(raw, nm.Name); desc != "" {
						docs[nm.Name] = desc
					}
				}
			}
		}
	}
	return docs
}

var (
	defaultParen = regexp.MustCompile(`\s*\((?:default|optional)[^)]*\)`)
	gatewayToken = regexp.MustCompile(`GATEWAY_[A-Z0-9_]+`)
	// gatewayAssignToken matches a GATEWAY_* token, optionally followed by a
	// "=value" (as written in prose like "GATEWAY_JWT_SIGNER=kms_aws"). summarize
	// uses it to tell the two prose shapes apart: a BARE token is a redundant
	// reference to a var by its env name and is stripped ("Foo holds GATEWAY_BAR
	// config." → "holds config."); a token in ASSIGNMENT form expresses a real
	// condition and is kept intact ("...required when GATEWAY_JWT_SIGNER=kms_aws")
	// so the description does not trail off at "when".
	gatewayAssignToken = regexp.MustCompile(`GATEWAY_[A-Z0-9_]+(=\S+)?`)
	wsRun              = regexp.MustCompile(`\s+`)
)

// prodRequirementCaveat matches a follow-on sentence that states a production
// requirement (e.g. "required in prod" / "is required in production"). Such a
// caveat is security relevant and must survive single-sentence truncation — it
// is why GATEWAY_TOTP_ENCRYPTION_KEY keeps its second sentence. It deliberately
// requires both "required" and a "prod"/"production" WORD so ordinary prose that
// merely says "not required" or "produces" is not pulled in.
var prodRequirementCaveat = regexp.MustCompile(`(?i)\brequired\b.*\bprod(uction)?\b`)

// summarize reduces a Go doc comment to a short operator-facing description: it
// drops the leading "FieldName" the Go doc convention prepends (matched
// literally against the known field name, so a comment opening with any verb —
// not only an allowlisted one — never leaks the identifier), keeps the first
// sentence plus any immediately following security/requirement caveat (so a
// "required in prod" warning is never silently dropped), strips bare inline
// GATEWAY_* references (but keeps "GATEWAY_X=value" condition clauses intact)
// and "(default ...)" parentheticals, and collapses whitespace.
func summarize(raw, fieldName string) string {
	s := wsRun.ReplaceAllString(strings.TrimSpace(raw), " ")
	if s == "" {
		return ""
	}
	s = firstSentenceWithCaveat(s)
	s = defaultParen.ReplaceAllString(s, "")
	s = gatewayAssignToken.ReplaceAllStringFunc(s, func(m string) string {
		// Keep "GATEWAY_X=value" intact: it expresses a condition, and dropping
		// the value would leave the sentence trailing off ("...required when").
		if strings.Contains(m, "=") {
			return m
		}
		return " "
	})
	s = wsRun.ReplaceAllString(strings.TrimSpace(s), " ")
	// Drop a leading field name (Go's "Name is ..." doc convention), matched
	// literally so the Go identifier never leaks into operator-facing docs.
	if fieldName != "" {
		if rest, ok := strings.CutPrefix(s, fieldName); ok && (rest == "" || rest[0] == ' ' || rest[0] == ',') {
			s = strings.TrimSpace(rest)
		}
	}
	s = strings.TrimLeft(s, "—-:, ")
	return strings.TrimSpace(s)
}

// firstSentenceWithCaveat keeps the first sentence of s and, when the sentence
// immediately following it states a production requirement (see
// prodRequirementCaveat, e.g. "required in prod"), keeps that sentence too. This
// stops single-sentence truncation from dropping production-required warnings
// while still trimming ordinary trailing prose.
func firstSentenceWithCaveat(s string) string {
	end := firstSentenceEnd(s)
	if end <= 0 {
		return s
	}
	first := s[:end]
	rest := strings.TrimLeft(s[end:], " ")
	if rest == "" {
		return first
	}
	next := rest
	if nextEnd := firstSentenceEnd(rest); nextEnd > 0 {
		next = rest[:nextEnd]
	}
	if prodRequirementCaveat.MatchString(next) {
		return strings.TrimRight(first, " ") + " " + next
	}
	return first
}

func firstSentenceEnd(s string) int {
	for i := 0; i < len(s)-1; i++ {
		if (s[i] == '.' || s[i] == '!' || s[i] == '?') && s[i+1] == ' ' {
			// Skip inline abbreviations ("e.g.", "i.e.") whose dot is not a
			// real sentence terminator.
			if s[i] == '.' && isAbbreviationDot(s, i) {
				continue
			}
			return i + 1
		}
	}
	return -1
}

// isAbbreviationDot reports whether the period at index i is the trailing dot
// of an inline abbreviation like "e.g." or "i.e.".
func isAbbreviationDot(s string, i int) bool {
	lower := strings.ToLower(s[:i+1])
	for _, abbr := range []string{"e.g.", "i.e."} {
		if strings.HasSuffix(lower, abbr) {
			return true
		}
	}
	return false
}

// renderDefault evaluates the default-value expression (a constant or a
// constant expression such as 1<<20, possibly referencing a named const)
// and renders it as the string the docs should show. An empty string
// default renders as "" (the page shows it as "(empty)").
func renderDefault(expr ast.Expr, typ string, consts map[string]ast.Expr) string {
	v := evalConst(expr, consts, map[string]bool{})
	if v == nil || v.Kind() == constant.Unknown {
		return ""
	}
	switch typ {
	case "boolean":
		return fmt.Sprintf("%v", constant.BoolVal(v))
	case "integer":
		if i, ok := constant.Int64Val(constant.ToInt(v)); ok {
			return fmt.Sprintf("%d", i)
		}
	case "number":
		// Float64Val reports ok=false for values not exactly representable as
		// float64 (e.g. 0.1); the returned nearest value is still correct for
		// display, so render it regardless of exactness.
		f, _ := constant.Float64Val(constant.ToFloat(v))
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", f), "0"), ".")
	case "string":
		return constant.StringVal(v)
	}
	return ""
}

// evalConst resolves a constant expression to a go/constant Value, following
// references to named constants collected from the file.
func evalConst(expr ast.Expr, consts map[string]ast.Expr, seen map[string]bool) constant.Value {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return constant.MakeFromLiteral(e.Value, e.Kind, 0)
	case *ast.ParenExpr:
		return evalConst(e.X, consts, seen)
	case *ast.Ident:
		switch e.Name {
		case "true":
			return constant.MakeBool(true)
		case "false":
			return constant.MakeBool(false)
		}
		if seen[e.Name] {
			return nil
		}
		if ref, ok := consts[e.Name]; ok {
			seen[e.Name] = true
			return evalConst(ref, consts, seen)
		}
		return nil
	case *ast.UnaryExpr:
		x := evalConst(e.X, consts, seen)
		if x == nil {
			return nil
		}
		return constant.UnaryOp(e.Op, x, 0)
	case *ast.BinaryExpr:
		x := evalConst(e.X, consts, seen)
		y := evalConst(e.Y, consts, seen)
		if x == nil || y == nil {
			return nil
		}
		if e.Op == token.SHL || e.Op == token.SHR {
			s, ok := constant.Uint64Val(y)
			if !ok {
				return nil
			}
			return constant.Shift(x, e.Op, uint(s))
		}
		return constant.BinaryOp(x, e.Op, y)
	case *ast.CallExpr:
		// Type conversion wrapper such as int64(...); evaluate the argument.
		if len(e.Args) == 1 {
			return evalConst(e.Args[0], consts, seen)
		}
	}
	return nil
}

func stringLit(expr ast.Expr) (string, bool) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v := constant.MakeFromLiteral(bl.Value, bl.Kind, 0)
	return constant.StringVal(v), true
}

// categoryRule maps a name prefix to a display category. Rules are evaluated
// in order, so list the most specific prefixes first. This is the single
// source for how the reference table is sectioned.
type categoryRule struct {
	prefix   string
	category string
}

var categoryRules = []categoryRule{
	{"GATEWAY_GRPC_PORT", "Server & ports"},
	{"GATEWAY_CONNECT_PORT", "Server & ports"},
	{"GATEWAY_METRICS_PORT", "Server & ports"},
	{"GATEWAY_EMAIL_SERVICE_", "Server & ports"},
	{"GATEWAY_NATIVE_OAUTH_", "OAuth"},
	{"GATEWAY_OAUTH_", "OAuth"},
	{"GATEWAY_MICROSOFT_TENANT_ID", "OAuth"},
	{"GATEWAY_JWT_", "JWT & tokens"},
	{"GATEWAY_REFRESH_", "JWT & tokens"},
	{"GATEWAY_REVOCATION_MODE", "JWT & tokens"},
	{"GATEWAY_SESSION_CACHE_", "JWT & tokens"},
	{"GATEWAY_PASSWORDLESS_", "Passwordless email login"},
	{"GATEWAY_PASSWORD_", "Password & lockout"},
	{"GATEWAY_LOGIN_", "Password & lockout"},
	{"GATEWAY_PASSKEY_", "Passkeys / WebAuthn"},
	{"GATEWAY_TOTP_", "TOTP / 2FA"},
	{"GATEWAY_QR_LOGIN_", "QR cross-device login"},
	{"GATEWAY_SMS_", "Phone / SMS verification"},
	{"GATEWAY_PHONE_", "Phone / SMS verification"},
	{"GATEWAY_CAPTCHA_", "CAPTCHA"},
	{"GATEWAY_AGEGATE_", "Age gating (COPPA)"},
	{"GATEWAY_MINOR_", "Age gating (COPPA)"},
	{"GATEWAY_IDV_", "Identity verification"},
	{"GATEWAY_SAML_", "SAML 2.0 IdP"},
	{"GATEWAY_SMTP_", "Email & branding"},
	{"GATEWAY_EMAIL_", "Email & branding"},
	{"GATEWAY_APP_BASE_URL", "Email & branding"},
	{"GATEWAY_TENANT_INVITATION_", "Email & branding"},
	{"GATEWAY_SIGNUP_EMAIL_", "Email & branding"},
	{"GATEWAY_RATE_LIMIT_", "Rate limiting"},
	{"GATEWAY_OTEL_", "OpenTelemetry"},
	{"GATEWAY_SWEEPER_", "Sweeper (GC)"},
	{"GATEWAY_AUDIT_", "Audit"},
	{"GATEWAY_WEBHOOKS_", "Webhooks / eventing"},
	{"GATEWAY_SCIM_", "SCIM provisioning"},
	{"GATEWAY_REPO_DRIVER", "Datastore"},
	{"GATEWAY_POSTGRES_", "Datastore"},
	{"GATEWAY_SQLITE_", "Datastore"},
	{"GATEWAY_DEFAULT_PROJECT", "Projects & tenancy"},
	{"GATEWAY_DEFAULT_TENANT", "Projects & tenancy"},
	{"GATEWAY_ADMIN_API_SECRET", "Projects & tenancy"},
	{"GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP", "Projects & tenancy"},
	{"GATEWAY_PROJECT_SECRETS_KEY", "Projects & tenancy"},
	{"GATEWAY_REQUIRE_VERIFIED_AUTH_DOMAIN", "Projects & tenancy"},
	{"GATEWAY_PROJECT_RESOLUTION_", "Projects & tenancy"},
	{"GATEWAY_DEFAULT_EMAIL_DOMAIN", "Email & branding"},
	{"GATEWAY_PUBLIC_EMAIL_DOMAINS", "Projects & tenancy"},
	{"GATEWAY_COOKIE_", "HTTP, CORS & cookies"},
	{"GATEWAY_ALLOWED_ORIGINS", "HTTP, CORS & cookies"},
	{"GATEWAY_TRUSTED_PROXIES", "HTTP, CORS & cookies"},
	{"GATEWAY_HTTP_MAX_BODY_BYTES", "HTTP, CORS & cookies"},
	{"GATEWAY_AUTH_", "Authentication"},
}

func categoryFor(name string) string {
	for _, r := range categoryRules {
		if strings.HasPrefix(name, r.prefix) {
			return r.category
		}
	}
	return "Other"
}

// slugify turns a display category into a stable URL fragment used as the id of
// its section on the configuration page. It lowercases, maps "&" to "and", and
// collapses every run of non-alphanumerics to a single hyphen (trimming the
// ends), so "JWT & tokens" → "jwt-and-tokens" and "Passkeys / WebAuthn" →
// "passkeys-webauthn". This is the single source of the slug: the generated
// `anchor` field is consumed by configuration.astro and the deep-link
// anti-drift test, neither of which re-derives it.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "&", " and ")
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// requirementPhrases are the substrings (matched case-insensitively, after the
// GATEWAY_* tokens themselves are removed) that mark a boot-time validation
// message as declaring a variable required. Covers both the "requires"/"is
// required" wording and the "is empty"/"must be set" family so a conditionally
// required var like GATEWAY_OTEL_EXPORTER_ENDPOINT (boot fails when empty) is
// not a false negative.
var requirementPhrases = []string{
	"requir", "is empty", "must be set", "must not be empty",
	"cannot be empty", "is missing", "is not set",
}

func mentionsRequirement(residual string) bool {
	for _, p := range requirementPhrases {
		if strings.Contains(residual, p) {
			return true
		}
	}
	return false
}

// conditionalStates are the trailing state words of a "when GATEWAY_X is <state>"
// conditional-requirement antecedent.
var conditionalStates = []string{"set", "unset", "empty", "configured"}

// isConditionalAntecedent reports whether the GATEWAY_* token at loc within val
// is the ANTECEDENT (trigger) of a conditional requirement rather than the
// variable being required. Two antecedent shapes are recognised:
//
//	"GATEWAY_X=..."                      value-equality trigger
//	"... when GATEWAY_X is set"          state trigger (set/unset/empty/configured)
//
// The state form requires the literal "when" immediately before the token so a
// genuine requirement phrased as "GATEWAY_X is empty" (no preceding "when",
// e.g. the OTLP endpoint check) is still correctly marked required.
func isConditionalAntecedent(val string, loc []int) bool {
	start, end := loc[0], loc[1]
	// Value-equality trigger: "GATEWAY_X=...".
	if end < len(val) && val[end] == '=' {
		return true
	}
	// State trigger: "when GATEWAY_X is set/unset/empty/configured".
	before := strings.TrimRight(strings.ToLower(val[:start]), " ")
	if before != "when" && !strings.HasSuffix(before, " when") {
		return false
	}
	after := strings.ToLower(strings.TrimLeft(val[end:], " "))
	rest, ok := strings.CutPrefix(after, "is ")
	if !ok {
		return false
	}
	rest = strings.TrimLeft(rest, " ")
	for _, state := range conditionalStates {
		if rest == state || strings.HasPrefix(rest, state+" ") ||
			strings.HasPrefix(rest, state+".") || strings.HasPrefix(rest, state+",") {
			return true
		}
	}
	return false
}

// scanRequired walks the repository for string literals that mark a GATEWAY_*
// variable as required (a boot-time validation message). This is how
// conditional requirements — e.g. the SQLite path, the Postgres DSN, the
// OTLP endpoint, the SMS/CAPTCHA provider credentials — are discovered from
// code rather than hand-listed.
//
// Two precision rules keep the Required column honest:
//
//   - The requirement phrase is matched on the message with its GATEWAY_*
//     tokens stripped, so a variable whose NAME merely contains "REQUIRE"
//     (e.g. GATEWAY_JWT_REQUIRE_AUD, GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL) is
//     never marked required just by appearing in a literal.
//   - The antecedent (trigger) of a conditional requirement is never marked;
//     only the consequent is. Two antecedent shapes are recognised: the
//     value-equality form "GATEWAY_X=true requires GATEWAY_Y" and the state
//     form "GATEWAY_Y is required when GATEWAY_X is set" (also unset/empty/
//     configured) — in both, GATEWAY_X is the trigger and GATEWAY_Y the
//     consequent, so only GATEWAY_Y is marked required.
func scanRequired(root string) (map[string]bool, error) {
	required := map[string]bool{}
	skipDirs := map[string]bool{
		"vendor": true, "gen": true, "node_modules": true,
		"docs-site": true, ".git": true, ".claude": true, "testdata": true,
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // tolerate unreadable paths
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // skip files we can't parse
		}
		ast.Inspect(f, func(n ast.Node) bool {
			bl, ok := n.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			val := constant.StringVal(constant.MakeFromLiteral(bl.Value, bl.Kind, 0))
			locs := gatewayToken.FindAllStringIndex(val, -1)
			if len(locs) == 0 {
				return true
			}
			residual := strings.ToLower(gatewayToken.ReplaceAllString(val, " "))
			if !mentionsRequirement(residual) {
				return true
			}
			for _, loc := range locs {
				// Skip the antecedent (trigger) of a conditional requirement;
				// only the consequent is the thing actually required.
				if isConditionalAntecedent(val, loc) {
					continue
				}
				required[val[loc[0]:loc[1]]] = true
			}
			return true
		})
		return nil
	})
	return required, err
}

// parseAuditEvents extracts the string value of every EventType constant in
// pkg/audit/logger.go.
func parseAuditEvents(path string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "EventType" {
				continue
			}
			for _, val := range vs.Values {
				if s, ok := stringLit(val); ok && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no EventType constants found in %s", path)
	}
	sort.Strings(out)
	return out, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// repoRoot finds the module root by walking up from the working directory
// until it finds go.mod, so the generator works whether invoked from the
// repo root (make) or from cmd/docsgen (go generate).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from working directory")
		}
		dir = parent
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "docsgen:", err)
	os.Exit(1)
}

const readmeText = `# Generated reference data

These JSON files are generated by ` + "`cmd/docsgen`" + ` from the Go source of
truth. **Do not hand-edit them** — your changes will be overwritten.

- ` + "`config.json`" + ` — every ` + "`GATEWAY_*`" + ` environment variable,
  extracted from ` + "`internal/config/config.go`" + `.
- ` + "`audit-events.json`" + ` — every audit event-type string, extracted from
  the ` + "`EventType`" + ` constants in ` + "`pkg/audit/logger.go`" + `.

Regenerate with:

    make docs-gen      # or: go generate ./...

The docs pages import these files directly, so the reference tables can never
drift from the implementation.
`
