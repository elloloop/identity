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
		out = append(out, ConfigVar{
			Name:        name,
			Type:        typ,
			Default:     def,
			Description: descByField[fieldName.Name],
			Category:    categoryFor(name),
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
				desc := summarize(raw)
				for _, nm := range fld.Names {
					if desc != "" {
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
	wsRun        = regexp.MustCompile(`\s+`)
)

// summarize reduces a Go doc comment to a single-sentence description: it
// drops the leading "FieldName " convention, strips inline GATEWAY_* tokens
// and "(default ...)" parentheticals, collapses whitespace, and keeps the
// first sentence.
func summarize(raw string) string {
	s := wsRun.ReplaceAllString(strings.TrimSpace(raw), " ")
	if s == "" {
		return ""
	}
	// First sentence only (terminator followed by space).
	if idx := firstSentenceEnd(s); idx > 0 {
		s = s[:idx]
	}
	s = defaultParen.ReplaceAllString(s, "")
	s = gatewayToken.ReplaceAllString(s, "")
	// Drop a leading exported identifier (Go's "Name is ..." convention).
	if fields := strings.Fields(s); len(fields) > 1 {
		first := fields[0]
		if isExportedIdent(first) && (fields[1] == "is" || fields[1] == "names" ||
			fields[1] == "holds" || fields[1] == "governs" || fields[1] == "gates" ||
			fields[1] == "bounds" || fields[1] == "extends" || fields[1] == "selects" ||
			fields[1] == "enumerates" || fields[1] == "returns") {
			s = strings.Join(fields[1:], " ")
		}
	}
	s = wsRun.ReplaceAllString(strings.TrimSpace(s), " ")
	s = strings.TrimLeft(s, "—-: ")
	return strings.TrimSpace(s)
}

func firstSentenceEnd(s string) int {
	for i := 0; i < len(s)-1; i++ {
		if (s[i] == '.' || s[i] == '!' || s[i] == '?') && s[i+1] == ' ' {
			// Skip common abbreviations that aren't sentence ends.
			return i + 1
		}
	}
	return -1
}

func isExportedIdent(s string) bool {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
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
		if f, ok := constant.Float64Val(constant.ToFloat(v)); ok {
			return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", f), "0"), ".")
		}
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
	{"GATEWAY_SMTP_", "Email & branding"},
	{"GATEWAY_EMAIL_", "Email & branding"},
	{"GATEWAY_APP_BASE_URL", "Email & branding"},
	{"GATEWAY_TENANT_INVITATION_", "Email & branding"},
	{"GATEWAY_SIGNUP_EMAIL_", "Email & branding"},
	{"GATEWAY_RATE_LIMIT_", "Rate limiting"},
	{"GATEWAY_OTEL_", "OpenTelemetry"},
	{"GATEWAY_SWEEPER_", "Sweeper (GC)"},
	{"GATEWAY_AUDIT_", "Audit"},
	{"GATEWAY_REPO_DRIVER", "Datastore"},
	{"GATEWAY_POSTGRES_", "Datastore"},
	{"GATEWAY_SQLITE_", "Datastore"},
	{"GATEWAY_DEFAULT_PROJECT", "Projects & tenancy"},
	{"GATEWAY_DEFAULT_TENANT", "Projects & tenancy"},
	{"GATEWAY_ADMIN_API_SECRET", "Projects & tenancy"},
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

// scanRequired walks the repository for string literals that mark a GATEWAY_*
// variable as required (an error message containing both the word "require"
// and the variable name). This is how conditional requirements — e.g. the
// SQLite path, the Postgres DSN, the SMS/CAPTCHA provider credentials — are
// discovered from code rather than hand-listed.
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
			if !strings.Contains(strings.ToLower(val), "requir") {
				return true
			}
			for _, m := range gatewayToken.FindAllString(val, -1) {
				required[m] = true
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
