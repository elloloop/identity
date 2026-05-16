package entdb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestDispatchCompleteness is a static-check guard against the
// IDENTITY-side bug that broke real-entdb IDV flows (#85): a proto
// type was used in `repo.go` (passed to r.client.get / query /
// delete) but the production sdkScope's three typed dispatch
// switches in client.go didn't include it, so writes worked but the
// follow-up read fell through to "unsupported message type".
//
// The memory-backed conformance suite uses proto reflection and so
// cannot catch this regression — it surfaces only against a real
// EntDB. The cost of the gap is a recurring nightly failure; the
// cost of detecting it here is one parse-time scan over two files.
//
// What this test asserts:
//
//	For every schemapb.X referenced as `r.client.{get,query,delete}(...&schemapb.X{}, ...)`
//	or `r.client.{get,query,delete}(..., dst, ...)` where dst is typed as *schemapb.X,
//	the production sdkScope.{get, query, delete} switches in client.go
//	must each have a `case *schemapb.X:` arm.
//
// Concretely the test extracts:
//   - The set of *schemapb.X type names appearing as the third
//     argument to r.client.get / r.client.query / r.client.delete
//     in internal/repo/entdb/repo.go.
//   - The set of *schemapb.X case-arm types appearing inside each of
//     the three switch statements in internal/repo/entdb/client.go's
//     sdkScope.get / sdkScope.query / sdkScope.delete methods.
//
// Then for each repo-side type it confirms each switch has the case.
// A missing case is the exact regression #85 fixed.
func TestDispatchCompleteness(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	repoGoPath := filepath.Join(root, "internal", "repo", "entdb", "repo.go")
	sweeperGoPath := filepath.Join(root, "internal", "repo", "entdb", "sweeper.go")
	clientGoPath := filepath.Join(root, "internal", "repo", "entdb", "client.go")

	usedTypes, err := schemapbTypesUsedInRepo(repoGoPath)
	if err != nil {
		t.Fatalf("scan repo.go: %v", err)
	}
	if len(usedTypes) == 0 {
		t.Fatalf("repo.go scan found no schemapb types — scanner is broken")
	}

	dispatched, err := dispatchedTypesByMethod(clientGoPath)
	if err != nil {
		t.Fatalf("scan client.go: %v", err)
	}
	for _, m := range []string{"get", "query", "delete"} {
		if len(dispatched[m]) == 0 {
			t.Fatalf("client.go: sdkScope.%s has no proto-type cases — scanner is broken", m)
		}
	}

	for _, m := range []string{"get", "query", "delete"} {
		missing := []string{}
		for tn := range usedTypes {
			if !dispatched[m][tn] {
				missing = append(missing, tn)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf(
				"sdkScope.%s switch is missing case for: %s\n"+
					"every schemapb type passed to r.client.%s in repo.go must be in client.go's dispatch table",
				m, strings.Join(missing, ", "), m,
			)
		}
	}

	// Sweeper dispatch: every schemapb type passed to
	// r.client.deleteExpired in sweeper.go must appear as a case in
	// client.go's expiresAtSweepSpec.
	sweepTypes, err := schemapbTypesPassedToDeleteExpired(sweeperGoPath)
	if err != nil {
		t.Fatalf("scan sweeper.go: %v", err)
	}
	if len(sweepTypes) == 0 {
		t.Fatalf("sweeper.go scan found no schemapb types — scanner is broken")
	}
	sweepDispatched, err := typesInSweepSpec(clientGoPath)
	if err != nil {
		t.Fatalf("scan expiresAtSweepSpec: %v", err)
	}
	if len(sweepDispatched) == 0 {
		t.Fatalf("client.go: expiresAtSweepSpec has no proto-type cases — scanner is broken")
	}
	missing := []string{}
	for tn := range sweepTypes {
		if !sweepDispatched[tn] {
			missing = append(missing, tn)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf(
			"expiresAtSweepSpec is missing case for: %s\n"+
				"every schemapb type passed to r.client.deleteExpired in sweeper.go must be in client.go's expiresAtSweepSpec",
			strings.Join(missing, ", "),
		)
	}
}

// schemapbTypesUsedInRepo parses repo.go and returns the set of
// *schemapb.X type names passed as arguments to r.client.get /
// r.client.query / r.client.delete. The set is keyed by short type
// name (e.g. "User", "IdentityVerificationRecord").
//
// Recognised argument shapes (mirrors how repo.go actually calls):
//
//	r.client.get(ctx, actor, &schemapb.X{}, id)        — composite-lit
//	r.client.get(ctx, actor, dst, id) where dst := &schemapb.X{}
//	r.client.delete(ctx, actor, &schemapb.X{}, nodeID) — composite-lit
//	r.client.query(ctx, actor, &schemapb.X{}, filter)  — composite-lit
//
// We trust the local-variable typed shape because it's how findByKey
// and a few other sites express the witness; the scanner walks the
// function bodies that contain the call to resolve `dst` back to its
// declared composite literal.
func schemapbTypesUsedInRepo(path string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}

	walkFunc := func(fn *ast.FuncDecl) {
		if fn.Body == nil {
			return
		}
		// First pass: collect local variables initialised to &schemapb.X{}.
		locals := map[string]string{} // var name → schemapb type
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				if len(v.Lhs) == 1 && len(v.Rhs) == 1 {
					if id, ok := v.Lhs[0].(*ast.Ident); ok {
						if name := schemapbCompositeTypeName(v.Rhs[0]); name != "" {
							locals[id.Name] = name
						}
					}
				}
			case *ast.ValueSpec:
				if len(v.Names) == 1 && len(v.Values) == 1 {
					if name := schemapbCompositeTypeName(v.Values[0]); name != "" {
						locals[v.Names[0].Name] = name
					}
				}
			}
			return true
		})
		// Second pass: find calls to r.client.{get,query,delete} and
		// resolve the 3rd argument (the witness or dst) back to a
		// schemapb type.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Match r.client.{get,query,delete}.
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel == nil || inner.Sel.Name != "client" {
				return true
			}
			switch sel.Sel.Name {
			case "get", "query", "delete":
				// signature: (ctx, actor, witness_or_dst, ...)
			default:
				return true
			}
			if len(call.Args) < 3 {
				return true
			}
			arg := call.Args[2]
			if name := schemapbCompositeTypeName(arg); name != "" {
				out[name] = true
				return true
			}
			if id, ok := arg.(*ast.Ident); ok {
				if name, ok := locals[id.Name]; ok {
					out[name] = true
				}
			}
			return true
		})
	}

	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			walkFunc(fn)
		}
	}
	return out, nil
}

// schemapbCompositeTypeName returns "X" if e is a composite literal
// of the form `&schemapb.X{...}`, or empty string otherwise.
func schemapbCompositeTypeName(e ast.Expr) string {
	unary, ok := e.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return ""
	}
	clit, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	sel, ok := clit.Type.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "schemapb" {
		return ""
	}
	return sel.Sel.Name
}

// dispatchedTypesByMethod parses client.go and returns, for each of
// sdkScope.{get, query, delete}, the set of schemapb.X type names
// appearing as `case *schemapb.X:` arms in the method's type switch.
func dispatchedTypesByMethod(path string) (map[string]map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{
		"get":    {},
		"query":  {},
		"delete": {},
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		recv := fn.Recv.List[0].Type
		star, ok := recv.(*ast.StarExpr)
		if !ok {
			continue
		}
		id, ok := star.X.(*ast.Ident)
		if !ok || id.Name != "sdkScope" {
			continue
		}
		methodName := fn.Name.Name
		if _, ok := out[methodName]; !ok {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range cc.List {
				star, ok := expr.(*ast.StarExpr)
				if !ok {
					continue
				}
				sel, ok := star.X.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "schemapb" {
					continue
				}
				out[methodName][sel.Sel.Name] = true
			}
			return true
		})
	}
	return out, nil
}

// schemapbTypesPassedToDeleteExpired parses sweeper.go and returns
// the set of *schemapb.X type names appearing as the third argument
// to r.client.deleteExpired calls.
func schemapbTypesPassedToDeleteExpired(path string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "deleteExpired" {
				return true
			}
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel == nil || inner.Sel.Name != "client" {
				return true
			}
			if len(call.Args) < 3 {
				return true
			}
			if name := schemapbCompositeTypeName(call.Args[2]); name != "" {
				out[name] = true
			}
			return true
		})
	}
	return out, nil
}

// typesInSweepSpec returns the set of schemapb.X type names appearing
// as `case *schemapb.X:` arms inside the top-level expiresAtSweepSpec
// function in client.go.
func typesInSweepSpec(path string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil || fn.Name.Name != "expiresAtSweepSpec" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range cc.List {
				star, ok := expr.(*ast.StarExpr)
				if !ok {
					continue
				}
				sel, ok := star.X.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "schemapb" {
					continue
				}
				out[sel.Sel.Name] = true
			}
			return true
		})
	}
	return out, nil
}

// repoRoot walks up from the test working directory until it finds
// the project go.mod.
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
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
