// This test enforces that every service.Repository decorator rebinds as a
// decorator:
//
//	A shipped struct that embeds service.Repository declares its own
//	WithProject, which binds the inner Repository and re-wraps it.
//
// Why this matters: every project-scoped read and write goes through
// Repository.WithProject. A decorator that embeds the interface without
// declaring WithProject gets the inner one promoted, so the repository a
// request is scoped to is the bare inner one — whatever the decorator adds
// (the session-cache invalidation on revoke, for one) silently stops applying
// on every project-scoped call. The compiler cannot see this: the promoted
// method satisfies the interface.
//
// It is a plain `go test` (no build tag) so it runs in the default
// `go test ./...` set and in the dedicated arch CI job.
package arch_test

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

func TestRepositoryDecoratorsRebind(t *testing.T) {
	root := repoRoot(t)

	var violations []string
	scannedDirs := 0
	for _, sr := range shippedRoots {
		err := filepath.WalkDir(filepath.Join(root, sr), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			scannedDirs++
			violations = append(violations, decoratorsMissingWithProject(t, root, path)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %q: %v", sr, err)
		}
	}
	if scannedDirs == 0 {
		t.Fatal("scanned zero shipped directories; the walker is misconfigured")
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d Repository decorator(s) embed service.Repository without declaring WithProject — "+
			"declare it, binding the inner Repository and re-wrapping it:\n  - %s",
			len(violations), strings.Join(violations, "\n  - "))
	}
}

// decoratorsMissingWithProject parses the shipped (non-test) files of one
// directory and returns every struct type that embeds service.Repository but
// has no WithProject method of its own. A directory holds one shipped package,
// so types and methods are matched across all of its files.
func decoratorsMissingWithProject(t *testing.T, root, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	decorators := map[string]token.Pos{}
	rebinds := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", filepath.Join(dir, name), err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if st, ok := ts.Type.(*ast.StructType); ok && embedsRepository(st, file.Name.Name) {
						decorators[ts.Name.Name] = ts.Pos()
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && d.Name.Name == "WithProject" {
					rebinds[receiverTypeName(d.Recv.List[0].Type)] = true
				}
			}
		}
	}

	var out []string
	for name, pos := range decorators {
		if !rebinds[name] {
			rel, _ := filepath.Rel(root, fset.Position(pos).Filename)
			out = append(out, filepath.ToSlash(rel)+": "+name)
		}
	}
	return out
}

// embedsRepository reports whether st has an embedded service.Repository
// field (a bare Repository inside package service itself).
func embedsRepository(st *ast.StructType, pkgName string) bool {
	for _, field := range st.Fields.List {
		if len(field.Names) != 0 {
			continue
		}
		switch typ := field.Type.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := typ.X.(*ast.Ident); ok && pkg.Name == "service" && typ.Sel.Name == "Repository" {
				return true
			}
		case *ast.Ident:
			if pkgName == "service" && typ.Name == "Repository" {
				return true
			}
		}
	}
	return false
}

// receiverTypeName strips the pointer from a method receiver's type.
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}
