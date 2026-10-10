package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Every declared event type is known to Log, which otherwise warns on each
// write of it as an unknown type.
func TestEveryDeclaredEventTypeIsValid(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "logger.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "EventType" {
				continue
			}
			for i, name := range vs.Names {
				lit := vs.Values[i].(*ast.BasicLit)
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				declared++
				if _, ok := validEventTypes[EventType(value)]; !ok {
					t.Errorf("%s (%q) is missing from validEventTypes", name.Name, value)
				}
			}
		}
	}
	if declared != len(validEventTypes) {
		t.Errorf("declared %d event types, validEventTypes holds %d", declared, len(validEventTypes))
	}
}
