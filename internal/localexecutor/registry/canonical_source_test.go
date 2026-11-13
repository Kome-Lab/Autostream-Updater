package registry

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Ownership is a source boundary, independent of the golden behavioral tests.
// It prevents a future local Marshal/strict decoder from silently replacing the
// reviewed shared success path while preserving public signatures.
func TestCanonicalAdapterSourceOwnership(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "validation.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]string{"CanonicalBinding": "ComputeBinding", "ValidateRequest": "ValidateRequest", "DecodeRequest": "DecodeRequest", "validateCommand": "ValidateCommand"}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "strictRequestValue" {
			t.Fatal("local strict Request decoder restored")
		}
		want, needed := required[fn.Name.Name]
		if !needed {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if owner.Name == "json" && selector.Sel.Name == "Marshal" {
				t.Error("local canonical Marshal restored")
			}
			if owner.Name == "evidence" && selector.Sel.Name == want {
				found = true
			}
			return true
		})
		if !found {
			t.Errorf("%s no longer delegates to shared %s", fn.Name.Name, want)
		}
		delete(required, fn.Name.Name)
	}
	if len(required) != 0 {
		t.Fatal("missing public adapter entry", required)
	}
}
