package imaging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestElToritoErrorsKeepLowercaseSentenceStarts(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "el_torito.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "New" && selector.Sel.Name != "Errorf") {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote error string %s: %v", literal.Value, err)
		}
		if strings.HasPrefix(value, "El Torito") || strings.HasPrefix(value, "ISO") {
			t.Errorf("capitalized returned error string remains: %q", value)
		}
		return true
	})
}
