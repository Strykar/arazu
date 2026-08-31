// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// reasonValues reads the vocabulary out of the source rather than repeating it.
// A hand-kept list in the test would pass on the day a reason is added and stop
// testing the thing this file exists for.
func reasonValues(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "case.go", nil, 0)
	if err != nil {
		t.Fatalf("parse case.go: %v", err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
			return true
		}
		name := vs.Names[0].Name
		if len(name) < 7 || name[:6] != "Reason" {
			return true
		}
		lit, ok := vs.Values[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = v
		return true
	})
	if len(out) == 0 {
		t.Fatal("no Reason constants found, so this test asserts nothing")
	}
	return out
}

// Every reason the vocabulary defines has to name the stage answerable for it.
//
// StageUnassigned is not a fallback, it is a report: eval.Matrix counts it as
// "the key expects a reason no stage claims", a corpus defect. So a stage that
// emits a reason StageFor does not know scores its own correct refusal as a
// broken answer key.
func TestEveryReasonNamesTheStageAnswerableForIt(t *testing.T) {
	for name, reason := range reasonValues(t) {
		if got := StageFor(reason); got == StageUnassigned {
			t.Errorf("%s (%q) maps to %s: no stage claims it, so eval reads it as an answer-key defect",
				name, reason, got)
		}
	}
}
