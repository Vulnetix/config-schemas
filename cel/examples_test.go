package cel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// whenContexts names the CEL context each kind's `when` is compiled in. A kind
// that gains a `when` must be listed here, or its examples go unchecked.
var whenContexts = map[string]Context{
	"DetectionRuleFeed": ContextCVE,
	"JailPolicy":        ContextFinding,
	"RiskStrategy":      ContextFinding,
	"Suppression":       ContextFinding,
}

// Every `when` in the published examples must compile in its kind's context.
// v1.1.0 shipped `finding.epss >= 0.1`, which does not type-check: the
// variables are top level, not under a `finding` object.
func TestExampleWhenExpressionsCompile(t *testing.T) {
	files, err := filepath.Glob("../examples/*/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		kind := filepath.Base(filepath.Dir(f))
		ctx, ok := whenContexts[kind]
		if !ok {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		for {
			var doc any
			if err := dec.Decode(&doc); err != nil {
				break
			}
			for _, expr := range whens(doc) {
				checked++
				if _, err := Compile(ctx, expr); err != nil {
					t.Errorf("%s: when %q: %v", f, expr, err)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no `when` found in the examples; the walk is broken")
	}
}

func whens(v any) []string {
	var out []string
	switch n := v.(type) {
	case map[string]any:
		for k, c := range n {
			if s, ok := c.(string); ok && k == "when" {
				out = append(out, s)
				continue
			}
			out = append(out, whens(c)...)
		}
	case []any:
		for _, c := range n {
			out = append(out, whens(c)...)
		}
	}
	return out
}
