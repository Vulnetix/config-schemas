package cel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	configschemas "github.com/vulnetix/config-schemas"
	"gopkg.in/yaml.v3"
)

// Every CEL field in the published examples must compile in the env its
// kind's x-vulnetix annotation names. v1.1.0 shipped `finding.epss >= 0.1`,
// which does not type-check: the variables are top level, not under a
// `finding` object.
func TestExampleExpressionsCompile(t *testing.T) {
	checked := map[Context]int{}
	for _, kind := range configschemas.Kinds() {
		meta, err := configschemas.KindMeta(kind)
		if err != nil {
			t.Fatal(err)
		}
		if len(meta.CELFields) == 0 {
			continue
		}
		files, _ := filepath.Glob(filepath.Join("..", "examples", kind, "*.yaml"))
		for _, f := range files {
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
				for _, field := range meta.CELFields {
					for _, expr := range valuesAt(doc, strings.Split(field.Path, ".")) {
						checked[Context(field.Env)]++
						if _, err := Compile(Context(field.Env), expr); err != nil {
							t.Errorf("%s: %s %q: %v", f, field.Path, expr, err)
						}
					}
				}
			}
		}
	}
	for _, c := range []Context{ContextFinding, ContextPackage, ContextRequest, ContextCVE} {
		if checked[c] == 0 {
			t.Errorf("no %s expression found in the examples; an advanced example should carry one", c)
		}
	}
}

// valuesAt returns the strings at a dotted path, where a segment ending in []
// means every item of that array.
func valuesAt(v any, path []string) []string {
	if len(path) == 0 {
		if s, ok := v.(string); ok {
			return []string{s}
		}
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	seg := path[0]
	if strings.HasSuffix(seg, "[]") {
		list, _ := m[strings.TrimSuffix(seg, "[]")].([]any)
		var out []string
		for _, item := range list {
			out = append(out, valuesAt(item, path[1:])...)
		}
		return out
	}
	return valuesAt(m[seg], path[1:])
}
