package configschemas

import (
	"encoding/json"
	"os"
	"path/filepath"

	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every kind has examples/<Kind>/minimal.yaml, with only the fields the schema
// requires, and examples/<Kind>/advanced.yaml, which sets every field the
// kind's spec defines (across its documents, so mutually exclusive forms can
// each have one), a CEL field wherever the kind has one, and every secret as a
// valueFrom env, except the fields in examples/<Kind>/unsupported-features.yaml,
// which a server cannot honour yet. The Terraform provider generator and the
// docs build both
// render these two files, so they are held to that shape here.
func TestMinimalAndAdvancedExamples(t *testing.T) {
	v := validator(t)
	for _, k := range Kinds() {
		meta, err := KindMeta(k)
		if err != nil {
			t.Fatal(err)
		}
		root := schemaRoot(t, k)
		for _, name := range []string{"minimal", "advanced"} {
			p := filepath.Join("examples", k, name+".yaml")
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s: missing %s", k, p)
				continue
			}
			docs := decodeFile(t, p)
			raws := rawDocs(t, p)
			for _, d := range docs {
				if d.Kind != k {
					t.Errorf("%s: kind %q", p, d.Kind)
				}
				if err := v.Validate(d); err != nil {
					t.Errorf("%s: %v", p, err)
				}
			}
			if name == "minimal" {
				if len(raws) != 1 {
					t.Errorf("%s: %d documents, want 1", p, len(raws))
				}
				for _, doc := range raws {
					checkMinimal(t, p, root, resolveLocal(root, propOf(root, "spec")), docField(doc, "spec"), "spec")
					if md, ok := docField(doc, "metadata").(map[string]any); ok && len(md) != 1 {
						t.Errorf("%s: metadata has %d fields, want only name", p, len(md))
					}
				}
				continue
			}
			want := map[string]bool{}
			specPaths(root, resolveLocal(root, propOf(root, "spec")), "spec", want, map[string]bool{})
			have := map[string]bool{}
			for _, doc := range raws {
				docPaths(docField(doc, "spec"), "spec", have)
			}
			// A field the schema accepts and a server cannot honour yet is
			// kept out of advanced.yaml, which is applied, and shown in
			// unsupported-features.yaml, which is only validated. Together
			// the two still set every field.
			if up := filepath.Join("examples", k, "unsupported-features.yaml"); fileExists(up) {
				for _, doc := range rawDocs(t, up) {
					docPaths(docField(doc, "spec"), "spec", have)
				}
			}
			var missing []string
			for p := range want {
				if !have[p] {
					missing = append(missing, p)
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("%s: does not set %s", p, strings.Join(missing, ", "))
			}
			for _, s := range meta.Secrets {
				found := false
				for _, doc := range raws {
					for _, val := range valuesAtPath(doc, strings.Split(s, ".")) {
						found = true
						m, ok := val.(map[string]any)
						if _, env := m["env"]; !ok || !env {
							t.Errorf("%s: %s must be a valueFrom env, got %v", p, s, val)
						}
					}
				}
				if !found {
					t.Errorf("%s: does not set the secret %s", p, s)
				}
			}
		}
	}
}

func schemaRoot(t *testing.T, kind string) map[string]any {
	t.Helper()
	b, _ := Schema(kind)
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func rawDocs(t *testing.T, p string) []any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	var out []any
	for {
		var d any
		if err := dec.Decode(&d); err != nil {
			break
		}
		if d != nil {
			out = append(out, d)
		}
	}
	return out
}

func propOf(n any, key string) any {
	m, _ := n.(map[string]any)
	props, _ := m["properties"].(map[string]any)
	return props[key]
}

func docField(doc any, key string) any {
	m, _ := doc.(map[string]any)
	return m[key]
}

var commonRoot = func() map[string]any {
	b, err := files.ReadFile("schemas/common.schema.json")
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}()

// resolveLocal follows #/ refs within the kind's own schema and refs into
// common.schema.json, except valueFrom: a secret is a leaf, set as an env.
// A ref inside a common definition resolves against common.
func resolveLocal(root map[string]any, n any) any {
	for i := 0; i < 16; i++ {
		m, ok := n.(map[string]any)
		if !ok {
			return n
		}
		ref, ok := m["$ref"].(string)
		switch {
		case !ok, ref == "common.schema.json#/$defs/valueFrom":
			return n
		case strings.HasPrefix(ref, "common.schema.json#/"):
			root = commonRoot
			n = resolve(root, strings.TrimPrefix(ref, "common.schema.json"))
		case strings.HasPrefix(ref, "#/"):
			n = resolve(root, ref)
		default:
			return n
		}
	}
	return n
}

// branches are the subschemas whose properties also describe the object.
func branches(root map[string]any, n any) []map[string]any {
	m, ok := resolveLocal(root, n).(map[string]any)
	if !ok {
		return nil
	}
	out := []map[string]any{m}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		if list, ok := m[k].([]any); ok {
			for _, c := range list {
				out = append(out, branches(root, c)...)
			}
		}
	}
	for _, k := range []string{"then", "else"} {
		if c, ok := m[k]; ok {
			out = append(out, branches(root, c)...)
		}
	}
	return out
}

// specPaths collects every property path the schema defines under spec. It
// does not descend into maps keyed by free names, or into common refs.
func specPaths(root map[string]any, n any, path string, out, seen map[string]bool) {
	if seen[path] && path != "spec" {
		return
	}
	for _, b := range branches(root, n) {
		if props, ok := b["properties"].(map[string]any); ok {
			for k, c := range props {
				if bc, ok := c.(bool); ok && !bc {
					continue
				}
				if cm, ok := c.(map[string]any); ok && len(cm) == 0 {
					continue
				}
				cp := path + "." + k
				// A property a branch only narrows (it has no type, ref or
				// description of its own) is defined elsewhere.
				out[cp] = true
				specPaths(root, c, cp, out, seen)
			}
		}
		if items, ok := b["items"]; ok {
			seen[path] = true
			specPaths(root, items, path+"[]", out, seen)
		}
	}
	seen[path] = true
}

func docPaths(v any, path string, out map[string]bool) {
	switch n := v.(type) {
	case map[string]any:
		for k, c := range n {
			cp := path + "." + k
			out[cp] = true
			docPaths(c, cp, out)
		}
	case []any:
		for _, c := range n {
			docPaths(c, path+"[]", out)
		}
	}
}

// checkMinimal fails a field the schema does not require, recursively.
func checkMinimal(t *testing.T, file string, root map[string]any, schema, val any, path string) {
	t.Helper()
	switch n := val.(type) {
	case map[string]any:
		required := map[string]bool{}
		bs := branches(root, schema)
		for _, b := range bs {
			if r, ok := b["required"].([]any); ok {
				for _, x := range r {
					required[x.(string)] = true
				}
			}
		}
		// An object that must have exactly one of its properties requires
		// whichever one the example chose.
		for _, b := range bs {
			if mp, ok := b["minProperties"].(float64); ok && mp >= 1 && len(n) == 1 {
				for k := range n {
					required[k] = true
				}
			}
		}
		for k, c := range n {
			if !required[k] {
				t.Errorf("%s: %s.%s is not required, so it does not belong in the minimal example", file, path, k)
				continue
			}
			var cs any
			for _, b := range bs {
				if props, ok := b["properties"].(map[string]any); ok && props[k] != nil {
					if _, isBool := props[k].(bool); !isBool {
						cs = props[k]
						break
					}
				}
			}
			checkMinimal(t, file, root, cs, c, path+"."+k)
		}
	case []any:
		m, _ := resolveLocal(root, schema).(map[string]any)
		for _, c := range n {
			checkMinimal(t, file, root, m["items"], c, path+"[]")
		}
	}
}

func valuesAtPath(v any, path []string) []any {
	if len(path) == 0 {
		return []any{v}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	seg := path[0]
	if strings.HasSuffix(seg, "[]") {
		list, _ := m[strings.TrimSuffix(seg, "[]")].([]any)
		var out []any
		for _, item := range list {
			out = append(out, valuesAtPath(item, path[1:])...)
		}
		return out
	}
	c, ok := m[seg]
	if !ok {
		return nil
	}
	return valuesAtPath(c, path[1:])
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
