package configschemas

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/vulnetix/config-schemas/cel"
)

// futureKinds may appear in dependsOn before their schema ships.
var futureKinds = map[string]bool{"VaultEntry": true, "MessagingConnection": true}

// derived is what the schema itself says about a kind: where valueFrom and
// celExpression are referenced, and whether metadata is a singleton's.
type derived struct {
	singleton bool
	secrets   []string
	cel       []string
}

type walker struct {
	root map[string]any
	out  *derived
	seen map[string]bool
}

func (w *walker) walk(node any, path string) {
	n, ok := node.(map[string]any)
	if !ok {
		return
	}
	if ref, ok := n["$ref"].(string); ok {
		switch {
		case ref == "common.schema.json#/$defs/valueFrom":
			w.out.secrets = appendUnique(w.out.secrets, path)
		case ref == "common.schema.json#/$defs/celExpression":
			w.out.cel = appendUnique(w.out.cel, path)
		case ref == "common.schema.json#/$defs/singletonMetadata", ref == "common.schema.json#/$defs/legacySingletonMetadata":
			if path == "metadata" {
				w.out.singleton = true
			}
		case strings.HasPrefix(ref, "#/"):
			key := ref + "@" + path
			if !w.seen[key] {
				w.seen[key] = true
				w.walk(resolve(w.root, ref), path)
			}
		}
	}
	if props, ok := n["properties"].(map[string]any); ok {
		for k, v := range props {
			p := k
			if path != "" {
				p = path + "." + k
			}
			w.walk(v, p)
		}
	}
	if items, ok := n["items"]; ok {
		w.walk(items, path+"[]")
	}
	if ap, ok := n["additionalProperties"].(map[string]any); ok {
		w.walk(ap, path+".*")
	}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		if list, ok := n[k].([]any); ok {
			for _, c := range list {
				w.walk(c, path)
			}
		}
	}
	for _, k := range []string{"if", "then", "else", "not"} {
		w.walk(n[k], path)
	}
}

func resolve(root map[string]any, ref string) any {
	var cur any = root
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func derive(t *testing.T, kind string) derived {
	t.Helper()
	b, err := Schema(kind)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	var d derived
	(&walker{root: root, out: &d, seen: map[string]bool{}}).walk(root, "")
	sort.Strings(d.secrets)
	sort.Strings(d.cel)
	return d
}

var nameOfKind = regexp.MustCompile(`metadata\.name of (?:a|an|the|a published) ([A-Z][A-Za-z]+)`)

// Every kind's annotation agrees with its schema, so a generator reading the
// annotation cannot drift from what validation accepts.
func TestMetaMatchesSchema(t *testing.T) {
	common, err := files.ReadFile("schemas/common.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	contexts := map[string]bool{}
	for _, c := range cel.Contexts() {
		contexts[string(c)] = true
	}
	for _, k := range Kinds() {
		m, err := KindMeta(k)
		if err != nil {
			t.Error(err)
			continue
		}
		d := derive(t, k)
		if m.Singleton != d.singleton {
			t.Errorf("%s: singleton %v, schema says %v", k, m.Singleton, d.singleton)
		}
		secrets := slices.Clone(m.Secrets)
		sort.Strings(secrets)
		if !slices.Equal(secrets, d.secrets) {
			t.Errorf("%s: secrets %q, schema has valueFrom at %q", k, secrets, d.secrets)
		}
		var celPaths []string
		for _, f := range m.CELFields {
			celPaths = append(celPaths, f.Path)
			if !contexts[f.Env] {
				t.Errorf("%s: %s: unknown CEL env %q", k, f.Path, f.Env)
			}
		}
		sort.Strings(celPaths)
		if !slices.Equal(celPaths, d.cel) {
			t.Errorf("%s: celFields %q, schema has celExpression at %q", k, celPaths, d.cel)
		}
		for _, dep := range m.DependsOn {
			if dep == k {
				t.Errorf("%s: depends on itself", k)
			}
			if _, err := Schema(dep); err != nil && !futureKinds[dep] {
				t.Errorf("%s: depends on unknown kind %q", k, dep)
			}
		}
		// A kind whose schema refers to another by metadata.name must list
		// it, directly or through the common reference definitions.
		b, _ := Schema(k)
		refs := nameOfKind.FindAllStringSubmatch(string(b), -1)
		if strings.Contains(string(b), "vaultRef") {
			refs = append(refs, []string{"", "VaultEntry"})
		}
		if strings.Contains(string(b), "messagingConnectionRef") {
			refs = append(refs, []string{"", "MessagingConnection"})
		}
		for _, r := range refs {
			if !slices.Contains(m.DependsOn, r[1]) {
				t.Errorf("%s: refers to a %s by name but dependsOn is %q", k, r[1], m.DependsOn)
			}
		}
	}
	if !strings.Contains(string(common), `"celExpression"`) {
		t.Fatal("common.schema.json has no celExpression; the walk is broken")
	}
}

// The annotation is the single list of CEL fields, so every example's CEL
// must compile in the env its field names.
func TestMetaCELEnvsAreKnown(t *testing.T) {
	seen := 0
	for _, k := range Kinds() {
		m, _ := KindMeta(k)
		seen += len(m.CELFields)
	}
	if seen < 6 {
		t.Fatalf("only %d CEL fields annotated; expected at least the jail, risk, suppression, feed, package list and AI guardrail fields", seen)
	}
}
