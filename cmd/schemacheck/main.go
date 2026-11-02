// Command schemacheck builds a release of the config schemas and checks that a
// release does not break documents the previous release accepted.
//
//	schemacheck release --version v1.2.0 --out dist
//	schemacheck compat --base old/schemas --version v1.2.0 --previous v1.1.0
//
// release writes every schema with its $id set to the URL it is published at,
// an index of kinds, one bundle schema for editors, and SHA256SUMS.
//
// compat compares the schemas in this tree against a previous release's and
// fails when a change could reject a document the previous release accepted,
// unless the new version is a major bump.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	configschemas "github.com/vulnetix/config-schemas"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "release":
		err = release(os.Args[2:])
	case "compat":
		err = compat(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemacheck:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: schemacheck release --version vX.Y.Z --out DIR | compat --base DIR --version vX.Y.Z --previous vA.B.C")
	os.Exit(2)
}

var semver = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

func major(v string) (int, error) {
	m := semver.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("%q is not a release version (vMAJOR.MINOR.PATCH)", v)
	}
	return strconv.Atoi(m[1])
}

func release(args []string) error {
	fl := flag.NewFlagSet("release", flag.ExitOnError)
	version := fl.String("version", "", "release tag, vMAJOR.MINOR.PATCH")
	out := fl.String("out", "dist", "output directory")
	_ = fl.Parse(args)
	if _, err := major(*version); err != nil {
		return err
	}
	// Prove the tree is valid before publishing any of it.
	if _, err := configschemas.NewValidator(); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	dev := configschemas.BaseURL + "/" + configschemas.DevVersion + "/"
	rel := configschemas.BaseURL + "/" + *version + "/"
	entries, err := fs.ReadDir(configschemas.FS(), "schemas")
	if err != nil {
		return err
	}
	written := []string{}
	for _, e := range entries {
		b, err := fs.ReadFile(configschemas.FS(), "schemas/"+e.Name())
		if err != nil {
			return err
		}
		b = []byte(strings.ReplaceAll(string(b), dev, rel))
		if err := os.WriteFile(filepath.Join(*out, e.Name()), b, 0o644); err != nil {
			return err
		}
		written = append(written, e.Name())
	}

	type kindEntry struct {
		Kind   string `json:"kind"`
		File   string `json:"file"`
		Schema string `json:"schema"`
	}
	idx := struct {
		Version    string      `json:"version"`
		APIVersion string      `json:"apiVersion"`
		Kinds      []kindEntry `json:"kinds"`
	}{Version: *version, APIVersion: configschemas.APIVersion}
	var oneOf []map[string]any
	for _, k := range configschemas.Kinds() {
		f := k + ".schema.json"
		idx.Kinds = append(idx.Kinds, kindEntry{Kind: k, File: f, Schema: rel + f})
		oneOf = append(oneOf, map[string]any{
			"if":   map[string]any{"properties": map[string]any{"kind": map[string]any{"const": k}}, "required": []string{"kind"}},
			"then": map[string]any{"$ref": rel + f},
		})
	}
	if err := writeJSON(filepath.Join(*out, "index.json"), idx); err != nil {
		return err
	}
	written = append(written, "index.json")

	// One schema an editor can bind to every file in .vulnetix/config/: it
	// dispatches on kind, so each document is checked against its own kind.
	bundle := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         rel + "vulnetix-config.schema.json",
		"title":       "Vulnetix config document",
		"description": "Any Vulnetix config document. Dispatches on kind to that kind's schema.",
		"type":        "object",
		"required":    []string{"apiVersion", "kind"},
		"properties":  map[string]any{"kind": map[string]any{"enum": configschemas.Kinds()}},
		"allOf":       oneOf,
	}
	if err := writeJSON(filepath.Join(*out, "vulnetix-config.schema.json"), bundle); err != nil {
		return err
	}
	written = append(written, "vulnetix-config.schema.json")

	sort.Strings(written)
	var sums strings.Builder
	for _, f := range written {
		b, err := os.ReadFile(filepath.Join(*out, f))
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), f)
	}
	if err := os.WriteFile(filepath.Join(*out, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("release %s: %d files in %s\n", *version, len(written)+1, *out)
	return nil
}

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}

func compat(args []string) error {
	fl := flag.NewFlagSet("compat", flag.ExitOnError)
	base := fl.String("base", "", "directory holding the previous release's *.schema.json")
	version := fl.String("version", "", "the version being released")
	previous := fl.String("previous", "", "the previous release's version")
	_ = fl.Parse(args)
	newMajor, err := major(*version)
	if err != nil {
		return err
	}
	oldMajor, err := major(*previous)
	if err != nil {
		return err
	}
	var breaks []string
	oldFiles, _ := filepath.Glob(filepath.Join(*base, "*.schema.json"))
	for _, of := range oldFiles {
		name := filepath.Base(of)
		if name == "vulnetix-config.schema.json" {
			continue // generated by release, not a source schema
		}
		ob, err := os.ReadFile(of)
		if err != nil {
			return err
		}
		nb, err := fs.ReadFile(configschemas.FS(), "schemas/"+name)
		if err != nil {
			breaks = append(breaks, name+": removed")
			continue
		}
		var o, n any
		if err := json.Unmarshal(ob, &o); err != nil {
			return fmt.Errorf("%s: %w", of, err)
		}
		if err := json.Unmarshal(nb, &n); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		breaks = append(breaks, Diff(name, o, n)...)
	}
	if len(breaks) == 0 {
		fmt.Printf("compat: %s accepts everything %s accepted\n", *version, *previous)
		return nil
	}
	for _, b := range breaks {
		fmt.Println("breaking:", b)
	}
	if newMajor > oldMajor {
		fmt.Printf("compat: %d breaking changes, allowed by the major bump %s -> %s\n", len(breaks), *previous, *version)
		return nil
	}
	return fmt.Errorf("%d breaking changes need a major version, not %s after %s", len(breaks), *version, *previous)
}

// Diff lists the changes from old to new that could make new reject a document
// old accepted. It is conservative where it is simple to be: a change it cannot
// classify in a keyword it checks counts as breaking.
func Diff(at string, old, cur any) []string {
	o, ok1 := old.(map[string]any)
	n, ok2 := cur.(map[string]any)
	if !ok1 || !ok2 {
		return nil
	}
	var out []string
	add := func(format string, a ...any) { out = append(out, at+": "+fmt.Sprintf(format, a...)) }

	if ot, nt := typeSet(o["type"]), typeSet(n["type"]); ot != nil {
		if nt == nil {
			// A type constraint removed only widens.
		} else {
			for t := range ot {
				if !nt[t] {
					add("type %s no longer allowed", t)
				}
			}
		}
	} else if nt := typeSet(n["type"]); nt != nil {
		add("type constraint added")
	}
	if oc, ok := o["const"]; ok {
		if nc, ok := n["const"]; ok && fmt.Sprint(oc) != fmt.Sprint(nc) {
			add("const %v became %v", oc, nc)
		}
	} else if _, ok := n["const"]; ok {
		add("const added")
	}
	if oe, ok := o["enum"].([]any); ok {
		ne, _ := n["enum"].([]any)
		have := map[string]bool{}
		for _, v := range ne {
			have[fmt.Sprint(v)] = true
		}
		if n["enum"] != nil {
			for _, v := range oe {
				if !have[fmt.Sprint(v)] {
					add("enum value %v removed", v)
				}
			}
		}
	} else if _, ok := n["enum"]; ok {
		add("enum added")
	}
	oreq, nreq := strSet(o["required"]), strSet(n["required"])
	for r := range nreq {
		if !oreq[r] {
			add("property %s became required", r)
		}
	}
	if ap, ok := n["additionalProperties"].(bool); ok && !ap {
		if oap, ok := o["additionalProperties"].(bool); !ok || oap {
			add("additionalProperties closed")
		}
	}
	for _, k := range []string{"minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties"} {
		if ov, nv := num(o[k]), num(n[k]); nv != nil && (ov == nil || *nv > *ov) {
			add("%s raised", k)
		}
	}
	for _, k := range []string{"maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties"} {
		if ov, nv := num(o[k]), num(n[k]); nv != nil && (ov == nil || *nv < *ov) {
			add("%s lowered", k)
		}
	}
	if op, np := o["pattern"], n["pattern"]; np != nil && fmt.Sprint(op) != fmt.Sprint(np) {
		add("pattern changed")
	}
	if or, nr := o["$ref"], n["$ref"]; or != nil && fmt.Sprint(stripVersion(or)) != fmt.Sprint(stripVersion(nr)) {
		add("$ref changed from %v to %v", or, nr)
	}

	for _, kw := range []string{"properties", "$defs"} {
		op, _ := o[kw].(map[string]any)
		np, _ := n[kw].(map[string]any)
		for k, ov := range op {
			nv, ok := np[k]
			if !ok {
				if kw == "properties" && n["additionalProperties"] == false {
					add("property %s removed", k)
				} else if kw == "$defs" {
					add("definition %s removed", k)
				}
				continue
			}
			out = append(out, Diff(at+"/"+kw+"/"+k, ov, nv)...)
		}
	}
	for _, kw := range []string{"items", "additionalProperties"} {
		if ov, ok := o[kw].(map[string]any); ok {
			out = append(out, Diff(at+"/"+kw, ov, n[kw])...)
		}
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
		oa, _ := o[kw].([]any)
		na, _ := n[kw].([]any)
		if len(oa) != len(na) && na != nil {
			// An allOf condition gated on a value the old schema refused
			// constrains only documents the old schema refused, so it can be
			// added in a minor release. Matching is by content, so the new
			// conditions may go anywhere in the list.
			if kw == "allOf" && len(na) > len(oa) && onlyGatedAdditions(o, oa, na) {
				continue
			}
			add("%s changed length", kw)
			continue
		}
		for i := range oa {
			if i < len(na) {
				out = append(out, Diff(fmt.Sprintf("%s/%s/%d", at, kw, i), oa[i], na[i])...)
			}
		}
	}
	return out
}

var versionInURL = regexp.MustCompile(`/v\d+\.\d+\.\d+(-dev)?/`)

func stripVersion(v any) any {
	if s, ok := v.(string); ok {
		return versionInURL.ReplaceAllString(s, "/")
	}
	return v
}

func typeSet(v any) map[string]bool {
	switch t := v.(type) {
	case string:
		return map[string]bool{t: true}
	case []any:
		m := map[string]bool{}
		for _, x := range t {
			m[fmt.Sprint(x)] = true
		}
		return m
	}
	return nil
}

func strSet(v any) map[string]bool {
	m := map[string]bool{}
	if a, ok := v.([]any); ok {
		for _, x := range a {
			m[fmt.Sprint(x)] = true
		}
	}
	return m
}

func num(v any) *float64 {
	if f, ok := v.(float64); ok {
		return &f
	}
	return nil
}

// onlyGatedAdditions reports whether na is oa plus conditions of the form
// {"if": {"properties": {"p": {"const": v}}}, "then": ...} where v is a value
// the old schema's enum for p did not allow. Every old item must still be
// present unchanged.
func onlyGatedAdditions(old map[string]any, oa, na []any) bool {
	key := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	have := map[string]int{}
	for _, v := range na {
		have[key(v)]++
	}
	for _, v := range oa {
		if have[key(v)] == 0 {
			return false
		}
		have[key(v)]--
	}
	oldProps, _ := old["properties"].(map[string]any)
	for _, v := range na {
		k := key(v)
		if have[k] == 0 {
			continue
		}
		have[k]--
		m, _ := v.(map[string]any)
		cond, _ := m["if"].(map[string]any)
		props, _ := cond["properties"].(map[string]any)
		if len(props) != 1 {
			return false
		}
		for p, c := range props {
			cm, _ := c.(map[string]any)
			val, ok := cm["const"]
			if !ok {
				return false
			}
			op, _ := oldProps[p].(map[string]any)
			enum, ok := op["enum"].([]any)
			if !ok {
				return false
			}
			for _, e := range enum {
				if fmt.Sprint(e) == fmt.Sprint(val) {
					return false
				}
			}
		}
	}
	return true
}
