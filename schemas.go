// Package configschemas embeds the JSON Schemas for every Vulnetix config kind
// and validates documents against them.
//
// The schemas are the source of truth. The config engine in vdb-site, the
// vulnetix CLI and the Terraform provider import this module pinned to a
// release tag, so all three accept exactly the documents the release accepts.
package configschemas

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed schemas/*.schema.json
var files embed.FS

// APIVersion is the document format version of every kind in this module.
const APIVersion = "vulnetix.com/v1"

// DevVersion is the version written in each schema's $id in the source tree.
// The release workflow replaces it with the release tag, so a released schema's
// $id is the URL it is downloaded from.
const DevVersion = "v0.0.0-dev"

// BaseURL is where released schemas are served: <BaseURL>/<version>/<file>.
const BaseURL = "https://github.com/Vulnetix/config-schemas/releases/download"

// sharedFiles hold definitions, not document kinds.
var sharedFiles = map[string]bool{"common.schema.json": true}

// FS returns the embedded schema files, under schemas/.
func FS() fs.FS { return files }

// Kinds lists every document kind, sorted.
func Kinds() []string {
	entries, _ := fs.ReadDir(files, "schemas")
	var kinds []string
	for _, e := range entries {
		if sharedFiles[e.Name()] {
			continue
		}
		kinds = append(kinds, strings.TrimSuffix(e.Name(), ".schema.json"))
	}
	sort.Strings(kinds)
	return kinds
}

// Schema returns the raw schema for a kind.
func Schema(kind string) ([]byte, error) {
	b, err := files.ReadFile(path.Join("schemas", kind+".schema.json"))
	if err != nil {
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
	return b, nil
}

// URL is the released location of a kind's schema at a version.
func URL(version, kind string) string {
	return fmt.Sprintf("%s/%s/%s.schema.json", BaseURL, version, kind)
}

// Validator validates documents against the embedded schemas. Build one with
// NewValidator and reuse it; compiling is the expensive part.
type Validator struct {
	schemas map[string]*jsonschema.Schema
}

// NewValidator compiles every kind's schema. It resolves $refs from the
// embedded copy only and never fetches anything.
func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	entries, err := fs.ReadDir(files, "schemas")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		b, err := files.ReadFile(path.Join("schemas", e.Name()))
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := c.AddResource(URL(DevVersion, strings.TrimSuffix(e.Name(), ".schema.json")), doc); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	v := &Validator{schemas: map[string]*jsonschema.Schema{}}
	for _, k := range Kinds() {
		s, err := c.Compile(URL(DevVersion, k))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		v.schemas[k] = s
	}
	return v, nil
}

// Document is one decoded config document.
type Document struct {
	Kind  string
	Name  string
	Value any // the document as JSON-compatible values
}

// ErrNotADocument is returned for input that has no kind.
var ErrNotADocument = errors.New("not a Vulnetix config document: no kind")

// Decode reads every document in a YAML (or JSON) stream. Empty documents are
// skipped, so a file of only comments decodes to nothing.
func Decode(r io.Reader) ([]Document, error) {
	dec := yaml.NewDecoder(r)
	var docs []Document
	for i := 0; ; i++ {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		var raw any
		if err := node.Decode(&raw); err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		if raw == nil {
			continue
		}
		// Round-trip through JSON so the value holds only JSON types; YAML can
		// decode a timestamp or a non-string map key the schema never sees.
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		val, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		d := Document{Value: val}
		if m, ok := val.(map[string]any); ok {
			d.Kind, _ = m["kind"].(string)
			if md, ok := m["metadata"].(map[string]any); ok {
				d.Name, _ = md["name"].(string)
			}
		}
		docs = append(docs, d)
	}
}

// Validate checks one document against the schema for its kind.
func (v *Validator) Validate(d Document) error {
	if d.Kind == "" {
		return ErrNotADocument
	}
	s, ok := v.schemas[d.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q (known: %s)", d.Kind, strings.Join(Kinds(), ", "))
	}
	return s.Validate(d.Value)
}
