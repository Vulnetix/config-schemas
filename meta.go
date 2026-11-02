package configschemas

import (
	"encoding/json"
	"fmt"
)

// MetaKeyword is the schema annotation every kind carries at its root. JSON
// Schema ignores keywords it does not know, so validators never see it; the
// docs generator, the Terraform provider generator and the CLI read it instead
// of keeping their own tables of which kinds are singletons, which fields are
// secrets and which take CEL.
const MetaKeyword = "x-vulnetix"

// Meta is a kind's x-vulnetix annotation.
type Meta struct {
	// ValidateOnly kinds are checked by the CLI and never sent: the server
	// has nothing that stores them yet. Plan notes them; apply skips them.
	ValidateOnly bool `json:"validateOnly"`
	// Singleton kinds exist once per tenant, named default.
	Singleton bool `json:"singleton"`
	// DependsOn lists the kinds this kind refers to by metadata.name, which
	// apply must create first. A kind named here may be newer than this
	// release.
	DependsOn []string `json:"dependsOn"`
	// Secrets are the field paths that hold a valueFrom: the value is read on
	// the client, sent once and never exported. Paths are dotted from the
	// document root, with [] for "every item of the array".
	Secrets []string `json:"secrets"`
	// CELFields are the field paths that hold a CEL expression, with the
	// cel package context each is compiled and evaluated in.
	CELFields []CELField `json:"celFields"`
}

// CELField is one field that takes a CEL expression.
type CELField struct {
	Path string `json:"path"`
	// Env is the cel.Context name: finding, package, request, event or cve.
	Env string `json:"env"`
}

// KindMeta returns a kind's x-vulnetix annotation.
func KindMeta(kind string) (Meta, error) {
	b, err := Schema(kind)
	if err != nil {
		return Meta{}, err
	}
	var s struct {
		Meta *Meta `json:"x-vulnetix"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Meta{}, fmt.Errorf("%s: %w", kind, err)
	}
	if s.Meta == nil {
		return Meta{}, fmt.Errorf("%s: no %s annotation", kind, MetaKeyword)
	}
	return *s.Meta, nil
}
