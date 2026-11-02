package cel

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"gopkg.in/yaml.v3"
)

// The golden vectors are embedded so the CLI and the server can run exactly
// the vectors this release was tested with, from the module they import,
// rather than a copy that drifts.
//
//go:embed testdata/vectors/*.yaml
var vectorFiles embed.FS

// VectorFS returns the vector files, under testdata/vectors/.
func VectorFS() fs.FS { return vectorFiles }

// VectorFile is one testdata/vectors/<context>.yaml.
type VectorFile struct {
	Context Context  `yaml:"context"`
	Vectors []Vector `yaml:"vectors"`
}

// Vector is one expression with one input and the expected outcome: either
// Want, or Error naming the expected error code. At, when set, is the
// expected position of the first issue.
type Vector struct {
	Name  string         `yaml:"name"`
	Expr  string         `yaml:"expr"`
	Input map[string]any `yaml:"input"`
	Want  *bool          `yaml:"want"`
	Error string         `yaml:"error"`
	At    *Issue         `yaml:"at"`
}

// LoadVectors reads the embedded vectors for a context.
func LoadVectors(ctx Context) ([]Vector, error) {
	b, err := vectorFiles.ReadFile("testdata/vectors/" + string(ctx) + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("no vectors for context %q", ctx)
	}
	var f VectorFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s vectors: %w", ctx, err)
	}
	if f.Context != ctx {
		return nil, fmt.Errorf("%s vectors: file says context %q", ctx, f.Context)
	}
	return f.Vectors, nil
}

// DecodeInput turns a vector's input, keyed by variable name, into the typed
// input of a context. Unknown keys are an error, so a misspelt variable in a
// vector cannot pass silently.
func DecodeInput(ctx Context, node map[string]any) (Input, error) {
	switch ctx {
	case ContextFinding:
		return decodeAs[Finding](node)
	case ContextPackage:
		return decodeAs[Package](node)
	case ContextRequest:
		return decodeAs[Request](node)
	case ContextEvent:
		return decodeAs[Event](node)
	case ContextCVE:
		return decodeAs[CVE](node)
	}
	return nil, fmt.Errorf("unknown context %q", ctx)
}

func decodeAs[T Input](node map[string]any) (Input, error) {
	var v T
	if len(node) == 0 {
		return v, nil
	}
	// The input is held as a map so the file decodes strictly at the top
	// level (yaml.v3 applies KnownFields inside a yaml.Node too), then goes
	// back through a strict decoder into the typed struct.
	raw, err := yaml.Marshal(node)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Run checks one vector. It returns nil when the outcome is the expected one.
func (v Vector) Run(ctx Context) error {
	if (v.Want == nil) == (v.Error == "") {
		return fmt.Errorf("%s: set exactly one of want and error", v.Name)
	}
	prg, err := Compile(ctx, v.Expr)
	if err == nil {
		var in Input
		if in, err = DecodeInput(ctx, v.Input); err != nil {
			return fmt.Errorf("%s: input: %w", v.Name, err)
		}
		var got bool
		if got, err = prg.Eval(in); err == nil {
			if v.Want == nil {
				return fmt.Errorf("%s: got %v, want error %s", v.Name, got, v.Error)
			}
			if got != *v.Want {
				return fmt.Errorf("%s: got %v, want %v", v.Name, got, *v.Want)
			}
			return nil
		}
	}
	var ce *Error
	if !errors.As(err, &ce) {
		return fmt.Errorf("%s: error is not a *cel.Error: %v", v.Name, err)
	}
	if v.Error == "" {
		return fmt.Errorf("%s: unexpected error: %v", v.Name, err)
	}
	if ce.Code != v.Error {
		return fmt.Errorf("%s: got error %v, want code %s", v.Name, err, v.Error)
	}
	if v.At != nil {
		if len(ce.Issues) == 0 || ce.Issues[0].Line != v.At.Line || ce.Issues[0].Column != v.At.Column {
			return fmt.Errorf("%s: got error %v, want it at %d:%d", v.Name, err, v.At.Line, v.At.Column)
		}
	}
	return nil
}
