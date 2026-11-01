package configschemas

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func decodeFile(t *testing.T, p string) []Document {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	docs, err := Decode(f)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	if len(docs) == 0 {
		t.Fatalf("%s: no documents", p)
	}
	return docs
}

// Every schema carries the dev $id of its own file, so the release workflow's
// rewrite produces the URL the file is published at.
func TestSchemaIDsMatchFileNames(t *testing.T) {
	entries, _ := fs.ReadDir(FS(), "schemas")
	for _, e := range entries {
		b, _ := files.ReadFile("schemas/" + e.Name())
		var s struct {
			ID     string `json:"$id"`
			Schema string `json:"$schema"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		want := BaseURL + "/" + DevVersion + "/" + e.Name()
		if s.ID != want {
			t.Errorf("%s: $id %q, want %q", e.Name(), s.ID, want)
		}
		if s.Schema != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s: $schema %q, want draft 2020-12", e.Name(), s.Schema)
		}
	}
}

// Every kind has at least one valid example, and every example is valid.
func TestExamplesValidate(t *testing.T) {
	v := validator(t)
	for _, k := range Kinds() {
		matches, _ := filepath.Glob(filepath.Join("examples", k, "*.yaml"))
		if len(matches) == 0 {
			t.Errorf("%s: no examples under examples/%s/", k, k)
		}
		for _, p := range matches {
			for _, d := range decodeFile(t, p) {
				if d.Kind != k {
					t.Errorf("%s: kind %q in the %s folder", p, d.Kind, k)
				}
				if err := v.Validate(d); err != nil {
					t.Errorf("%s: %v", p, err)
				}
			}
		}
	}
}

// Every file under testdata/invalid/<Kind>/ must be rejected. Each file's
// first line is a comment naming the rule it breaks.
func TestInvalidDocumentsAreRejected(t *testing.T) {
	v := validator(t)
	matches, _ := filepath.Glob(filepath.Join("testdata", "invalid", "*", "*.yaml"))
	if len(matches) == 0 {
		t.Fatal("no invalid fixtures")
	}
	for _, p := range matches {
		for _, d := range decodeFile(t, p) {
			if err := v.Validate(d); err == nil {
				t.Errorf("%s: accepted, want rejected", p)
			}
		}
	}
}

func TestUnknownKindAndMissingKind(t *testing.T) {
	v := validator(t)
	docs, err := Decode(strings.NewReader("apiVersion: vulnetix.com/v1\nkind: NoSuchKind\nmetadata: {name: x}\n---\nfoo: bar\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(docs[0]); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("unknown kind: %v", err)
	}
	if err := v.Validate(docs[1]); err != ErrNotADocument {
		t.Errorf("missing kind: %v", err)
	}
}

func TestDecodeSkipsEmptyDocuments(t *testing.T) {
	docs, err := Decode(strings.NewReader("# just a comment\n---\n---\napiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default}\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || docs[0].Kind != "QualityGate" || docs[0].Name != "default" {
		t.Fatalf("got %+v", docs)
	}
}
