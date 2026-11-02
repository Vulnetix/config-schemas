package configschemas

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed examples/*/*.yaml
var exampleFiles embed.FS

// Example returns one of a kind's example files, by its name without the
// .yaml extension: minimal and advanced exist for every kind. Consumers test
// their adapters against the same documents the docs and the Terraform
// provider render, so a release cannot ship an example its own adapters
// refuse.
func Example(kind, name string) ([]byte, error) {
	b, err := exampleFiles.ReadFile(path.Join("examples", kind, name+".yaml"))
	if err != nil {
		return nil, fmt.Errorf("no example %s for kind %q", name, kind)
	}
	return b, nil
}

// Examples lists a kind's example names, sorted, without the .yaml extension.
func Examples(kind string) []string {
	entries, err := fs.ReadDir(exampleFiles, path.Join("examples", kind))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	sort.Strings(out)
	return out
}
