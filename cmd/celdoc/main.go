// Command celdoc prints the CEL rule reference as Markdown, for the docs site.
//
//	celdoc                    every context, the functions and the limits
//	celdoc --context finding  one context's variable table
//
// The output comes from the same tables the environments are declared from,
// so the docs cannot describe a variable the module does not have.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vulnetix/config-schemas/cel"
)

func main() {
	ctx := flag.String("context", "", "print only this context: "+names())
	flag.Parse()
	if *ctx == "" {
		fmt.Print(cel.Markdown())
		return
	}
	if cel.Variables(cel.Context(*ctx)) == nil {
		fmt.Fprintf(os.Stderr, "celdoc: unknown context %q; one of %s\n", *ctx, names())
		os.Exit(2)
	}
	fmt.Print(cel.MarkdownContext(cel.Context(*ctx)))
}

func names() string {
	var out []string
	for _, c := range cel.Contexts() {
		out = append(out, string(c))
	}
	return strings.Join(out, ", ")
}
