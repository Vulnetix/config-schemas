package cel

import (
	"fmt"
	"strings"
)

// Markdown renders the reference for every context: variables with types and
// bounds, then the custom functions and the limits. cmd/celdoc prints it for
// the docs site, and README.md carries the same text between markers, which
// TestREADMEIsCurrent holds to.
func Markdown() string {
	var b strings.Builder
	for _, ctx := range Contexts() {
		b.WriteString(MarkdownContext(ctx))
		b.WriteString("\n")
	}
	b.WriteString("### Functions\n\nAvailable in every context, alongside the [CEL standard library](https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions).\n\n")
	b.WriteString("| Function | Description |\n|---|---|\n")
	for _, f := range Functions() {
		fmt.Fprintf(&b, "| %s | %s |\n", f.Signature, cell(f.Doc))
	}
	fmt.Fprintf(&b, "\n### Limits\n\n"+
		"| Limit | Value |\n|---|---|\n"+
		"| Expression length | %d bytes |\n"+
		"| Estimated cost, checked at plan | %d |\n"+
		"| Actual cost, checked at evaluation | %d |\n\n"+
		"The estimate assumes every string and list is at its bound in the tables above, and evaluation refuses an input past a bound, so an expression that passes plan cannot exceed the limit when it runs. A single `exists` or `all` over a list is well inside it; a comprehension nested inside another over the same list usually is not.\n",
		MaxExpressionLength, MaxCost, MaxCost)
	return b.String()
}

// MarkdownContext renders one context's variable table.
func MarkdownContext(ctx Context) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### `%s`\n\n", ctx)
	b.WriteString("| Variable | Type | Bound | Description |\n|---|---|---|---|\n")
	for _, v := range variables[ctx] {
		doc := v.Doc
		if v.Derived {
			doc = "Derived. " + doc
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", v.Name, v.Type, bound(v), cell(doc))
	}
	return b.String()
}

func bound(v Variable) string {
	switch v.Type {
	case typeString:
		return fmt.Sprintf("%d chars", v.MaxLen)
	case typeStringList:
		return fmt.Sprintf("%d items of %d chars", v.MaxItems, v.MaxLen)
	case typeStringMap:
		return fmt.Sprintf("%d keys, %d items each, of %d chars", v.MaxItems, v.MaxValueItems, v.MaxLen)
	case typeLabelMap:
		return fmt.Sprintf("%d keys, keys and values of %d chars", v.MaxItems, v.MaxLen)
	}
	return ""
}

// cell escapes a table cell; a pipe inside one would end it.
func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
