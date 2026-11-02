package cel

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVectors(t *testing.T) {
	for _, ctx := range Contexts() {
		t.Run(string(ctx), func(t *testing.T) {
			vs, err := LoadVectors(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// The brief for every context: enough vectors to pin behaviour,
			// and each kind of failure covered at least once.
			if len(vs) < 15 {
				t.Errorf("%d vectors, want at least 15", len(vs))
			}
			codes := map[string]bool{}
			for _, v := range vs {
				codes[v.Error] = true
				t.Run(v.Name, func(t *testing.T) {
					if err := v.Run(ctx); err != nil {
						t.Error(err)
					}
				})
			}
			for _, c := range []string{CodeType, CodeSyntax, CodeResultType, CodeCost, CodeInput} {
				if !codes[c] {
					t.Errorf("no vector expects error %s", c)
				}
			}
		})
	}
}

// The estimate must be an upper bound on what evaluation actually costs, or
// the plan-time check means nothing.
func TestEstimateBoundsActualCost(t *testing.T) {
	for _, ctx := range Contexts() {
		vs, err := LoadVectors(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			if v.Want == nil {
				continue
			}
			prg, err := Compile(ctx, v.Expr)
			if err != nil {
				t.Fatalf("%s/%s: %v", ctx, v.Name, err)
			}
			in, err := DecodeInput(ctx, v.Input)
			if err != nil {
				t.Fatal(err)
			}
			_, det, err := prg.prg.Eval(in.vars(time.Now()))
			if err != nil {
				continue // an eval error vector; Run covers it
			}
			if got := *det.ActualCost(); got > prg.Cost().Max {
				t.Errorf("%s/%s: actual cost %d above the estimate %d", ctx, v.Name, got, prg.Cost().Max)
			}
		}
	}
}

func TestVariablesMatchInputs(t *testing.T) {
	inputs := map[Context]Input{
		ContextFinding: Finding{}, ContextPackage: Package{}, ContextRequest: Request{},
		ContextEvent: Event{}, ContextCVE: CVE{},
	}
	for _, ctx := range Contexts() {
		vars := inputs[ctx].vars(time.Now())
		table := Variables(ctx)
		if len(vars) != len(table) {
			t.Errorf("%s: input renders %d variables, table has %d", ctx, len(vars), len(table))
		}
		for _, v := range table {
			val, ok := vars[v.Name]
			if !ok {
				t.Errorf("%s: input does not render %s", ctx, v.Name)
				continue
			}
			var match bool
			switch val.(type) {
			case string:
				match = v.Type == typeString && v.MaxLen > 0
			case float64:
				match = v.Type == typeDouble
			case int64:
				match = v.Type == typeInt
			case bool:
				match = v.Type == typeBool
			case time.Time:
				match = v.Type == typeTimestamp
			case []string:
				match = v.Type == typeStringList && v.MaxLen > 0 && v.MaxItems > 0
			case map[string][]string:
				match = v.Type == typeStringMap && v.MaxLen > 0 && v.MaxItems > 0 && v.MaxValueItems > 0
			}
			if !match {
				t.Errorf("%s.%s: Go value %T does not fit table type %s with its bounds", ctx, v.Name, val, v.Type)
			}
			if v.Doc == "" {
				t.Errorf("%s.%s: no doc", ctx, v.Name)
			}
		}
	}
}

func code(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

func TestExpressionLength(t *testing.T) {
	ok := "true" + strings.Repeat(" ", MaxExpressionLength-4)
	if _, err := Compile(ContextFinding, ok); err != nil {
		t.Errorf("%d bytes: %v", len(ok), err)
	}
	if _, err := Compile(ContextFinding, ok+" "); code(err) != CodeLength {
		t.Errorf("%d bytes: got %v, want a length error", len(ok)+1, err)
	}
}

func TestRuntimeCostLimit(t *testing.T) {
	expr := "aliases.all(a, a.glob('CVE-*'))"
	prg, err := compile(ContextFinding, expr, 20)
	if err != nil {
		t.Fatal(err)
	}
	in := Finding{Aliases: strings.Split(strings.Repeat("CVE-2024-0001,", 20), ",")[:20]}
	if _, err := prg.Eval(in); code(err) != CodeCost {
		t.Errorf("got %v, want a cost error", err)
	}
	if prg, err = Compile(ContextFinding, expr); err != nil {
		t.Fatal(err)
	}
	if got, err := prg.Eval(in); err != nil || !got {
		t.Errorf("with the real limit: got %v, %v", got, err)
	}
}

func TestContextMismatch(t *testing.T) {
	prg, err := Compile(ContextFinding, "kev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prg.Eval(Package{KEV: true}); code(err) != CodeContext {
		t.Errorf("got %v, want a context error", err)
	}
	if _, err := Compile("nope", "true"); code(err) != CodeContext {
		t.Errorf("got %v, want a context error", err)
	}
}

func TestNowDefaultsToTheClock(t *testing.T) {
	prg, err := Compile(ContextCVE, "now > timestamp('2026-01-01T00:00:00Z')")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := prg.Eval(CVE{}); err != nil || !got {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestErrorPosition(t *testing.T) {
	_, err := Compile(ContextFinding, "kev &&\n  cvss == 'x'")
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != CodeType {
		t.Fatalf("got %v", err)
	}
	if is := ce.Issues[0]; is.Line != 2 || is.Column != 8 {
		t.Errorf("issue at %d:%d, want 2:8: %v", is.Line, is.Column, err)
	}
	if !strings.HasPrefix(err.Error(), "type: 2:8: ") {
		t.Errorf("message %q", err.Error())
	}
}

func TestSemver(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.9.0", "1.10.0", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-rc.1", "1.0.0-beta.11", 1},
		{"1.0.0+build.1", "1.0.0+build.2", 0},
	} {
		a, oka := parseSemver(c.a)
		b, okb := parseSemver(c.b)
		if !oka || !okb {
			t.Errorf("%s, %s: not parsed", c.a, c.b)
			continue
		}
		if got := a.compare(b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"", "1", "1.2", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+", "1.0.x", "2024.1", "1.0.0-a_b"} {
		if _, ok := parseSemver(bad); ok {
			t.Errorf("%q parsed as a version", bad)
		}
	}
}

func TestPurlMatches(t *testing.T) {
	for _, c := range []struct {
		purl, pattern string
		want          bool
		err           bool
	}{
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash", true, false},
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21", true, false},
		{"pkg:npm/lodash@4.17.21", "pkg:pypi/lodash", false, false},
		{"pkg:npm/lodash", "pkg:npm/lodash@4.17.21", false, false},
		{"pkg:npm/%40acme/tool@1.0.0", "pkg:npm/@acme/*", true, false},
		{"pkg:npm/@acme/tool@1.0.0", "pkg:npm/%40acme/*", true, false},
		{"pkg:npm/@acme-evil/tool", "pkg:npm/@acme/*", false, false},
		{"pkg:npm/@acme/", "pkg:npm/@acme/*", false, false},
		{"pkg:golang/github.com/acme/tool/v2@v2.0.0", "pkg:golang/github.com/*", true, false},
		{"pkg:golang/github.com/acme/tool/v2@v2.0.0", "pkg:golang/github.com/acme/tool/*", true, false},
		{"PKG:NPM/lodash", "pkg:npm/lodash", true, false},
		{"pkg:npm/lodash@1.0.0?arch=x#sub", "pkg:npm/lodash@1.0.0", true, false},
		{"pkg:npm/lodash", "pkg:npm/lo*", false, true},
		{"pkg:npm/lodash", "pkg:npm/*", false, true},
		{"pkg:npm/@acme/tool", "pkg:npm/@acme/*@1.0.0", false, true},
		{"lodash", "pkg:npm/lodash", false, true},
		{"pkg:npm", "pkg:npm/lodash", false, true},
	} {
		got, err := purlMatches(c.purl, c.pattern)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("purlMatches(%q, %q) = %v, %v; want %v, error %v", c.purl, c.pattern, got, err, c.want, c.err)
		}
	}
}

// The cases of vdb-site's feGlobMatch, which this dialect must equal.
func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"main", "main", true},
		{"release/*", "release/1.0", true},
		{"release/*", "release/1.0/hotfix", false},
		{"release/**", "release/1.0/hotfix", true},
		{"**/*.go", "main.go", true},
		{"**/*.go", "a/b/main.go", true},
		{"src/**/test", "src/test", true},
		{"v?", "v1", true},
		{"v?", "v10", false},
		{"a.b", "aXb", false},
		{"dependabot[bot]", "dependabot[bot]", true},
	} {
		if got := globMatch(c.s, c.pat); got != c.want {
			t.Errorf("glob(%q, %q) = %v, want %v", c.s, c.pat, got, c.want)
		}
	}
}

func TestNamespaceCandidates(t *testing.T) {
	got := strings.Join(namespaceCandidates("github.com/acme/tool/v2"), " ")
	if want := "github.com/acme/tool/* github.com/acme/* github.com/*"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := namespaceCandidates("com.acme:lib"); len(got) != 1 || got[0] != "com.acme:*" {
		t.Errorf("got %q", got)
	}
}

func TestREADMEIsCurrent(t *testing.T) {
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- celdoc:begin -->\n", "<!-- celdoc:end -->"
	s := string(b)
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatal("README.md has no celdoc markers")
	}
	if got := s[i+len(begin) : j]; got != Markdown() {
		t.Error("README.md reference is stale; regenerate it with go run ./cmd/celdoc")
	}
}
