package cel

import (
	"sync"
	"testing"
)

// The package cache is the path every runtime uses, so the vectors run
// through it as well as through Compile.
func TestVectorsThroughTheCache(t *testing.T) {
	for _, err := range RunVectors(Eval) {
		t.Error(err)
	}
}

func TestCacheCompilesOnce(t *testing.T) {
	c := NewCache(0)
	a, err := c.Program(ContextFinding, "kev")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Program(ContextFinding, "kev")
	if a != b {
		t.Error("the second lookup compiled again")
	}
	// The same text in another context is another program.
	if _, err := c.Program(ContextPackage, "kev"); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 {
		t.Errorf("len %d, want 2", c.Len())
	}
}

func TestCacheKeepsCompileErrors(t *testing.T) {
	c := NewCache(0)
	for i := 0; i < 2; i++ {
		prg, err := c.Program(ContextFinding, "severity >")
		if prg != nil || code(err) != CodeSyntax {
			t.Fatalf("got %v, %v", prg, err)
		}
	}
	if c.Len() != 1 {
		t.Errorf("len %d, want 1", c.Len())
	}
}

func TestCacheBound(t *testing.T) {
	c := NewCache(2)
	for _, e := range []string{"kev", "eol", "malicious"} {
		if _, err := c.Program(ContextFinding, e); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() > 2 {
		t.Errorf("len %d, past the bound of 2", c.Len())
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := NewCache(8)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := c.Eval("cvss >= 7.0", Finding{CVSS: float64(i % 10)})
			if err != nil || ok != (i%10 >= 7) {
				t.Errorf("%d: %v %v", i, ok, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestTypedHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  func() (bool, error)
	}{
		{"finding", func() (bool, error) { return EvalFinding("kev && severity == 'critical'", Finding{KEV: true, Severity: "critical"}) }},
		{"package", func() (bool, error) { return EvalPackage("malware || versionLag > 3", Package{VersionLag: 4}) }},
		{"request", func() (bool, error) { return EvalRequest("'shell' in tools", Request{Tools: []string{"shell"}}) }},
		{"event", func() (bool, error) { return EvalEvent("event == 'push'", Event{Event: "push"}) }},
		{"cve", func() (bool, error) { return EvalCVE("kev && cvss >= 9", CVE{KEV: true, CVSS: 9.8}) }},
	}
	for _, c := range cases {
		ok, err := c.got()
		if err != nil || !ok {
			t.Errorf("%s: %v %v", c.name, ok, err)
		}
	}
	// A helper still refuses an expression that does not type-check in its
	// context.
	if _, err := EvalPackage("severity == 'critical'", Package{}); code(err) != CodeType {
		t.Errorf("package helper with a finding variable: %v", err)
	}
}

func TestEvalNilInput(t *testing.T) {
	if _, err := Eval("true", nil); code(err) != CodeContext {
		t.Errorf("got %v", err)
	}
}
