package ssvc

import (
	"reflect"
	"strings"
	"testing"

	configschemas "github.com/vulnetix/config-schemas"
	"github.com/vulnetix/config-schemas/cel"
	"gopkg.in/yaml.v3"
)

func TestTableShape(t *testing.T) {
	rows := Table()
	if len(rows) != 36 {
		t.Fatalf("%d rows, want 36", len(rows))
	}
	seen := map[Inputs]bool{}
	for _, r := range rows {
		if seen[r.Inputs] {
			t.Fatalf("duplicate row %+v", r.Inputs)
		}
		seen[r.Inputs] = true
		if r.Outcome.Rank() < 0 {
			t.Fatalf("row %+v has outcome %q", r.Inputs, r.Outcome)
		}
	}
}

// Rows of the CISA Coordinator table 2.0.3 that fix its corners and a few of
// the cells where Track* and Attend begin.
func TestPublishedRows(t *testing.T) {
	for _, tc := range []struct {
		e Exploitation
		a Automatable
		i TechnicalImpact
		m MissionWellBeing
		o Outcome
	}{
		{ExploitNone, AutomatableNo, ImpactPartial, MissionLow, Track},
		{ExploitNone, AutomatableNo, ImpactTotal, MissionHigh, TrackStar},
		{ExploitNone, AutomatableYes, ImpactPartial, MissionHigh, Attend},
		{ExploitPoC, AutomatableNo, ImpactPartial, MissionHigh, TrackStar},
		{ExploitPoC, AutomatableNo, ImpactTotal, MissionMedium, TrackStar},
		{ExploitPoC, AutomatableYes, ImpactTotal, MissionLow, Track},
		{ExploitActive, AutomatableNo, ImpactTotal, MissionMedium, Attend},
		{ExploitActive, AutomatableNo, ImpactTotal, MissionHigh, Act},
		{ExploitActive, AutomatableYes, ImpactPartial, MissionLow, Attend},
		{ExploitActive, AutomatableYes, ImpactTotal, MissionLow, Attend},
		{ExploitActive, AutomatableYes, ImpactTotal, MissionHigh, Act},
	} {
		got, err := Lookup(Inputs{tc.e, tc.a, tc.i, tc.m})
		if err != nil || got != tc.o {
			t.Errorf("%+v: got %v, %v want %v", tc, got, err, tc.o)
		}
	}
	if _, err := Lookup(Inputs{"x", AutomatableNo, ImpactPartial, MissionLow}); err == nil {
		t.Error("an unknown value must be refused")
	}
}

// Raising any one decision point never lowers the outcome.
func TestTableIsMonotonic(t *testing.T) {
	for _, r := range Table() {
		for _, up := range raise(r.Inputs) {
			o, _ := Lookup(up)
			if o.Rank() < r.Outcome.Rank() {
				t.Errorf("%+v is %s but raising to %+v gives %s", r.Inputs, r.Outcome, up, o)
			}
		}
	}
}

func raise(in Inputs) []Inputs {
	var out []Inputs
	if i := index(exploitations, in.Exploitation); i+1 < len(exploitations) {
		n := in
		n.Exploitation = exploitations[i+1]
		out = append(out, n)
	}
	if in.Automatable == AutomatableNo {
		n := in
		n.Automatable = AutomatableYes
		out = append(out, n)
	}
	if in.TechnicalImpact == ImpactPartial {
		n := in
		n.TechnicalImpact = ImpactTotal
		out = append(out, n)
	}
	if i := index(missions, in.MissionWellBeing); i+1 < len(missions) {
		n := in
		n.MissionWellBeing = missions[i+1]
		out = append(out, n)
	}
	return out
}

func TestDefaultPolicyDecides(t *testing.T) {
	c := Default()
	d, err := c.DecideFinding(cel.Finding{ID: "CVE-1", KEV: true, CVSS: 9.8, Criticality: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != Act || d.Priority != "immediate" || d.Inputs.Exploitation != ExploitActive || d.Inputs.MissionWellBeing != MissionHigh {
		t.Fatalf("%+v", d)
	}
	// The same finding in a low-criticality repository is still urgent (active,
	// automatable, total) but the table says Attend.
	d, _ = c.DecideFinding(cel.Finding{ID: "CVE-1", KEV: true, CVSS: 9.8, Criticality: "low"})
	if d.Outcome != Attend {
		t.Fatalf("%+v", d)
	}
	// Nothing known about it: Track.
	d, _ = c.DecideFinding(cel.Finding{ID: "CVE-2", CVSS: 5})
	if d.Outcome != Track || d.Priority != "low" || d.Inputs.MissionWellBeing != MissionMedium {
		t.Fatalf("%+v", d)
	}
	// A public exploit, not yet seen in the wild.
	d, _ = c.DecideFinding(cel.Finding{ID: "CVE-3", ExploitMaturity: "poc", CVSS: 9.1, Criticality: "high"})
	if d.Inputs.Exploitation != ExploitPoC || d.Inputs.Automatable != AutomatableYes || d.Outcome != Attend {
		t.Fatalf("%+v", d)
	}
}

func TestMappingAndOverrides(t *testing.T) {
	p, err := PolicyFromSpec(map[string]any{
		"mapping": []any{map[string]any{"exploitation": []any{"active"}, "missionWellBeing": []any{"high"}, "outcome": "Act"}},
		"overrides": []any{
			map[string]any{"name": "no-fix-unreachable", "when": "!reachable && fixAvailability == 'no_fix'", "outcome": "Track"},
			map[string]any{"name": "payments", "when": "labels['pci'] == 'in-scope' && severity == 'critical'", "outcome": "Act"},
		},
		"outcomes": map[string]any{"act": map[string]any{"priority": "immediate", "dueDays": int64(3)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := c.DecideFinding(cel.Finding{ID: "x", KEV: true, Criticality: "high"})
	if d.Table == Act || d.Outcome != Act || d.Source != "mapping" || d.DueDays != 3 {
		t.Fatalf("mapping: %+v", d)
	}
	d, _ = c.DecideFinding(cel.Finding{ID: "y", Severity: "critical", Labels: map[string]string{"pci": "in-scope"}})
	if d.Outcome != Act || d.Source != "override" || d.Name != "payments" {
		t.Fatalf("override: %+v", d)
	}
	d, _ = c.DecideFinding(cel.Finding{ID: "z", KEV: true, Criticality: "high", FixAvailability: "no_fix"})
	if d.Outcome != Track || d.Name != "no-fix-unreachable" {
		t.Fatalf("first override wins over the mapping: %+v", d)
	}
}

func TestSpecRoundTrip(t *testing.T) {
	if got := DefaultPolicy().Spec(); len(got) != 0 {
		t.Fatalf("the default names nothing: %v", got)
	}
	spec := map[string]any{
		"exploitation":     map[string]any{"poc": "exploitCount > 2"},
		"automatable":      "cvss >= 8.0",
		"missionWellBeing": map[string]any{"critical": "high", "unclassified": "low"},
		"mapping":          []any{map[string]any{"automatable": []any{"yes"}, "outcome": "Attend"}},
		"overrides":        []any{map[string]any{"when": "kev", "outcome": "Act"}},
		"outcomes":         map[string]any{"attend": map[string]any{"priority": "high", "dueDays": int64(14)}},
	}
	p, err := PolicyFromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if back := p.Spec(); !reflect.DeepEqual(back, map[string]any{
		"exploitation":     map[string]any{"poc": "exploitCount > 2"},
		"automatable":      "cvss >= 8.0",
		"missionWellBeing": map[string]any{"unclassified": "low"},
		"mapping":          []any{map[string]any{"automatable": []any{"yes"}, "outcome": "Attend"}},
		"overrides":        []any{map[string]any{"when": "kev", "outcome": "Act"}},
		"outcomes":         map[string]any{"attend": map[string]any{"priority": "high", "dueDays": int64(14)}},
	}) {
		t.Fatalf("%v", back)
	}
}

func TestValidate(t *testing.T) {
	p := DefaultPolicy()
	p.Automatable = "cvss >="
	p.Overrides = []OverrideRule{{When: "nosuch > 1", Outcome: Act}}
	p.Mission["urgent"] = MissionHigh
	p.Mission["low"] = "extreme"
	p.Outcomes[Act] = OutcomeSpec{Priority: "now", DueDays: 400}
	msgs := p.Validate("spec.")
	for _, want := range []string{"spec.automatable", "spec.overrides[0].when", "missionWellBeing.urgent", "missionWellBeing.low", "outcomes.act.priority", "outcomes.act.dueDays"} {
		found := false
		for _, m := range msgs {
			if strings.Contains(m, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no message for %s in %v", want, msgs)
		}
	}
	if _, err := Compile(p); err == nil {
		t.Error("an invalid policy must not compile")
	}
	if _, err := PolicyFromSpec(map[string]any{"mapping": []any{map[string]any{"outcome": "Defer"}}}); err == nil {
		t.Error("an unknown outcome must be refused")
	}
}

// The published examples are policies the package accepts and compiles.
func TestExamplesCompile(t *testing.T) {
	for _, name := range []string{"minimal", "advanced"} {
		b, err := configschemas.Example("SsvcPolicy", name)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Spec map[string]any `yaml:"spec"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		p, err := PolicyFromSpec(doc.Spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := Compile(p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "advanced" && len(p.Overrides) != 2 {
			t.Errorf("advanced: %d overrides", len(p.Overrides))
		}
	}
}
