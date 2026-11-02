package ssvc

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/vulnetix/config-schemas/cel"
)

// Policy is an organisation's SSVC configuration: how Vulnetix's signals about
// a finding become the four decision points, what the organisation does for a
// row of the table, and what each outcome asks of it. It is the spec of the
// SsvcPolicy kind. The zero Policy is not usable; start from DefaultPolicy, or
// read a document with PolicyFromSpec, which fills in what a document leaves
// out.
type Policy struct {
	// ExploitationActive and ExploitationPoC are CEL expressions over the
	// finding context. Active wins when both hold; neither is none.
	ExploitationActive string
	ExploitationPoC    string
	// Automatable holds when an attacker can automate steps 1 to 4 of the
	// kill chain.
	Automatable string
	// TechnicalImpactTotal holds when exploiting the finding gives total
	// control or total disclosure.
	TechnicalImpactTotal string
	// Mission maps a repository's criticality (low, medium, high, critical,
	// or Unclassified) to the mission and well-being value.
	Mission map[string]MissionWellBeing
	// Mapping changes the outcome of the table cells it matches.
	Mapping []MappingRule
	// Overrides are CEL rules over the finding, applied after the table and
	// the mapping: the first that holds sets the outcome.
	Overrides []OverrideRule
	// Outcomes says what each outcome asks of the organisation.
	Outcomes map[Outcome]OutcomeSpec
}

// Unclassified is the Mission key for a repository with no criticality.
const Unclassified = "unclassified"

// MappingRule changes the outcome of every cell of the table its fields
// match. A field left empty matches any value.
type MappingRule struct {
	Exploitation     []Exploitation     `json:"exploitation,omitempty"`
	Automatable      []Automatable      `json:"automatable,omitempty"`
	TechnicalImpact  []TechnicalImpact  `json:"technicalImpact,omitempty"`
	MissionWellBeing []MissionWellBeing `json:"missionWellBeing,omitempty"`
	Outcome          Outcome            `json:"outcome"`
}

func (r MappingRule) matches(in Inputs) bool {
	return has(r.Exploitation, in.Exploitation) && has(r.Automatable, in.Automatable) &&
		has(r.TechnicalImpact, in.TechnicalImpact) && has(r.MissionWellBeing, in.MissionWellBeing)
}

func has[T comparable](list []T, v T) bool {
	if len(list) == 0 {
		return true
	}
	return index(list, v) >= 0
}

// OverrideRule sets the outcome of the findings its CEL condition holds for.
type OverrideRule struct {
	Name    string  `json:"name,omitempty"`
	When    string  `json:"when"`
	Outcome Outcome `json:"outcome"`
}

// OutcomeSpec is what an outcome asks of the organisation.
type OutcomeSpec struct {
	// Priority is immediate, high, medium or low.
	Priority string `json:"priority"`
	// DueDays is the remediation window in days, or 0 for the standard
	// update cycle.
	DueDays int `json:"dueDays,omitempty"`
}

// Priorities lists the priorities from least to most urgent.
func Priorities() []string { return []string{"low", "medium", "high", "immediate"} }

// DefaultPolicy is the policy of an organisation that has configured none.
func DefaultPolicy() Policy {
	return Policy{
		ExploitationActive:   "kev || exploitMaturity in ['active', 'weaponized']",
		ExploitationPoC:      "exploitMaturity == 'poc' || exploitCount > 0",
		Automatable:          "cvss >= 9.0 || epss >= 0.7",
		TechnicalImpactTotal: "cvss >= 9.0 || malicious",
		Mission: map[string]MissionWellBeing{
			"low": MissionLow, "medium": MissionMedium, "high": MissionHigh, "critical": MissionHigh,
			Unclassified: MissionMedium,
		},
		Outcomes: map[Outcome]OutcomeSpec{
			Track:     {Priority: "low"},
			TrackStar: {Priority: "medium"},
			Attend:    {Priority: "high"},
			Act:       {Priority: "immediate"},
		},
	}
}

// outcomeKeys are the spec keys of the outcomes.
var outcomeKeys = map[string]Outcome{"track": Track, "trackStar": TrackStar, "attend": Attend, "act": Act}

// OutcomeKey is the spec key of an outcome.
func OutcomeKey(o Outcome) string {
	for k, v := range outcomeKeys {
		if v == o {
			return k
		}
	}
	return ""
}

// PolicyFromSpec reads the spec of an SsvcPolicy document. Anything the spec
// leaves out takes the default. It does not compile the expressions; Compile
// does.
func PolicyFromSpec(spec map[string]any) (Policy, error) {
	p := DefaultPolicy()
	str := func(v any) (string, bool) { s, ok := v.(string); return s, ok }
	if e, ok := spec["exploitation"].(map[string]any); ok {
		if s, ok := str(e["active"]); ok {
			p.ExploitationActive = s
		}
		if s, ok := str(e["poc"]); ok {
			p.ExploitationPoC = s
		}
	}
	if s, ok := str(spec["automatable"]); ok {
		p.Automatable = s
	}
	if s, ok := str(spec["technicalImpact"]); ok {
		p.TechnicalImpactTotal = s
	}
	if m, ok := spec["missionWellBeing"].(map[string]any); ok {
		for k, v := range m {
			if s, ok := str(v); ok {
				p.Mission[k] = MissionWellBeing(s)
			}
		}
	}
	if l, ok := spec["mapping"].([]any); ok {
		for i, item := range l {
			m, _ := item.(map[string]any)
			r := MappingRule{}
			r.Exploitation = strList[Exploitation](m["exploitation"])
			r.Automatable = strList[Automatable](m["automatable"])
			r.TechnicalImpact = strList[TechnicalImpact](m["technicalImpact"])
			r.MissionWellBeing = strList[MissionWellBeing](m["missionWellBeing"])
			o, _ := str(m["outcome"])
			r.Outcome = Outcome(o)
			if r.Outcome.Rank() < 0 {
				return p, fmt.Errorf("mapping[%d].outcome: %q is not Track, Track*, Attend or Act", i, o)
			}
			p.Mapping = append(p.Mapping, r)
		}
	}
	if l, ok := spec["overrides"].([]any); ok {
		for i, item := range l {
			m, _ := item.(map[string]any)
			r := OverrideRule{}
			r.Name, _ = str(m["name"])
			r.When, _ = str(m["when"])
			o, _ := str(m["outcome"])
			r.Outcome = Outcome(o)
			if r.Outcome.Rank() < 0 {
				return p, fmt.Errorf("overrides[%d].outcome: %q is not Track, Track*, Attend or Act", i, o)
			}
			p.Overrides = append(p.Overrides, r)
		}
	}
	if m, ok := spec["outcomes"].(map[string]any); ok {
		for k, v := range m {
			o, known := outcomeKeys[k]
			if !known {
				return p, fmt.Errorf("outcomes.%s: not one of track, trackStar, attend, act", k)
			}
			om, _ := v.(map[string]any)
			cur := p.Outcomes[o]
			if s, ok := str(om["priority"]); ok {
				cur.Priority = s
			}
			if d, ok := om["dueDays"]; ok {
				cur.DueDays = intOf(d)
			}
			p.Outcomes[o] = cur
		}
	}
	return p, nil
}

func strList[T ~string](v any) []T {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]T, 0, len(l))
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, T(s))
		}
	}
	return out
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// Spec renders a policy as the spec of an SsvcPolicy document, naming only
// what differs from DefaultPolicy, in the form PolicyFromSpec reads and a store
// reads back.
func (p Policy) Spec() map[string]any {
	def := DefaultPolicy()
	spec := map[string]any{}
	exp := map[string]any{}
	if p.ExploitationActive != def.ExploitationActive {
		exp["active"] = p.ExploitationActive
	}
	if p.ExploitationPoC != def.ExploitationPoC {
		exp["poc"] = p.ExploitationPoC
	}
	if len(exp) > 0 {
		spec["exploitation"] = exp
	}
	if p.Automatable != def.Automatable {
		spec["automatable"] = p.Automatable
	}
	if p.TechnicalImpactTotal != def.TechnicalImpactTotal {
		spec["technicalImpact"] = p.TechnicalImpactTotal
	}
	mw := map[string]any{}
	for k, v := range p.Mission {
		if def.Mission[k] != v {
			mw[k] = string(v)
		}
	}
	if len(mw) > 0 {
		spec["missionWellBeing"] = mw
	}
	if len(p.Mapping) > 0 {
		l := make([]any, 0, len(p.Mapping))
		for _, r := range p.Mapping {
			m := map[string]any{"outcome": string(r.Outcome)}
			put := func(k string, v []string) {
				if len(v) > 0 {
					a := make([]any, len(v))
					for i, s := range v {
						a[i] = s
					}
					m[k] = a
				}
			}
			put("exploitation", toStrings(r.Exploitation))
			put("automatable", toStrings(r.Automatable))
			put("technicalImpact", toStrings(r.TechnicalImpact))
			put("missionWellBeing", toStrings(r.MissionWellBeing))
			l = append(l, m)
		}
		spec["mapping"] = l
	}
	if len(p.Overrides) > 0 {
		l := make([]any, 0, len(p.Overrides))
		for _, r := range p.Overrides {
			m := map[string]any{"when": r.When, "outcome": string(r.Outcome)}
			if r.Name != "" {
				m["name"] = r.Name
			}
			l = append(l, m)
		}
		spec["overrides"] = l
	}
	oc := map[string]any{}
	for o, s := range p.Outcomes {
		d := def.Outcomes[o]
		if s == d {
			continue
		}
		m := map[string]any{"priority": s.Priority}
		if s.DueDays > 0 {
			m["dueDays"] = int64(s.DueDays)
		}
		oc[OutcomeKey(o)] = m
	}
	if len(oc) > 0 {
		spec["outcomes"] = oc
	}
	return spec
}

func toStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// Validate returns one message per problem, each prefixed with prefix (such as
// "spec."): unknown values, expressions that do not compile in the finding
// context, and mission keys that are not criticalities.
func (p Policy) Validate(prefix string) []string {
	var out []string
	for _, f := range []struct{ path, expr string }{
		{"exploitation.active", p.ExploitationActive}, {"exploitation.poc", p.ExploitationPoC},
		{"automatable", p.Automatable}, {"technicalImpact", p.TechnicalImpactTotal},
	} {
		if err := cel.Check(cel.ContextFinding, f.expr); err != nil {
			out = append(out, prefix+f.path+": "+err.Error())
		}
	}
	keys := make([]string, 0, len(p.Mission))
	for k := range p.Mission {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch k {
		case "low", "medium", "high", "critical", Unclassified:
		default:
			out = append(out, fmt.Sprintf("%smissionWellBeing.%s: not a criticality", prefix, k))
		}
		if index(missions, p.Mission[k]) < 0 {
			out = append(out, fmt.Sprintf("%smissionWellBeing.%s: %q is not low, medium or high", prefix, k, p.Mission[k]))
		}
	}
	for i, r := range p.Overrides {
		if err := cel.Check(cel.ContextFinding, r.When); err != nil {
			out = append(out, fmt.Sprintf("%soverrides[%d].when: %s", prefix, i, err))
		}
	}
	for o, s := range p.Outcomes {
		if index(Priorities(), s.Priority) < 0 {
			out = append(out, fmt.Sprintf("%soutcomes.%s.priority: %q is not low, medium, high or immediate", prefix, OutcomeKey(o), s.Priority))
		}
		if s.DueDays < 0 || s.DueDays > 365 {
			out = append(out, fmt.Sprintf("%soutcomes.%s.dueDays: must be 0 to 365", prefix, OutcomeKey(o)))
		}
	}
	sort.Strings(out)
	return out
}

// Compiled is a Policy whose expressions have been compiled. It is safe for
// concurrent use.
type Compiled struct {
	Policy                   Policy
	active, poc, auto, total *cel.Program
	overrides                []*cel.Program
}

var programs = cel.NewCache(0)

// Compile compiles the policy's expressions. Programs are cached by
// expression, so compiling the same policy again is cheap.
func Compile(p Policy) (*Compiled, error) {
	if msgs := p.Validate(""); len(msgs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	c := &Compiled{Policy: p}
	var err error
	for _, f := range []struct {
		dst  **cel.Program
		expr string
	}{{&c.active, p.ExploitationActive}, {&c.poc, p.ExploitationPoC}, {&c.auto, p.Automatable}, {&c.total, p.TechnicalImpactTotal}} {
		if *f.dst, err = programs.Program(cel.ContextFinding, f.expr); err != nil {
			return nil, err
		}
	}
	for _, r := range p.Overrides {
		prg, err := programs.Program(cel.ContextFinding, r.When)
		if err != nil {
			return nil, err
		}
		c.overrides = append(c.overrides, prg)
	}
	return c, nil
}

var (
	defaultOnce     sync.Once
	defaultCompiled *Compiled
)

// Default is the compiled DefaultPolicy.
func Default() *Compiled {
	defaultOnce.Do(func() {
		c, err := Compile(DefaultPolicy())
		if err != nil {
			panic("ssvc: the default policy does not compile: " + err.Error())
		}
		defaultCompiled = c
	})
	return defaultCompiled
}

// Decision is the result for one finding.
type Decision struct {
	Inputs   Inputs  `json:"inputs"`
	Table    Outcome `json:"table"`
	Outcome  Outcome `json:"outcome"`
	Priority string  `json:"priority"`
	DueDays  int     `json:"dueDays,omitempty"`
	// Source is table, mapping or override.
	Source string `json:"source"`
	// Rule is the index of the mapping or override rule that set the outcome,
	// and Name the override's name.
	Rule int    `json:"rule,omitempty"`
	Name string `json:"name,omitempty"`
}

// Derive turns a finding into the four decision points. An expression that
// fails to evaluate holds for nothing, so the decision point takes its lower
// value; err reports the first failure.
func (c *Compiled) Derive(f cel.Finding) (in Inputs, err error) {
	hold := func(p *cel.Program) bool {
		ok, e := p.Eval(f)
		if e != nil && err == nil {
			err = e
		}
		return ok && e == nil
	}
	in.Exploitation = ExploitNone
	switch {
	case hold(c.active):
		in.Exploitation = ExploitActive
	case hold(c.poc):
		in.Exploitation = ExploitPoC
	}
	in.Automatable = AutomatableNo
	if hold(c.auto) {
		in.Automatable = AutomatableYes
	}
	in.TechnicalImpact = ImpactPartial
	if hold(c.total) {
		in.TechnicalImpact = ImpactTotal
	}
	key := strings.ToLower(f.Criticality)
	if key == "" {
		key = Unclassified
	}
	in.MissionWellBeing = c.Policy.Mission[key]
	if in.MissionWellBeing == "" {
		in.MissionWellBeing = c.Policy.Mission[Unclassified]
	}
	return in, err
}

// Decide is the decision for four decision points. f supplies the finding the
// override rules are evaluated against; pass the zero Finding when deciding
// from decision points alone, and no override can hold unless it is
// unconditional.
func (c *Compiled) Decide(in Inputs, f cel.Finding) (Decision, error) {
	base, err := Lookup(in)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Inputs: in, Table: base, Outcome: base, Source: "table"}
	for i, r := range c.Policy.Mapping {
		if r.matches(in) {
			d.Outcome, d.Source, d.Rule = r.Outcome, "mapping", i
		}
	}
	for i, prg := range c.overrides {
		if ok, e := prg.Eval(f); e == nil && ok {
			r := c.Policy.Overrides[i]
			d.Outcome, d.Source, d.Rule, d.Name = r.Outcome, "override", i, r.Name
			break
		}
	}
	spec := c.Policy.Outcomes[d.Outcome]
	d.Priority, d.DueDays = spec.Priority, spec.DueDays
	return d, nil
}

// DecideFinding derives the decision points of a finding and decides.
func (c *Compiled) DecideFinding(f cel.Finding) (Decision, error) {
	in, derr := c.Derive(f)
	d, err := c.Decide(in, f)
	if err != nil {
		return d, err
	}
	return d, derr
}
