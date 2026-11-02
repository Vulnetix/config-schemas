// Package ssvc is the CISA Stakeholder-Specific Vulnerability Categorization
// decision (https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
// that Vulnetix makes for a finding: four decision points go in, and one of
// Track, Track*, Attend or Act comes out.
//
// The decision points and the table are those of the CISA Coordinator decision
// table, version 2.0.3, published by the CERT Coordination Center in
// github.com/CERTCC/SSVC:
//
//   - Exploitation: none, poc or active.
//   - Automatable: no or yes.
//   - Technical impact: partial or total.
//   - Mission and well-being: low, medium or high.
//
// The table is fixed. What an organisation configures (see Policy) is how the
// signals Vulnetix holds about a finding become those four values, which
// outcome a given row means to the organisation, and what each outcome asks of
// it. The vulnetix SsvcPolicy kind is a Policy as a document.
package ssvc

import "fmt"

// Exploitation is the present state of exploitation of the vulnerability.
type Exploitation string

const (
	ExploitNone   Exploitation = "none"
	ExploitPoC    Exploitation = "poc"
	ExploitActive Exploitation = "active"
)

// Automatable is whether an attacker can reliably automate steps 1 to 4 of the
// kill chain (reconnaissance, weaponization, delivery, exploitation).
type Automatable string

const (
	AutomatableNo  Automatable = "no"
	AutomatableYes Automatable = "yes"
)

// TechnicalImpact is the technical impact of exploiting the vulnerability.
type TechnicalImpact string

const (
	ImpactPartial TechnicalImpact = "partial"
	ImpactTotal   TechnicalImpact = "total"
)

// MissionWellBeing combines mission prevalence and public well-being impact.
type MissionWellBeing string

const (
	MissionLow    MissionWellBeing = "low"
	MissionMedium MissionWellBeing = "medium"
	MissionHigh   MissionWellBeing = "high"
)

// Outcome is the decision.
type Outcome string

const (
	Track     Outcome = "Track"
	TrackStar Outcome = "Track*"
	Attend    Outcome = "Attend"
	Act       Outcome = "Act"
)

// Outcomes lists the outcomes from least to most urgent.
func Outcomes() []Outcome { return []Outcome{Track, TrackStar, Attend, Act} }

// Rank is the outcome's urgency: 0 for Track to 3 for Act.
func (o Outcome) Rank() int {
	for i, x := range Outcomes() {
		if x == o {
			return i
		}
	}
	return -1
}

// Inputs are the four decision points of one decision.
type Inputs struct {
	Exploitation     Exploitation     `json:"exploitation"`
	Automatable      Automatable      `json:"automatable"`
	TechnicalImpact  TechnicalImpact  `json:"technicalImpact"`
	MissionWellBeing MissionWellBeing `json:"missionWellBeing"`
}

// Valid reports the first decision point that holds an unknown value.
func (in Inputs) Valid() error {
	switch in.Exploitation {
	case ExploitNone, ExploitPoC, ExploitActive:
	default:
		return fmt.Errorf("exploitation %q is not none, poc or active", in.Exploitation)
	}
	switch in.Automatable {
	case AutomatableNo, AutomatableYes:
	default:
		return fmt.Errorf("automatable %q is not no or yes", in.Automatable)
	}
	switch in.TechnicalImpact {
	case ImpactPartial, ImpactTotal:
	default:
		return fmt.Errorf("technicalImpact %q is not partial or total", in.TechnicalImpact)
	}
	switch in.MissionWellBeing {
	case MissionLow, MissionMedium, MissionHigh:
	default:
		return fmt.Errorf("missionWellBeing %q is not low, medium or high", in.MissionWellBeing)
	}
	return nil
}

// Row is one row of the decision table.
type Row struct {
	Inputs
	Outcome Outcome `json:"outcome"`
}

// table is the outcome of each combination, in the order exploitation (none,
// poc, active), automatable (no, yes), technical impact (partial, total),
// mission and well-being (low, medium, high): 36 rows.
// Source: CISA Coordinator decision table 2.0.3, github.com/CERTCC/SSVC,
// data/json/decision_tables/cisa/cisa_coordinator_2_0_3.json.
var table = [36]Outcome{
	Track, Track, Track, Track, Track, TrackStar,
	Track, Track, Attend, Track, Track, Attend,
	Track, Track, TrackStar, Track, TrackStar, Attend,
	Track, Track, Attend, Track, TrackStar, Attend,
	Track, Track, Attend, Track, Attend, Act,
	Attend, Attend, Act, Attend, Act, Act,
}

var (
	exploitations = []Exploitation{ExploitNone, ExploitPoC, ExploitActive}
	automatables  = []Automatable{AutomatableNo, AutomatableYes}
	impacts       = []TechnicalImpact{ImpactPartial, ImpactTotal}
	missions      = []MissionWellBeing{MissionLow, MissionMedium, MissionHigh}
)

func index[T comparable](list []T, v T) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

// Lookup is the CISA outcome for a combination of decision points.
func Lookup(in Inputs) (Outcome, error) {
	if err := in.Valid(); err != nil {
		return "", err
	}
	i := ((index(exploitations, in.Exploitation)*2+index(automatables, in.Automatable))*2+index(impacts, in.TechnicalImpact))*3 + index(missions, in.MissionWellBeing)
	return table[i], nil
}

// Table returns the 36 rows of the decision table, in table order.
func Table() []Row {
	out := make([]Row, 0, len(table))
	for _, e := range exploitations {
		for _, a := range automatables {
			for _, t := range impacts {
				for _, m := range missions {
					in := Inputs{e, a, t, m}
					o, _ := Lookup(in)
					out = append(out, Row{Inputs: in, Outcome: o})
				}
			}
		}
	}
	return out
}

// Values lists every value of each decision point, for a UI and for schemas.
func Values() map[string][]string {
	conv := func(n int, f func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	return map[string][]string{
		"exploitation":     conv(len(exploitations), func(i int) string { return string(exploitations[i]) }),
		"automatable":      conv(len(automatables), func(i int) string { return string(automatables[i]) }),
		"technicalImpact":  conv(len(impacts), func(i int) string { return string(impacts[i]) }),
		"missionWellBeing": conv(len(missions), func(i int) string { return string(missions[i]) }),
	}
}
