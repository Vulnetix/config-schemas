package cel

// Runtime is a runtime that evaluates stored rules, and what it does when a
// rule's expression cannot be evaluated. The library only reports the error;
// what a rule does with it is the runtime's own business rule, and this table
// is the one place they are written down. cmd/celdoc renders it, and README.md
// carries the same text, which TestREADMEIsCurrent holds to.
type Runtime struct {
	Name string
	// Where is the document field the expression is written in.
	Where string
	// OnError is what happens when the expression does not compile or fails
	// to evaluate.
	OnError string
}

// Runtimes lists the runtimes in the order the docs show them.
func Runtimes() []Runtime {
	return []Runtime{
		{
			Name:    "Jail (vdb-api)",
			Where:   "`JailPolicy` rule `when`",
			OnError: "Does not fail closed. A rule whose `when` does not compile, or uses a finding variable the facts of its rule kind do not carry yet, is skipped with a warning and does not run. A fact the expression fails on leaves the rule `indeterminate`, so the verdict is `indeterminate` and the CLI exits 3; a breached rule elsewhere still wins, with exit 1.",
		},
		{
			Name:    "Factory gate (vdb-site)",
			Where:   "`JailPolicy` rule `when`, in a workflow gate node",
			OnError: "The only runtime that fails closed. A `when` that does not compile or fails on a finding makes the rule breach, and its label says it could not be evaluated. So does a scan that kept fewer findings than it found, unless the count over the kept ones already breaches. A rule with `onBreach: WARN` does not fail the gate.",
		},
		{
			Name:    "Risk prioritisation (vdb-site)",
			Where:   "`RiskStrategy` rule `when`",
			OnError: "Fails open. A finding the expression fails on does not match. A rule that does not compile is logged and matches nothing.",
		},
		{
			Name:    "Suppression",
			Where:   "`Suppression` `when`",
			OnError: "Fails open. A finding the expression fails on is not suppressed. A rule whose expression cannot be evaluated covers nothing in that run and the error is logged; every other rule applies as usual.",
		},
		{
			Name:    "Package firewall",
			Where:   "`PackageList` entry `when`",
			OnError: "The entry is skipped and the error is logged: a deny entry does not block and an allow entry does not waive, so a broken condition neither blocks nor waives more than was declared.",
		},
		{
			Name:    "AI firewall",
			Where:   "`AiFirewallPolicy` rule `when`",
			OnError: "The rule is skipped and named in the decision's skipped list with the error. The gateway does not block or flag on a condition it could not evaluate.",
		},
	}
}
