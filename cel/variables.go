package cel

// The variable tables are the single description of each context: the CEL
// environment is declared from them, inputs are bounds-checked against them,
// and cmd/celdoc renders them for the docs. Field names and value sets come
// from the models the inputs are read from, cited per context.

// Context names a rule context. Each has its own variables, so an expression
// written for one does not type-check in another.
type Context string

const (
	// ContextFinding is for quality gate, jail, prioritisation and
	// suppression rules over vulnerability findings.
	ContextFinding Context = "finding"
	// ContextPackage is for package firewall rules over one package version.
	ContextPackage Context = "package"
	// ContextRequest is for AI firewall guardrails over one model request.
	ContextRequest Context = "request"
	// ContextEvent is for factory trigger conditions over one forge delivery.
	ContextEvent Context = "event"
	// ContextCVE is for detection rule feed selectors.
	ContextCVE Context = "cve"
)

// Contexts lists every context in documentation order.
func Contexts() []Context {
	return []Context{ContextFinding, ContextPackage, ContextRequest, ContextEvent, ContextCVE}
}

// CEL type names used in the tables.
const (
	typeString     = "string"
	typeDouble     = "double"
	typeInt        = "int"
	typeBool       = "bool"
	typeTimestamp  = "timestamp"
	typeStringList = "list(string)"
	typeStringMap  = "map(string, list(string))"
	// typeLabelMap is a map of string to string, such as a repository's labels.
	typeLabelMap = "map(string, string)"
)

// String bounds. The estimated cost of an expression is computed from them,
// so they are upper bounds an input must respect, not hints: Eval refuses an
// input that exceeds one rather than run past the estimate plan approved.
const (
	lenEnum = 64
	lenID   = 256
	lenName = 512
	lenPurl = 2048
	lenPath = 1024
)

// Variable describes one variable of a context.
type Variable struct {
	Name string
	// Type is the CEL type: string, double, int, bool, timestamp,
	// list(string) or map(string, list(string)).
	Type string
	Doc  string
	// Derived variables are computed from the input, not set by the caller.
	Derived bool
	// MaxLen bounds each string, in code points: the value itself, each list
	// item, or each map key and value item.
	MaxLen int
	// MaxItems bounds a list's items or a map's keys.
	MaxItems int
	// MaxValueItems bounds each value list of a map(string, list(string)).
	MaxValueItems int
}

// nowVar is in every context, so a rule can compare a timestamp with the time
// of evaluation instead of a date written into the rule.
var nowVar = Variable{Name: "now", Type: typeTimestamp, Doc: "The time of evaluation. Callers may fix it; otherwise it is the clock when Eval runs."}

var variables = map[Context][]Variable{
	// cli/internal/scan.EnrichedVuln and the saas Finding model, with the
	// filters the campaign scope (vdb-site handler/campaign_spec.go) already
	// selects on.
	ContextFinding: {
		{Name: "id", Type: typeString, MaxLen: lenID, Doc: "The advisory identifier, such as `CVE-2024-3094` or a GHSA ID."},
		{Name: "aliases", Type: typeStringList, MaxLen: lenID, MaxItems: 64, Doc: "Other identifiers the advisory is known by."},
		{Name: "severity", Type: typeString, MaxLen: lenEnum, Doc: "Lower case: `critical`, `high`, `medium`, `low`, or empty when unknown."},
		{Name: "cvss", Type: typeDouble, Doc: "CVSS base score, 0 to 10. 0 when unscored."},
		{Name: "epss", Type: typeDouble, Doc: "EPSS probability, 0 to 1."},
		{Name: "epssPercentile", Type: typeDouble, Doc: "EPSS percentile, 0 to 1."},
		{Name: "kev", Type: typeBool, Doc: "Listed in any known-exploited catalogue: CISA KEV, VulnCheck KEV or EU KEV."},
		{Name: "exploitMaturity", Type: typeString, MaxLen: lenEnum, Doc: "The highest exploit tier, as the CLI `--exploits` gate grades it: `poc`, `active`, `weaponized`, or empty when none is known."},
		{Name: "exploitCount", Type: typeInt, Doc: "Number of public exploits known."},
		{Name: "reachability", Type: typeString, MaxLen: lenEnum, Doc: "Lower case reachability verdict: `direct`, `transitive`, `semantic`, `unreachable`, or empty when not assessed."},
		{Name: "reachable", Type: typeBool, Derived: true, Doc: "True when `reachability` is `direct`, `transitive` or `semantic`, the same set the findings page counts as reachable."},
		{Name: "internetExposed", Type: typeBool, Doc: "The package is observed on internet-facing infrastructure."},
		{Name: "eol", Type: typeBool, Doc: "The package version is end of life."},
		{Name: "malicious", Type: typeBool, Doc: "The package is known malware."},
		{Name: "fixAvailability", Type: typeString, MaxLen: lenEnum, Doc: "`available`, `partial`, `no_fix`, or empty when unknown."},
		{Name: "direct", Type: typeBool, Doc: "The package is a direct dependency, not a transitive one."},
		{Name: "purl", Type: typeString, MaxLen: lenPurl, Doc: "Package URL of the affected package, with version."},
		{Name: "ecosystem", Type: typeString, MaxLen: lenEnum, Doc: "Package ecosystem, such as `npm`, `pypi`, `golang`, `maven`."},
		{Name: "cwe", Type: typeStringList, MaxLen: lenEnum, MaxItems: 64, Doc: "CWE identifiers, upper case with prefix: `CWE-79`."},
		{Name: "repo", Type: typeString, MaxLen: lenName, Doc: "Repository full name, `owner/name`."},
		{Name: "branch", Type: typeString, MaxLen: lenName, Doc: "Branch the finding was scanned on."},
		{Name: "path", Type: typeString, MaxLen: lenPath, Doc: "File the finding came from, such as the manifest or lock file, relative to the repository root."},
		{Name: "labels", Type: typeLabelMap, MaxLen: lenID, MaxItems: 50, Doc: "The key/value labels of the repository the finding is in, as set on the repository's asset record or in a RepositorySettings document: `labels['tier'] == 'prod'`. Empty when the repository has none, and in a runtime that does not know the repository's asset record, so `'tier' in labels` is false there."},
		{Name: "owner", Type: typeString, MaxLen: lenName, Doc: "Who owns the repository: a team name, a user name or an email address, as set on its asset record. Empty when none is set."},
		{Name: "criticality", Type: typeString, MaxLen: lenEnum, Doc: "How much the business depends on the repository: `low`, `medium`, `high` or `critical`. Empty when none is set, so `criticality in ['high', 'critical']` is false for an unclassified repository."},
		nowVar,
	},
	// package-firewall internal/policy.Signal and internal/types.OrgConfig.
	ContextPackage: {
		{Name: "purl", Type: typeString, MaxLen: lenPurl, Doc: "Package URL of the requested version."},
		{Name: "ecosystem", Type: typeString, MaxLen: lenEnum, Doc: "Package ecosystem, such as `npm`, `pypi`, `golang`, `maven`."},
		{Name: "name", Type: typeString, MaxLen: lenName, Doc: "Package name as the ecosystem writes it: `@acme/tool`, `github.com/acme/tool`, `com.acme:tool`."},
		{Name: "version", Type: typeString, MaxLen: lenID, Doc: "Requested version."},
		{Name: "published", Type: typeTimestamp, Doc: "When the version was published. The zero timestamp when unknown."},
		{Name: "ageDays", Type: typeInt, Derived: true, Doc: "Whole days from `published` to `now`. -1 when the publish time is unknown, so a cooldown rule never reads an unknown age as new."},
		{Name: "versionLag", Type: typeInt, Doc: "How many releases are newer than this version. 0 for the newest, or when the lag is unknown."},
		{Name: "malware", Type: typeBool, Doc: "The version is known malware."},
		{Name: "cvss", Type: typeDouble, Doc: "Highest CVSS base score across the version's advisories."},
		{Name: "epss", Type: typeDouble, Doc: "Highest EPSS probability across the version's advisories."},
		{Name: "cess", Type: typeDouble, Doc: "Highest Coalition ESS score across the version's advisories."},
		{Name: "kev", Type: typeBool, Doc: "An advisory for the version is in a known-exploited catalogue."},
		{Name: "eol", Type: typeBool, Doc: "The version is end of life."},
		{Name: "exploitMaturity", Type: typeString, MaxLen: lenEnum, Doc: "`poc`, `active`, `weaponized`, or empty when no exploit is known."},
		{Name: "badActor", Type: typeBool, Doc: "The publisher is a known bad actor."},
		nowVar,
	},
	// ai-firewall internal/policy.Input: the client identity and the
	// capabilities (tools, MCP servers, skills) the capability rules match.
	ContextRequest: {
		{Name: "provider", Type: typeString, MaxLen: lenID, Doc: "Provider slug, such as `anthropic` or `openai`."},
		{Name: "model", Type: typeString, MaxLen: lenID, Doc: "Model slug as requested."},
		{Name: "client", Type: typeString, MaxLen: lenID, Doc: "Calling client's name, such as `claude-code` or `codex`."},
		{Name: "tools", Type: typeStringList, MaxLen: lenID, MaxItems: 512, Doc: "Tool names the request declares or calls, including flattened MCP tools such as `mcp__github__create_issue`."},
		{Name: "mcpServers", Type: typeStringList, MaxLen: lenID, MaxItems: 128, Doc: "Labels of the remote MCP servers the request wires in."},
		{Name: "skills", Type: typeStringList, MaxLen: lenID, MaxItems: 256, Doc: "Skill names the request offers."},
		nowVar,
	},
	// vdb-site handler/factory_engine_events.go FactoryGithubEvent.
	ContextEvent: {
		{Name: "event", Type: typeString, MaxLen: lenEnum, Doc: "Trigger event name, such as `pull_request.opened` or `push`."},
		{Name: "base", Type: typeString, MaxLen: lenEnum, Doc: "The event name before the first dot, such as `pull_request`. Derived from `event` when not sent."},
		{Name: "action", Type: typeString, MaxLen: lenEnum, Doc: "The event name after the first dot, such as `opened`. Empty for `push`."},
		{Name: "repo", Type: typeString, MaxLen: lenName, Doc: "`owner/name` on github.com, `host/owner/name` on other forges."},
		{Name: "number", Type: typeInt, Doc: "Pull request or issue number, 0 when there is none."},
		{Name: "subject", Type: typeString, MaxLen: lenID, Doc: "What the delivery is about: `pr:7`, `issue:12`, `release:v1.2.3`, or empty."},
		{Name: "ref", Type: typeString, MaxLen: lenName, Doc: "The pushed ref, for `push`."},
		{Name: "headBranch", Type: typeString, MaxLen: lenName, Doc: "Branch the change is on."},
		{Name: "baseBranch", Type: typeString, MaxLen: lenName, Doc: "Pull request target branch; the pushed branch for `push`."},
		{Name: "defaultBranch", Type: typeString, MaxLen: lenName, Doc: "Repository default branch."},
		{Name: "author", Type: typeString, MaxLen: lenID, Doc: "Pull request author, pusher, comment author or run actor."},
		{Name: "authorType", Type: typeString, MaxLen: lenEnum, Doc: "`user` or `bot`."},
		{Name: "sender", Type: typeString, MaxLen: lenID, Doc: "The delivery's sender."},
		{Name: "senderType", Type: typeString, MaxLen: lenEnum, Doc: "`user` or `bot`."},
		{Name: "labels", Type: typeStringList, MaxLen: lenID, MaxItems: 100, Doc: "Labels on the pull request or issue."},
		{Name: "draft", Type: typeBool, Doc: "The pull request is a draft."},
		{Name: "origin", Type: typeString, MaxLen: lenEnum, Doc: "`same_repo` or `fork`. An empty origin reads as `same_repo`."},
		{Name: "conclusion", Type: typeString, MaxLen: lenEnum, Doc: "Conclusion of a check run, check suite or workflow run, or a deployment state: `success`, `failure`, `cancelled` and so on."},
		{Name: "reviewState", Type: typeString, MaxLen: lenEnum, Doc: "`approved`, `changes_requested`, `dismissed` or `commented` on `pull_request_review`."},
		{Name: "paths", Type: typeStringList, MaxLen: lenPath, MaxItems: 1000, Doc: "Paths a push added, modified or removed. A caller with more than the bound sends the first 1000 and sets `pathsTruncated`."},
		{Name: "pathsTruncated", Type: typeBool, Doc: "`paths` is partial."},
		{Name: "deleted", Type: typeBool, Doc: "The push deleted its ref."},
		{Name: "severity", Type: typeString, MaxLen: lenEnum, Doc: "Lower case alert severity on `dependabot_alert`, `code_scanning_alert` and `posture_finding`."},
		{Name: "environment", Type: typeString, MaxLen: lenName, Doc: "Deployment environment on `deployment_status`."},
		{Name: "packageType", Type: typeString, MaxLen: lenEnum, Doc: "Published package type on `registry_package`: `container`, `npm`, `maven` and so on."},
		{Name: "properties", Type: typeStringMap, MaxLen: lenID, MaxItems: 100, MaxValueItems: 50, Doc: "Repository custom property values, by property name."},
		nowVar,
	},
	// saas VirtualPatch (confidence, falsePositiveRisk, kind) and the CVE it
	// covers. Values are upper case because that is how they are stored.
	ContextCVE: {
		{Name: "id", Type: typeString, MaxLen: lenID, Doc: "CVE identifier."},
		{Name: "cvss", Type: typeDouble, Doc: "CVSS base score, 0 to 10. 0 when unscored."},
		{Name: "epss", Type: typeDouble, Doc: "EPSS probability, 0 to 1."},
		{Name: "kev", Type: typeBool, Doc: "Listed in a known-exploited catalogue."},
		{Name: "published", Type: typeTimestamp, Doc: "When the CVE was published. The zero timestamp when unknown."},
		{Name: "kind", Type: typeString, MaxLen: lenEnum, Doc: "Rule format: `SNORT`, `SURICATA`, `MODSECURITY`, `NGINX`, `AWS_WAF`, `CLOUDFLARE_WAF`, `REGEX_L7`, `SIGMA`, `YARA`, `STIX`, `OPENIOC`."},
		{Name: "confidence", Type: typeString, MaxLen: lenEnum, Doc: "Confidence in the rule: `HIGH`, `MEDIUM`, `LOW`, or empty."},
		{Name: "falsePositiveRisk", Type: typeString, MaxLen: lenEnum, Doc: "`HIGH`, `MEDIUM`, `LOW`, or empty."},
		nowVar,
	},
}

// Variables returns a context's variables in documentation order, or nil for
// an unknown context.
func Variables(ctx Context) []Variable {
	vs, ok := variables[ctx]
	if !ok {
		return nil
	}
	out := make([]Variable, len(vs))
	copy(out, vs)
	return out
}

func lookupVar(ctx Context, name string) (Variable, bool) {
	for _, v := range variables[ctx] {
		if v.Name == name {
			return v, true
		}
	}
	return Variable{}, false
}
