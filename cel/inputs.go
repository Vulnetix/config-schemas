package cel

import (
	"strings"
	"time"
)

// Input is the typed value one context's expressions are evaluated against.
// Only the structs in this file implement it, so a caller cannot hand a
// finding expression a package by mistake: Eval checks the context first.
type Input interface {
	Context() Context
	// vars renders the input as the activation, including the derived
	// variables, with clock standing in for a zero Now. Its keys are exactly
	// the context's variable names, which TestVariablesMatchInputs holds to.
	vars(clock time.Time) map[string]any
}

// Finding is one vulnerability finding: a CLI scan result
// (cli/internal/scan.EnrichedVuln) or a stored finding (saas Finding).
type Finding struct {
	ID              string   `json:"id" yaml:"id"`
	Aliases         []string `json:"aliases" yaml:"aliases"`
	Severity        string   `json:"severity" yaml:"severity"`
	CVSS            float64  `json:"cvss" yaml:"cvss"`
	EPSS            float64  `json:"epss" yaml:"epss"`
	EPSSPercentile  float64  `json:"epssPercentile" yaml:"epssPercentile"`
	KEV             bool     `json:"kev" yaml:"kev"`
	ExploitMaturity string   `json:"exploitMaturity" yaml:"exploitMaturity"`
	ExploitCount    int      `json:"exploitCount" yaml:"exploitCount"`
	Reachability    string   `json:"reachability" yaml:"reachability"`
	InternetExposed bool     `json:"internetExposed" yaml:"internetExposed"`
	EOL             bool     `json:"eol" yaml:"eol"`
	Malicious       bool     `json:"malicious" yaml:"malicious"`
	FixAvailability string   `json:"fixAvailability" yaml:"fixAvailability"`
	Direct          bool     `json:"direct" yaml:"direct"`
	Purl            string   `json:"purl" yaml:"purl"`
	Ecosystem       string   `json:"ecosystem" yaml:"ecosystem"`
	CWE             []string `json:"cwe" yaml:"cwe"`
	Repo            string   `json:"repo" yaml:"repo"`
	Branch          string   `json:"branch" yaml:"branch"`
	Path            string   `json:"path" yaml:"path"`
	// Now is the evaluation time. Zero means time.Now when Eval runs; vectors
	// set it so they give the same answer on every machine.
	Now time.Time `json:"now" yaml:"now"`
}

// Context implements Input.
func (Finding) Context() Context { return ContextFinding }

func (f Finding) vars(clock time.Time) map[string]any {
	r := strings.ToLower(f.Reachability)
	return map[string]any{
		"id":              f.ID,
		"aliases":         strs(f.Aliases),
		"severity":        f.Severity,
		"cvss":            f.CVSS,
		"epss":            f.EPSS,
		"epssPercentile":  f.EPSSPercentile,
		"kev":             f.KEV,
		"exploitMaturity": f.ExploitMaturity,
		"exploitCount":    int64(f.ExploitCount),
		"reachability":    f.Reachability,
		// The server's reachable filter (vdb-site findings.go reachableExpr)
		// counts DIRECT, TRANSITIVE and SEMANTIC, so this does too: a rule must
		// select the same findings in the CLI as on the findings page.
		"reachable":       r == "direct" || r == "transitive" || r == "semantic",
		"internetExposed": f.InternetExposed,
		"eol":             f.EOL,
		"malicious":       f.Malicious,
		"fixAvailability": f.FixAvailability,
		"direct":          f.Direct,
		"purl":            f.Purl,
		"ecosystem":       f.Ecosystem,
		"cwe":             strs(f.CWE),
		"repo":            f.Repo,
		"branch":          f.Branch,
		"path":            f.Path,
		"now":             orNow(f.Now, clock),
	}
}

// Package is one package version as the package firewall judges it
// (package-firewall internal/policy.Signal plus the request's identity).
type Package struct {
	Purl      string `json:"purl" yaml:"purl"`
	Ecosystem string `json:"ecosystem" yaml:"ecosystem"`
	Name      string `json:"name" yaml:"name"`
	Version   string `json:"version" yaml:"version"`
	// Published is when this version was published. Zero means unknown, and
	// ageDays is then -1 so a cooldown rule cannot mistake it for brand new.
	Published       time.Time `json:"published" yaml:"published"`
	VersionLag      int       `json:"versionLag" yaml:"versionLag"`
	Malware         bool      `json:"malware" yaml:"malware"`
	CVSS            float64   `json:"cvss" yaml:"cvss"`
	EPSS            float64   `json:"epss" yaml:"epss"`
	CESS            float64   `json:"cess" yaml:"cess"`
	KEV             bool      `json:"kev" yaml:"kev"`
	EOL             bool      `json:"eol" yaml:"eol"`
	ExploitMaturity string    `json:"exploitMaturity" yaml:"exploitMaturity"`
	BadActor        bool      `json:"badActor" yaml:"badActor"`
	Now             time.Time `json:"now" yaml:"now"`
}

// Context implements Input.
func (Package) Context() Context { return ContextPackage }

func (p Package) vars(clock time.Time) map[string]any {
	age := int64(-1)
	if !p.Published.IsZero() {
		age = int64(orNow(p.Now, clock).Sub(p.Published) / (24 * time.Hour))
		if age < 0 {
			age = 0
		}
	}
	return map[string]any{
		"purl":            p.Purl,
		"ecosystem":       p.Ecosystem,
		"name":            p.Name,
		"version":         p.Version,
		"published":       p.Published,
		"ageDays":         age,
		"versionLag":      int64(p.VersionLag),
		"malware":         p.Malware,
		"cvss":            p.CVSS,
		"epss":            p.EPSS,
		"cess":            p.CESS,
		"kev":             p.KEV,
		"eol":             p.EOL,
		"exploitMaturity": p.ExploitMaturity,
		"badActor":        p.BadActor,
		"now":             orNow(p.Now, clock),
	}
}

// Request is one model request through the AI firewall
// (ai-firewall internal/policy.Input).
type Request struct {
	Provider   string    `json:"provider" yaml:"provider"`
	Model      string    `json:"model" yaml:"model"`
	Client     string    `json:"client" yaml:"client"`
	Tools      []string  `json:"tools" yaml:"tools"`
	MCPServers []string  `json:"mcpServers" yaml:"mcpServers"`
	Skills     []string  `json:"skills" yaml:"skills"`
	Now        time.Time `json:"now" yaml:"now"`
}

// Context implements Input.
func (Request) Context() Context { return ContextRequest }

func (r Request) vars(clock time.Time) map[string]any {
	return map[string]any{
		"provider":   r.Provider,
		"model":      r.Model,
		"client":     r.Client,
		"tools":      strs(r.Tools),
		"mcpServers": strs(r.MCPServers),
		"skills":     strs(r.Skills),
		"now":        orNow(r.Now, clock),
	}
}

// Event is one forge delivery a factory trigger is judged on. The fields are
// vdb-site's FactoryGithubEvent (handler/factory_engine_events.go), facts
// only: no title, body or comment text reaches an expression.
type Event struct {
	Event          string              `json:"event" yaml:"event"`
	Base           string              `json:"base" yaml:"base"`
	Action         string              `json:"action" yaml:"action"`
	Repo           string              `json:"repo" yaml:"repo"`
	Number         int                 `json:"number" yaml:"number"`
	Subject        string              `json:"subject" yaml:"subject"`
	Ref            string              `json:"ref" yaml:"ref"`
	HeadBranch     string              `json:"headBranch" yaml:"headBranch"`
	BaseBranch     string              `json:"baseBranch" yaml:"baseBranch"`
	DefaultBranch  string              `json:"defaultBranch" yaml:"defaultBranch"`
	Author         string              `json:"author" yaml:"author"`
	AuthorType     string              `json:"authorType" yaml:"authorType"`
	Sender         string              `json:"sender" yaml:"sender"`
	SenderType     string              `json:"senderType" yaml:"senderType"`
	Labels         []string            `json:"labels" yaml:"labels"`
	Draft          bool                `json:"draft" yaml:"draft"`
	Origin         string              `json:"origin" yaml:"origin"`
	Conclusion     string              `json:"conclusion" yaml:"conclusion"`
	ReviewState    string              `json:"reviewState" yaml:"reviewState"`
	Paths          []string            `json:"paths" yaml:"paths"`
	PathsTruncated bool                `json:"pathsTruncated" yaml:"pathsTruncated"`
	Deleted        bool                `json:"deleted" yaml:"deleted"`
	Severity       string              `json:"severity" yaml:"severity"`
	Environment    string              `json:"environment" yaml:"environment"`
	PackageType    string              `json:"packageType" yaml:"packageType"`
	Properties     map[string][]string `json:"properties" yaml:"properties"`
	Now            time.Time           `json:"now" yaml:"now"`
}

// Context implements Input.
func (Event) Context() Context { return ContextEvent }

func (e Event) vars(clock time.Time) map[string]any {
	// Base and action are derived from the event name when left empty, and an
	// empty origin reads as same_repo, exactly as feConditions.match does.
	base, action := e.Base, e.Action
	if b, a, _ := strings.Cut(e.Event, "."); base == "" || action == "" {
		if base == "" {
			base = b
		}
		if action == "" {
			action = a
		}
	}
	origin := e.Origin
	if origin == "" {
		origin = "same_repo"
	}
	props := map[string][]string{}
	for k, v := range e.Properties {
		props[k] = strs(v)
	}
	return map[string]any{
		"event":          e.Event,
		"base":           base,
		"action":         action,
		"repo":           e.Repo,
		"number":         int64(e.Number),
		"subject":        e.Subject,
		"ref":            e.Ref,
		"headBranch":     e.HeadBranch,
		"baseBranch":     e.BaseBranch,
		"defaultBranch":  e.DefaultBranch,
		"author":         e.Author,
		"authorType":     e.AuthorType,
		"sender":         e.Sender,
		"senderType":     e.SenderType,
		"labels":         strs(e.Labels),
		"draft":          e.Draft,
		"origin":         origin,
		"conclusion":     e.Conclusion,
		"reviewState":    e.ReviewState,
		"paths":          strs(e.Paths),
		"pathsTruncated": e.PathsTruncated,
		"deleted":        e.Deleted,
		"severity":       e.Severity,
		"environment":    e.Environment,
		"packageType":    e.PackageType,
		"properties":     props,
		"now":            orNow(e.Now, clock),
	}
}

// CVE is one candidate entry for a detection rule feed: a vulnerability and
// the virtual patch or countermeasure written for it (saas VirtualPatch).
type CVE struct {
	ID                string    `json:"id" yaml:"id"`
	CVSS              float64   `json:"cvss" yaml:"cvss"`
	EPSS              float64   `json:"epss" yaml:"epss"`
	KEV               bool      `json:"kev" yaml:"kev"`
	Published         time.Time `json:"published" yaml:"published"`
	Kind              string    `json:"kind" yaml:"kind"`
	Confidence        string    `json:"confidence" yaml:"confidence"`
	FalsePositiveRisk string    `json:"falsePositiveRisk" yaml:"falsePositiveRisk"`
	Now               time.Time `json:"now" yaml:"now"`
}

// Context implements Input.
func (CVE) Context() Context { return ContextCVE }

func (c CVE) vars(clock time.Time) map[string]any {
	return map[string]any{
		"id":                c.ID,
		"cvss":              c.CVSS,
		"epss":              c.EPSS,
		"kev":               c.KEV,
		"published":         c.Published,
		"kind":              c.Kind,
		"confidence":        c.Confidence,
		"falsePositiveRisk": c.FalsePositiveRisk,
		"now":               orNow(c.Now, clock),
	}
}

// strs turns a nil slice into an empty one, so an absent list is [] in an
// expression rather than a value the adapter has to special-case.
func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// orNow is the input's own Now, or the clock when the caller left it zero.
func orNow(t, clock time.Time) time.Time {
	if t.IsZero() {
		return clock
	}
	return t
}
