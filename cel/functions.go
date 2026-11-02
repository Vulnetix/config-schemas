package cel

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// The functions every context adds to standard CEL. Each exists because the
// rule it serves cannot be written correctly with the standard library:
//
//	glob          the one glob dialect factory triggers already use for
//	              branches, paths and logins; a regex would need escaping
//	              that rule authors get wrong.
//	matchesPurl   the package firewall's namespace rule, which a prefix test
//	              gets wrong ("@acme" also prefixes "@acme-evil").
//	semverCompare semantic version order; string comparison sorts 1.10 before 1.9.
//	isSemver      a guard, because semverCompare refuses what is not semver.
//
// The standard function `matches` is a regex test, which is why the purl
// function is not called `matches`: CEL cannot overload a member function on
// the same argument types.

// Overload IDs, also the keys of the cost functions in cost.go.
const (
	overloadGlob          = "string_glob_string"
	overloadMatchesPurl   = "string_matchesPurl_string"
	overloadSemverCompare = "semverCompare_string_string"
	overloadIsSemver      = "isSemver_string"
)

// Function documents one custom function for the README and cmd/celdoc.
type Function struct {
	Signature string
	Doc       string
}

// Functions lists the custom functions, available in every context.
func Functions() []Function {
	return []Function{
		{"`string.glob(pattern string) bool`", "Glob match over the whole string. `*` is any run of characters except `/`, `**` is any run including `/`, `**/` is zero or more directories, `?` is one character except `/`. Everything else is literal. The same dialect as factory trigger conditions."},
		{"`string.matchesPurl(pattern string) bool`", "Package URL match. The pattern is a purl: without a version it matches every version, with one it matches that version only. A pattern whose name ends in `/*` or `:*` matches every package under that namespace, as package firewall allow entries do: `pkg:npm/@acme/*` covers `pkg:npm/@acme/tool@1.0.0` but not `pkg:npm/@acme-evil/tool`. Qualifiers and subpaths are ignored. Names compare as written. An invalid purl or pattern is an evaluation error."},
		{"`semverCompare(a string, b string) int`", "-1, 0 or 1 as `a` is lower than, equal to or higher than `b` in semantic version order. Precedence follows SemVer 2.0.0: pre-releases rank below the release and build metadata is ignored. A leading `v` is optional; the shorthands `1` and `1.2` are not versions. A value that is not a semantic version is an evaluation error; guard with `isSemver`."},
		{"`isSemver(v string) bool`", "Whether `v` is a semantic version, with or without a leading `v`."},
	}
}

func functionOptions() []celgo.EnvOption {
	return []celgo.EnvOption{
		celgo.Function("glob",
			celgo.MemberOverload(overloadGlob, []*celgo.Type{celgo.StringType, celgo.StringType}, celgo.BoolType,
				celgo.BinaryBinding(func(s, pat ref.Val) ref.Val {
					return types.Bool(globMatch(string(s.(types.String)), string(pat.(types.String))))
				}))),
		celgo.Function("matchesPurl",
			celgo.MemberOverload(overloadMatchesPurl, []*celgo.Type{celgo.StringType, celgo.StringType}, celgo.BoolType,
				celgo.BinaryBinding(func(p, pat ref.Val) ref.Val {
					ok, err := purlMatches(string(p.(types.String)), string(pat.(types.String)))
					if err != nil {
						return types.NewErr("matchesPurl: %v", err)
					}
					return types.Bool(ok)
				}))),
		celgo.Function("semverCompare",
			celgo.Overload(overloadSemverCompare, []*celgo.Type{celgo.StringType, celgo.StringType}, celgo.IntType,
				celgo.BinaryBinding(func(a, b ref.Val) ref.Val {
					va, oka := parseSemver(string(a.(types.String)))
					vb, okb := parseSemver(string(b.(types.String)))
					if !oka {
						return types.NewErr("semverCompare: %q is not a semantic version", string(a.(types.String)))
					}
					if !okb {
						return types.NewErr("semverCompare: %q is not a semantic version", string(b.(types.String)))
					}
					return types.Int(va.compare(vb))
				}))),
		celgo.Function("isSemver",
			celgo.Overload(overloadIsSemver, []*celgo.Type{celgo.StringType}, celgo.BoolType,
				celgo.UnaryBinding(func(v ref.Val) ref.Val {
					_, ok := parseSemver(string(v.(types.String)))
					return types.Bool(ok)
				}))),
	}
}

// ── semver ───────────────────────────────────────────────────────────────

// semVersion is a parsed Semantic Versioning 2.0.0 version. It is written out
// here rather than taken from golang.org/x/mod/semver, whose recent releases
// pull the go directive past the 1.25 this module promises its importers, and
// which also accepts the shorthands v1 and v1.2 that SemVer does not.
type semVersion struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver(s string) (semVersion, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		// Build metadata does not take part in precedence (SemVer 10).
		if !validIdents(s[i+1:], false) {
			return semVersion{}, false
		}
		s = s[:i]
	}
	var v semVersion
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre {
		if !validIdents(pre, true) {
			return semVersion{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	nums := strings.Split(core, ".")
	if len(nums) != 3 {
		return semVersion{}, false
	}
	for i, n := range nums {
		x, ok := numericIdent(n)
		if !ok {
			return semVersion{}, false
		}
		switch i {
		case 0:
			v.major = x
		case 1:
			v.minor = x
		default:
			v.patch = x
		}
	}
	return v, true
}

// numericIdent parses a numeric identifier: digits, no leading zero.
func numericIdent(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	x, err := strconv.ParseUint(s, 10, 64)
	return x, err == nil
}

// validIdents checks dot-separated identifiers of [0-9A-Za-z-]. Numeric
// pre-release identifiers may not have leading zeros; build ones may.
func validIdents(s string, pre bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		digits := true
		for _, c := range id {
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				digits = false
			default:
				return false
			}
		}
		if pre && digits && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// compare orders by SemVer precedence (SemVer 11).
func (a semVersion) compare(b semVersion) int {
	for _, d := range [][2]uint64{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	// A version without a pre-release ranks above one with.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xn, xok := numericIdent(x)
		yn, yok := numericIdent(y)
		switch {
		case xok && yok:
			if xn < yn {
				return -1
			}
			return 1
		case xok:
			return -1 // numeric identifiers rank below alphanumeric ones
		case yok:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// ── glob ─────────────────────────────────────────────────────────────────

// globCacheMax bounds the compiled-pattern cache. Patterns are almost always
// literals in the rule, so a few hundred cover every rule an org has; past the
// bound a pattern is compiled per call rather than letting a pattern built from
// input grow the cache without limit.
const globCacheMax = 1024

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// globRE compiles a glob in the dialect of vdb-site's feGlobRE
// (handler/factory_trigger_conditions.go). It must stay identical to it: a
// trigger condition and a CEL rule over the same branch must agree.
func globRE(pat string) *regexp.Regexp {
	globMu.Lock()
	re, ok := globCache[pat]
	globMu.Unlock()
	if ok {
		return re
	}
	var b strings.Builder
	b.WriteString(`^`)
	for i := 0; i < len(pat); {
		switch {
		case strings.HasPrefix(pat[i:], "**/"):
			b.WriteString(`(?:.*/)?`)
			i += 3
		case strings.HasPrefix(pat[i:], "**"):
			b.WriteString(`.*`)
			i += 2
		case pat[i] == '*':
			b.WriteString(`[^/]*`)
			i++
		case pat[i] == '?':
			b.WriteString(`[^/]`)
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(pat[i])))
			i++
		}
	}
	b.WriteString(`$`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		re = nil
	}
	globMu.Lock()
	if len(globCache) < globCacheMax {
		globCache[pat] = re
	}
	globMu.Unlock()
	return re
}

func globMatch(s, pat string) bool {
	re := globRE(pat)
	return re != nil && re.MatchString(s)
}

// ── purl ─────────────────────────────────────────────────────────────────

type purlParts struct {
	typ, name, version string
}

// parsePurl splits a package URL into type, namespace-and-name, and version.
// It is deliberately lenient about encoding: `@acme/tool` and `%40acme/tool`
// are the same name, because people write purls both ways.
func parsePurl(s string) (purlParts, error) {
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		if len(s) >= 4 && strings.EqualFold(s[:4], "pkg:") {
			rest = s[4:]
		} else {
			return purlParts{}, fmt.Errorf("%q is not a package URL: it must start with pkg:", s)
		}
	}
	rest = strings.TrimLeft(rest, "/")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return purlParts{}, fmt.Errorf("%q is not a package URL: it needs a type and a name", s)
	}
	var version string
	if at := strings.LastIndexByte(path, '@'); at > 0 && at > strings.LastIndexByte(path, '/') {
		path, version = path[:at], path[at+1:]
	}
	name, err := url.PathUnescape(path)
	if err != nil {
		return purlParts{}, fmt.Errorf("%q is not a package URL: %v", s, err)
	}
	if version, err = url.PathUnescape(version); err != nil {
		return purlParts{}, fmt.Errorf("%q is not a package URL: %v", s, err)
	}
	return purlParts{typ: strings.ToLower(typ), name: name, version: version}, nil
}

// purlMatches applies a purl pattern; see Functions for the rule.
func purlMatches(purl, pattern string) (bool, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return false, err
	}
	pat, err := parsePurl(pattern)
	if err != nil {
		return false, fmt.Errorf("pattern: %w", err)
	}
	if p.typ != pat.typ {
		return false, nil
	}
	if ns, ok := strings.CutSuffix(pat.name, "*"); ok {
		if ns == "" || (!strings.HasSuffix(ns, "/") && !strings.HasSuffix(ns, ":")) {
			return false, fmt.Errorf("pattern %q: a wildcard must follow / or :", pattern)
		}
		if pat.version != "" {
			return false, fmt.Errorf("pattern %q: a namespace pattern covers every version, so it cannot name one", pattern)
		}
		for _, c := range namespaceCandidates(p.name) {
			if c == pat.name {
				return true, nil
			}
		}
		return false, nil
	}
	if p.name != pat.name {
		return false, nil
	}
	return pat.version == "" || p.version == pat.version, nil
}

// namespaceCandidates is package-firewall internal/types.NamespaceCandidates,
// copied because it is in an internal package of a private module. "a/b/c" yields
// "a/b/*" then "a/*": a namespace ends at "/" or ":", never mid-segment.
func namespaceCandidates(packageName string) []string {
	var out []string
	for i := len(packageName) - 2; i > 0; i-- {
		if c := packageName[i]; c == '/' || c == ':' {
			out = append(out, packageName[:i+1]+"*")
		}
	}
	return out
}
