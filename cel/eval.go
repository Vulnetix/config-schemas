package cel

import "sync"

// DefaultCacheSize is how many compiled programs the package cache holds
// before it starts again. A tenant's rules number in the tens; the bound only
// stops a stream of distinct expressions from growing memory without limit.
const DefaultCacheSize = 4096

// Cache compiles each (context, expression) pair once and keeps the result,
// including a compile error, so a runtime that evaluates the same stored rule
// on every request pays for parsing, type-checking and the cost estimate
// once. It is safe for concurrent use.
//
// When it is full it is emptied rather than evicting one entry at a time:
// the working set of a runtime is small, refilling it is cheap, and no
// bookkeeping is done on the hot path.
type Cache struct {
	max int
	mu  sync.RWMutex
	m   map[cacheKey]cacheEntry
}

type cacheKey struct {
	ctx  Context
	expr string
}

type cacheEntry struct {
	prg *Program
	err error
}

// NewCache returns a cache that holds at most max programs. max <= 0 means
// DefaultCacheSize.
func NewCache(max int) *Cache {
	if max <= 0 {
		max = DefaultCacheSize
	}
	return &Cache{max: max, m: map[cacheKey]cacheEntry{}}
}

// Program returns the compiled program for expr in ctx, compiling it on first
// use. The error is the one Compile returned, always an *Error.
func (c *Cache) Program(ctx Context, expr string) (*Program, error) {
	k := cacheKey{ctx, expr}
	c.mu.RLock()
	e, ok := c.m[k]
	c.mu.RUnlock()
	if ok {
		return e.prg, e.err
	}
	prg, err := Compile(ctx, expr)
	if err != nil {
		// Keep the typed nil out of the interface so callers can test
		// err == nil.
		e = cacheEntry{err: err}
	} else {
		e = cacheEntry{prg: prg}
	}
	c.mu.Lock()
	if len(c.m) >= c.max {
		c.m = map[cacheKey]cacheEntry{}
	}
	c.m[k] = e
	c.mu.Unlock()
	return e.prg, e.err
}

// Eval compiles expr in the input's context (once) and evaluates it.
func (c *Cache) Eval(expr string, in Input) (bool, error) {
	if in == nil {
		return false, newError(CodeContext, "no input")
	}
	prg, err := c.Program(in.Context(), expr)
	if err != nil {
		return false, err
	}
	return prg.Eval(in)
}

// Len is the number of programs held.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

var shared = NewCache(DefaultCacheSize)

// Eval evaluates expr against in through the package-wide cache. Use it, or
// one of the typed helpers below, wherever a stored rule is evaluated; use
// Compile directly only to check an expression.
func Eval(expr string, in Input) (bool, error) { return shared.Eval(expr, in) }

// EvalFinding evaluates a finding rule: a jail, quality gate, prioritisation
// or suppression `when`.
func EvalFinding(expr string, f Finding) (bool, error) { return shared.Eval(expr, f) }

// EvalPackage evaluates a package firewall rule.
func EvalPackage(expr string, p Package) (bool, error) { return shared.Eval(expr, p) }

// EvalRequest evaluates an AI firewall guardrail condition.
func EvalRequest(expr string, r Request) (bool, error) { return shared.Eval(expr, r) }

// EvalEvent evaluates a factory trigger condition.
func EvalEvent(expr string, e Event) (bool, error) { return shared.Eval(expr, e) }

// EvalCVE evaluates a detection rule feed selector.
func EvalCVE(expr string, c CVE) (bool, error) { return shared.Eval(expr, c) }
