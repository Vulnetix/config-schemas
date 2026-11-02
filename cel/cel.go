// Package cel compiles and evaluates the CEL (https://cel.dev) expressions in
// Vulnetix config documents: the `when` of gate, jail, prioritisation and
// suppression rules, package firewall and AI firewall rules, factory trigger
// conditions and detection rule feed selectors.
//
// Each rule context has its own typed environment (see Variables), so plan
// rejects an expression that names a variable its context does not have, or
// compares a score with a string, before anything is applied. The CLI and the
// server both use this package, and both run the golden vectors in
// testdata/vectors, so a rule gives the same answer wherever it is evaluated.
//
// Every expression is bounded three ways: its length, its estimated cost at
// compile time, and its actual cost at evaluation. The estimate is computed
// from the variable bounds in the tables, and Eval refuses an input outside
// them, so an expression plan accepted cannot cost more than plan said.
package cel

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
)

const (
	// MaxExpressionLength is the longest expression, in bytes. It matches
	// celExpression.maxLength in schemas/common.schema.json.
	MaxExpressionLength = 4096
	// MaxCost bounds both the estimated cost at compile time and the actual
	// cost at evaluation. It is the per-expression limit Kubernetes applies
	// to admission policy CEL, which these rules may one day be rendered to.
	MaxCost = 1_000_000
)

// Error codes. They are part of the vector format, so they are stable across
// cel-go versions where the messages are not.
const (
	CodeLength     = "length"      // the expression is longer than MaxExpressionLength
	CodeSyntax     = "syntax"      // the expression does not parse
	CodeType       = "type"        // it parses but does not type-check
	CodeResultType = "result_type" // it type-checks to something other than bool
	CodeCost       = "cost"        // estimated or actual cost exceeds MaxCost
	CodeContext    = "context"     // unknown context, or an input of the wrong context
	CodeInput      = "input"       // the input exceeds a variable's bounds
	CodeEval       = "eval"        // evaluation failed, such as a bad purl or division by zero
)

// Issue is one problem with an expression. Line and Column are 1-based and
// zero when the problem has no position, such as an excessive cost.
type Issue struct {
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

// Error is what Compile and Eval return. Code says which kind of failure it
// is; Issues carry positions for syntax and type errors.
type Error struct {
	Code   string  `json:"code"`
	Issues []Issue `json:"issues"`
}

func (e *Error) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		if is.Line > 0 {
			parts[i] = fmt.Sprintf("%d:%d: %s", is.Line, is.Column, is.Message)
		} else {
			parts[i] = is.Message
		}
	}
	return e.Code + ": " + strings.Join(parts, "; ")
}

func newError(code, format string, args ...any) *Error {
	return &Error{Code: code, Issues: []Issue{{Message: fmt.Sprintf(format, args...)}}}
}

func issuesError(code string, iss *celgo.Issues) *Error {
	e := &Error{Code: code}
	for _, ce := range iss.Errors() {
		is := Issue{Message: ce.Message}
		if loc := ce.Location; loc != nil && loc.Line() > 0 {
			is.Line, is.Column = loc.Line(), loc.Column()+1
		}
		e.Issues = append(e.Issues, is)
	}
	if len(e.Issues) == 0 {
		e.Issues = []Issue{{Message: iss.String()}}
	}
	return e
}

var (
	envOnce sync.Once
	envs    map[Context]*celgo.Env
	envErr  error
)

func env(ctx Context) (*celgo.Env, error) {
	envOnce.Do(func() {
		envs = map[Context]*celgo.Env{}
		for _, c := range Contexts() {
			e, err := newEnv(c)
			if err != nil {
				envErr = fmt.Errorf("cel: building the %s environment: %w", c, err)
				return
			}
			envs[c] = e
		}
	})
	if envErr != nil {
		return nil, envErr
	}
	e, ok := envs[ctx]
	if !ok {
		return nil, newError(CodeContext, "unknown context %q", ctx)
	}
	return e, nil
}

func newEnv(ctx Context) (*celgo.Env, error) {
	opts := []celgo.EnvOption{
		// `cvss >= 7` is what everyone writes; without this it is a type
		// error because 7 is an int and cvss a double.
		celgo.CrossTypeNumericComparisons(true),
		celgo.ParserExpressionSizeLimit(MaxExpressionLength),
	}
	for _, v := range variables[ctx] {
		t, err := celType(v.Type)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", v.Name, err)
		}
		opts = append(opts, celgo.Variable(v.Name, t))
	}
	opts = append(opts, functionOptions()...)
	return celgo.NewEnv(opts...)
}

func celType(t string) (*celgo.Type, error) {
	switch t {
	case typeString:
		return celgo.StringType, nil
	case typeDouble:
		return celgo.DoubleType, nil
	case typeInt:
		return celgo.IntType, nil
	case typeBool:
		return celgo.BoolType, nil
	case typeTimestamp:
		return celgo.TimestampType, nil
	case typeStringList:
		return celgo.ListType(celgo.StringType), nil
	case typeStringMap:
		return celgo.MapType(celgo.StringType, celgo.ListType(celgo.StringType)), nil
	}
	return nil, fmt.Errorf("unknown type %q", t)
}

// Program is a compiled, type-checked expression. It is safe for concurrent
// use; compile once and evaluate many times.
type Program struct {
	ctx  Context
	expr string
	cost Cost
	prg  celgo.Program
	// limit is the runtime cost limit, for the error message.
	limit uint64
}

// Cost is an expression's estimated cost range.
type Cost struct {
	Min uint64 `json:"min"`
	Max uint64 `json:"max"`
}

// Compile parses and type-checks expr in ctx. It fails when the expression is
// too long, does not parse, does not type-check, does not return bool, or
// could cost more than MaxCost on an input within the variable bounds. The
// error is always an *Error.
func Compile(ctx Context, expr string) (*Program, error) {
	return compile(ctx, expr, MaxCost)
}

// compile takes the runtime limit separately so a test can prove the runtime
// limit fires; in production it is always MaxCost.
func compile(ctx Context, expr string, runtimeLimit uint64) (*Program, error) {
	e, err := env(ctx)
	if err != nil {
		return nil, err
	}
	if len(expr) > MaxExpressionLength {
		return nil, newError(CodeLength, "expression is %d bytes, longer than the %d allowed", len(expr), MaxExpressionLength)
	}
	parsed, iss := e.Parse(expr)
	if iss.Err() != nil {
		return nil, issuesError(CodeSyntax, iss)
	}
	checked, iss := e.Check(parsed)
	if iss.Err() != nil {
		return nil, issuesError(CodeType, iss)
	}
	if out := checked.OutputType(); !out.IsExactType(celgo.BoolType) {
		return nil, newError(CodeResultType, "expression returns %s, not bool", out)
	}
	est, err := e.EstimateCost(checked, sizeEstimator{ctx: ctx})
	if err != nil {
		return nil, newError(CodeCost, "estimating cost: %v", err)
	}
	if est.Max > MaxCost {
		return nil, newError(CodeCost, "estimated cost %d exceeds the limit of %d; the usual causes are a comprehension nested in another and a regex over a long string", est.Max, MaxCost)
	}
	prg, err := e.Program(checked,
		celgo.CostLimit(runtimeLimit),
		celgo.CostTracking(runtimeCost{}),
		celgo.EvalOptions(celgo.OptOptimize),
	)
	if err != nil {
		return nil, newError(CodeType, "%v", err)
	}
	return &Program{ctx: ctx, expr: expr, cost: Cost{Min: est.Min, Max: est.Max}, prg: prg, limit: runtimeLimit}, nil
}

// Check compiles expr and returns only the error, for plan and validate.
func Check(ctx Context, expr string) error {
	_, err := Compile(ctx, expr)
	return err
}

// Context is the program's rule context.
func (p *Program) Context() Context { return p.ctx }

// Expression is the source text.
func (p *Program) Expression() string { return p.expr }

// Cost is the estimated cost range from compile time.
func (p *Program) Cost() Cost { return p.cost }

// Eval evaluates the program against an input of its context. The error is
// always an *Error.
func (p *Program) Eval(in Input) (bool, error) {
	if in == nil {
		return false, newError(CodeContext, "no input")
	}
	if in.Context() != p.ctx {
		return false, newError(CodeContext, "expression is for %s, input is a %s", p.ctx, in.Context())
	}
	vars := in.vars(time.Now().UTC())
	if err := checkBounds(p.ctx, vars); err != nil {
		return false, err
	}
	out, _, err := p.prg.Eval(vars)
	if err != nil {
		var cancelled interpreter.EvalCancelledError
		if errors.As(err, &cancelled) && cancelled.Cause == interpreter.CostLimitExceeded {
			return false, newError(CodeCost, "actual cost exceeded the limit of %d", p.limit)
		}
		return false, newError(CodeEval, "%v", err)
	}
	b, ok := out.(types.Bool)
	if !ok {
		// Unreachable for a checked bool program; kept so a cel-go change
		// fails loudly instead of reading as false.
		return false, newError(CodeEval, "expression returned %v, not bool", out.Type())
	}
	return bool(b), nil
}

// checkBounds refuses an input outside the variable bounds the cost estimate
// assumed.
func checkBounds(ctx Context, vars map[string]any) error {
	tooLong := func(name, s string, max int) error {
		if n := utf8.RuneCountInString(s); n > max {
			return newError(CodeInput, "%s: a value of %d characters is longer than the %d allowed", name, n, max)
		}
		return nil
	}
	for _, v := range variables[ctx] {
		switch val := vars[v.Name].(type) {
		case string:
			if err := tooLong(v.Name, val, v.MaxLen); err != nil {
				return err
			}
		case []string:
			if len(val) > v.MaxItems {
				return newError(CodeInput, "%s: %d items, more than the %d allowed", v.Name, len(val), v.MaxItems)
			}
			for _, s := range val {
				if err := tooLong(v.Name, s, v.MaxLen); err != nil {
					return err
				}
			}
		case map[string][]string:
			if len(val) > v.MaxItems {
				return newError(CodeInput, "%s: %d keys, more than the %d allowed", v.Name, len(val), v.MaxItems)
			}
			for k, list := range val {
				if err := tooLong(v.Name, k, v.MaxLen); err != nil {
					return err
				}
				if len(list) > v.MaxValueItems {
					return newError(CodeInput, "%s[%q]: %d items, more than the %d allowed", v.Name, k, len(list), v.MaxValueItems)
				}
				for _, s := range list {
					if err := tooLong(v.Name, s, v.MaxLen); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
