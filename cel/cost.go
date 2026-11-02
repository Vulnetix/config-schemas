package cel

import (
	"math"
	"unicode/utf8"

	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// sizeEstimator tells the cost checker how big each variable can be, from the
// bounds in the context's table. Without it every string and list is of
// unknown size, the estimate saturates, and no comprehension could pass.
type sizeEstimator struct {
	ctx Context
}

func (e sizeEstimator) EstimateSize(node checker.AstNode) *checker.SizeEstimate {
	path := node.Path()
	if len(path) == 0 {
		return nil
	}
	v, ok := lookupVar(e.ctx, path[0])
	if !ok {
		return nil
	}
	var max int
	switch {
	case len(path) == 1 && v.Type == typeString:
		max = v.MaxLen
	case len(path) == 1:
		max = v.MaxItems
	case v.Type == typeStringList && len(path) == 2 && path[1] == "@items":
		max = v.MaxLen
	case v.Type == typeStringMap && len(path) == 2 && path[1] == "@keys":
		max = v.MaxLen
	case v.Type == typeStringMap && len(path) == 2 && path[1] == "@values":
		max = v.MaxValueItems
	case v.Type == typeStringMap && len(path) == 3 && path[1] == "@values" && path[2] == "@items":
		max = v.MaxLen
	default:
		return nil
	}
	if max == 0 {
		return nil
	}
	return &checker.SizeEstimate{Min: 0, Max: uint64(max)}
}

func (e sizeEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	operands := args
	if target != nil {
		operands = append([]checker.AstNode{*target}, args...)
	}
	sizes := make([]checker.SizeEstimate, len(operands))
	for i, n := range operands {
		sizes[i] = e.size(n)
	}
	var est checker.CostEstimate
	switch overloadID {
	case overloadGlob:
		est = checker.CostEstimate{Min: globCost(sizes[0].Min, sizes[1].Min), Max: globCost(sizes[0].Max, sizes[1].Max)}
	case overloadMatchesPurl, overloadSemverCompare:
		est = checker.CostEstimate{Min: linearCost(sizes[0].Min + sizes[1].Min), Max: linearCost(sizes[0].Max + sizes[1].Max)}
	case overloadIsSemver:
		est = checker.CostEstimate{Min: linearCost(sizes[0].Min), Max: linearCost(sizes[0].Max)}
	default:
		return nil
	}
	return &checker.CallEstimate{CostEstimate: est}
}

func (e sizeEstimator) size(n checker.AstNode) checker.SizeEstimate {
	if s := n.ComputedSize(); s != nil {
		return *s
	}
	if s := e.EstimateSize(n); s != nil {
		return *s
	}
	return checker.UnknownSizeEstimate()
}

// globCost charges a glob like CEL charges `matches`, since it is one: the
// string's traversal times a per-pattern factor, O(n*m) as RE2 is.
func globCost(strLen, patLen uint64) uint64 {
	str := factorCost(sat(strLen, 1), common.StringTraversalCostFactor)
	pat := factorCost(patLen, common.RegexStringLengthCostFactor)
	if pat == 0 {
		pat = 1
	}
	return sat(1, satMul(str, pat))
}

// linearCost is one call plus a traversal of its string operands.
func linearCost(n uint64) uint64 {
	return sat(1, factorCost(n, common.StringTraversalCostFactor))
}

func factorCost(n uint64, f float64) uint64 {
	c := math.Ceil(float64(n) * f)
	if c >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(c)
}

func sat(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}

// runtimeCost charges the custom functions at evaluation by the same formula
// the estimate used, on the actual sizes, so the runtime limit and the
// estimate measure the same thing.
type runtimeCost struct{}

func (runtimeCost) CallCost(function, overloadID string, args []ref.Val, result ref.Val) *uint64 {
	strLen := func(i int) uint64 {
		if i >= len(args) {
			return 0
		}
		if s, ok := args[i].(types.String); ok {
			return uint64(utf8.RuneCountInString(string(s)))
		}
		return 0
	}
	var c uint64
	switch overloadID {
	case overloadGlob:
		c = globCost(strLen(0), strLen(1))
	case overloadMatchesPurl, overloadSemverCompare:
		c = linearCost(strLen(0) + strLen(1))
	case overloadIsSemver:
		c = linearCost(strLen(0))
	default:
		return nil
	}
	return &c
}
