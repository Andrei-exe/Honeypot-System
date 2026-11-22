package vfs

import (
	"strconv"
	"strings"
)

// arith evaluates $((...)) like ash's math.c (BusyBox 1.30.1, with Buildroot's SH_MATH_64): 64-bit
// integers that wrap around, the C operators with C's precedence, ** , ?: , the comma, assignments
// (x=5, x+=2, x++) and variables whose value is itself an expression (X=5+1; $((X*2)) = 12).
// Returns the value, or ash's error message ("divide by zero", "arithmetic syntax error"...).
func (s *Shell) arith(expr string) (int64, string) {
	if strings.TrimSpace(expr) == "" {
		return 0, "" // $(( )) = 0
	}
	c := &calc{s: s, text: expr, steps: new(int)}
	v := c.comma(true)
	if c.skip(); c.err == "" && c.pos < len(c.text) {
		c.err = "arithmetic syntax error"
	}
	return v, c.err
}

// calc reads one expression. eval = false: the part is skipped (the other side of && || ?:), so
// it can't divide by zero or assign anything.
type calc struct {
	s     *Shell
	text  string
	pos   int
	err   string
	depth int // variables holding expressions, read inside each other: X=X would never end
	// operands read so far, shared with those variables: X='Y+Y' Y='Z+Z' ... doubles at each name,
	// and 40 of them would keep the CPU busy for hours (ash too: it would hang that shell)
	steps *int
}

const maxCalcSteps = 100000

// binaryOps: the two-character operators first, so "<=" isn't read as "<" then "=".
var binaryOps = []struct {
	op   string
	prec int // higher binds tighter
}{
	{"||", 1}, {"&&", 2}, {"==", 6}, {"!=", 6}, {"<=", 7}, {">=", 7}, {"<<", 8}, {">>", 8}, {"**", 11},
	{"|", 3}, {"^", 4}, {"&", 5}, {"<", 7}, {">", 7}, {"+", 9}, {"-", 9}, {"*", 10}, {"/", 10}, {"%", 10},
}

var assignOps = []string{"<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=", "="}

func (c *calc) skip() {
	for c.pos < len(c.text) && strings.IndexByte(" \t\n", c.text[c.pos]) >= 0 {
		c.pos++
	}
}

func (c *calc) fail(msg string) int64 {
	if c.err == "" {
		c.err = msg
	}
	return 0
}

// next reports whether the text continues with op (after spaces).
func (c *calc) next(op string) bool {
	c.skip()
	return strings.HasPrefix(c.text[c.pos:], op)
}

func (c *calc) name() string {
	start := c.pos
	if c.pos < len(c.text) && isNameStart(c.text[c.pos]) {
		for c.pos < len(c.text) && isNameChar(c.text[c.pos]) {
			c.pos++
		}
	}
	return c.text[start:c.pos]
}

// comma: "a, b" is b
func (c *calc) comma(eval bool) int64 {
	v := c.assign(eval)
	for c.err == "" && c.next(",") {
		c.pos++
		v = c.assign(eval)
	}
	return v
}

// assign: NAME = ..., NAME += ... (right to left, like C); anything else is a ?: expression.
func (c *calc) assign(eval bool) int64 {
	start := c.pos
	c.skip()
	if name := c.name(); name != "" {
		c.skip()
		rest := c.text[c.pos:]
		for _, op := range assignOps {
			if strings.HasPrefix(rest, op) && !strings.HasPrefix(rest, "==") {
				c.pos += len(op)
				v := c.assign(eval)
				if c.err != "" {
					return 0
				}
				if op != "=" {
					v = c.apply(op[:len(op)-1], c.variable(name, eval), v, eval)
				}
				c.store(name, v, eval)
				return v
			}
		}
	}
	c.pos = start
	return c.ternary(eval)
}

func (c *calc) ternary(eval bool) int64 {
	cond := c.binary(1, eval)
	if c.err != "" || !c.next("?") {
		return cond
	}
	c.pos++
	yes := c.comma(eval && cond != 0)
	if c.err != "" {
		return 0
	}
	if !c.next(":") {
		return c.fail("malformed ?: operator")
	}
	c.pos++
	no := c.ternary(eval && cond == 0)
	if cond != 0 {
		return yes
	}
	return no
}

// operator reads the binary operator ahead, if any ("+=" is an assignment's, not "+").
func (c *calc) operator() (string, int) {
	c.skip()
	rest := c.text[c.pos:]
	for _, b := range binaryOps {
		if !strings.HasPrefix(rest, b.op) {
			continue
		}
		for _, a := range assignOps {
			if a != "=" && strings.HasPrefix(rest, a) && len(a) > len(b.op) {
				return "", 0
			}
		}
		return b.op, b.prec
	}
	return "", 0
}

// binary reads operands joined by operators that bind at least as tight as min.
func (c *calc) binary(min int, eval bool) int64 {
	left := c.unary(eval)
	for c.err == "" {
		op, prec := c.operator()
		if op == "" || prec < min {
			break
		}
		c.pos += len(op)
		switch op {
		case "&&": // the right side only counts (and only runs) if it can change the result
			right := c.binary(prec+1, eval && left != 0)
			left = boolInt(left != 0 && right != 0)
		case "||":
			right := c.binary(prec+1, eval && left == 0)
			left = boolInt(left != 0 || right != 0)
		default:
			next := prec + 1
			if op == "**" {
				next = prec // 2**3**2 = 2**(3**2)
			}
			left = c.apply(op, left, c.binary(next, eval), eval)
		}
	}
	return left
}

// unary: - + ! ~ ++x --x, a number, a variable (x++ x--) or ( ... ). -2**2 = 4, like ash.
func (c *calc) unary(eval bool) int64 {
	c.skip()
	if c.pos == len(c.text) {
		return c.fail("arithmetic syntax error")
	}
	*c.steps++
	c.s.work-- // and the line's budget, shared with globs and ${X#p}
	if *c.steps > maxCalcSteps || c.s.work < 0 {
		return c.fail("expression recursion loop detected")
	}
	if rest := c.text[c.pos:]; strings.HasPrefix(rest, "++") || strings.HasPrefix(rest, "--") {
		start := c.pos
		c.pos += 2
		c.skip()
		if name := c.name(); name != "" { // ++x: changed, then read
			v := c.variable(name, eval) + 1
			if rest[0] == '-' {
				v -= 2
			}
			c.store(name, v, eval)
			return v
		}
		c.pos = start // "--2": two minus signs
	}
	switch ch := c.text[c.pos]; {
	case strings.IndexByte("-+!~", ch) >= 0:
		c.pos++
		v := c.unary(eval)
		switch ch {
		case '-':
			return -v
		case '!':
			return boolInt(v == 0)
		case '~':
			return ^v
		}
		return v
	case ch == '(':
		c.pos++
		v := c.comma(eval)
		if c.err == "" && !c.next(")") {
			return c.fail("arithmetic syntax error")
		}
		c.pos++
		return v
	case ch >= '0' && ch <= '9':
		return c.number()
	}
	name := c.name()
	if name == "" {
		return c.fail("arithmetic syntax error")
	}
	v := c.variable(name, eval)
	if rest := c.text[c.pos:]; strings.HasPrefix(rest, "++") || strings.HasPrefix(rest, "--") {
		c.pos += 2 // x++: read, then changed
		if rest[0] == '+' {
			c.store(name, v+1, eval)
		} else {
			c.store(name, v-1, eval)
		}
	}
	return v
}

// number: 42, 0x2a (hex), 052 (octal; "08" is an error, like in ash).
func (c *calc) number() int64 {
	start := c.pos
	for c.pos < len(c.text) && isNameChar(c.text[c.pos]) {
		c.pos++
	}
	digits, base := c.text[start:c.pos], 10
	switch {
	case len(digits) > 1 && (digits[1] == 'x' || digits[1] == 'X') && digits[0] == '0':
		digits, base = digits[2:], 16
	case len(digits) > 1 && digits[0] == '0':
		digits, base = digits[1:], 8
	}
	v, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return c.fail("arithmetic syntax error")
	}
	return int64(v)
}

// variable reads a variable: empty or unset = 0, anything else is evaluated (X=abc reads abc).
// Each read counts as a step: A='A%=A%=I' reads A twice at each level (2^100 reads before the
// depth limit), so after an error nothing more is read.
func (c *calc) variable(name string, eval bool) int64 {
	value, _ := c.s.lookup(name)
	if !eval || c.err != "" || strings.TrimSpace(value) == "" {
		return 0
	}
	*c.steps++
	c.s.work--
	if c.depth >= 100 || *c.steps > maxCalcSteps || c.s.work < 0 {
		return c.fail("expression recursion loop detected")
	}
	inner := &calc{s: c.s, text: value, depth: c.depth + 1, steps: c.steps}
	v := inner.comma(true)
	if inner.skip(); inner.err == "" && inner.pos < len(inner.text) {
		inner.err = "arithmetic syntax error"
	}
	if inner.err != "" {
		return c.fail(inner.err)
	}
	return v
}

func (c *calc) store(name string, v int64, eval bool) {
	if eval && c.err == "" {
		if msg := c.s.setVar(name, strconv.FormatInt(v, 10)); msg != "" {
			c.fail(msg)
		}
	}
}

// apply computes l op r. Shifts use the low 6 bits of r and overflow wraps, like C on the router.
func (c *calc) apply(op string, l, r int64, eval bool) int64 {
	switch op {
	case "+":
		return l + r
	case "-":
		return l - r
	case "*":
		return l * r
	case "/", "%":
		if r == 0 {
			if eval {
				return c.fail("divide by zero")
			}
			return 0
		}
		if op == "/" {
			return l / r // Go, like the CPU, gives the smallest int64 for its / -1 (no crash)
		}
		return l % r
	case "**":
		if r < 0 {
			if eval {
				return c.fail("exponent less than 0")
			}
			return 0
		}
		result := int64(1)
		for ; r > 0; r >>= 1 { // by squaring: 2**1000000000000 must not loop that many times
			if r&1 == 1 {
				result *= l
			}
			l *= l
		}
		return result
	case "<<":
		return l << (uint64(r) & 63)
	case ">>":
		return l >> (uint64(r) & 63)
	case "<":
		return boolInt(l < r)
	case "<=":
		return boolInt(l <= r)
	case ">":
		return boolInt(l > r)
	case ">=":
		return boolInt(l >= r)
	case "==":
		return boolInt(l == r)
	case "!=":
		return boolInt(l != r)
	case "&":
		return l & r
	case "^":
		return l ^ r
	case "|":
		return l | r
	}
	return c.fail("arithmetic syntax error")
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func isNameStart(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isNameChar(c byte) bool  { return isNameStart(c) || c >= '0' && c <= '9' }
