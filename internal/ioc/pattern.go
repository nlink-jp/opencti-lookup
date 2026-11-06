package ioc

import "strings"

// PatternLiterals returns every single-quoted string literal in a STIX 2.1
// pattern, unescaped. A comparison's right-hand side is always such a literal
// (`[ipv4-addr:value = '192.0.2.10']`, `IN ('a', 'b')`), and so is a hash
// algorithm name in a property path (`hashes.'SHA-256'`), which is harmless
// here: it never equals an indicator value.
//
// The indicator path of a lookup fetches candidates whose pattern merely
// contains the value (`contains` matches substrings, Phase 0 record §3), then
// keeps those with a literal equivalent to the input. ok is false when a
// quote is left open — the pattern is not STIX and cannot be read exactly.
func PatternLiterals(pattern string) (literals []string, ok bool) {
	var b strings.Builder
	in, escaped := false, false
	for _, r := range pattern {
		switch {
		case !in:
			if r == '\'' {
				in = true
				b.Reset()
			}
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '\'':
			literals = append(literals, b.String())
			in = false
		default:
			b.WriteRune(r)
		}
	}
	return literals, !in
}

// PatternMatch reports whether a STIX pattern compares against this value, and
// the literal it compares against.
func (v Value) PatternMatch(pattern string) (literal string, ok bool) {
	lits, readable := PatternLiterals(pattern)
	if !readable {
		return "", false
	}
	for _, l := range lits {
		if v.Equivalent(l) {
			return l, true
		}
	}
	return "", false
}
