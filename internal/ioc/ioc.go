// Package ioc classifies an indicator value and lists the forms in which
// OpenCTI may have stored it.
//
// OpenCTI does not canonicalize values when it stores them (Phase 0 record §3):
// an IPv6 address stored expanded does not match its canonical form, and a
// SHA-256 is found under hashes.SHA-256, never under value. So a lookup asks
// for every form the value could have been stored in, and maps what comes
// back to the input by equivalence, not by string equality. OpenCTI itself
// matches case-insensitively, URL paths included.
package ioc

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

// Kind is what a value is.
type Kind string

const (
	IPv4   Kind = "ipv4"
	IPv6   Kind = "ipv6"
	Domain Kind = "domain"
	URL    Kind = "url"
	Email  Kind = "email"
	MD5    Kind = "md5"
	SHA1   Kind = "sha1"
	SHA256 Kind = "sha256"
	SHA512 Kind = "sha512"
)

// MaxValueLength bounds one input value.
const MaxValueLength = 2048

// Value is one classified input.
type Value struct {
	Input string // as given, trimmed
	Kind  Kind
	// Key is the observable filter key: "value", or "hashes.<algorithm>".
	Key string
	// Forms are the values to ask for, the input first, without duplicates.
	Forms []string
	// ObservableType is OpenCTI's entity type for this kind.
	ObservableType string
}

// ErrInvalid wraps every classification failure.
var ErrInvalid = errors.New("not a recognised indicator value")

// Classify reads one value. The order matters: a hash or an IP is tested before
// a domain, because "deadbeef…" and "1.2.3.4" would otherwise pass as names.
func Classify(raw string) (Value, error) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return Value{}, fmt.Errorf("%w: empty", ErrInvalid)
	case len(s) > MaxValueLength:
		return Value{}, fmt.Errorf("%w: longer than %d bytes", ErrInvalid, MaxValueLength)
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0:
		return Value{}, fmt.Errorf("%w: %q holds whitespace or a control character", ErrInvalid, s)
	}

	if v, ok := classifyIP(s); ok {
		return v, nil
	}
	if k, ok := hashKind(s); ok {
		lower := strings.ToLower(s)
		return Value{Input: s, Kind: k, Key: "hashes." + hashAlgorithm(k), Forms: dedupe(s, lower), ObservableType: "StixFile"}, nil
	}
	if strings.Contains(s, "://") {
		if !validURL(s) {
			return Value{}, fmt.Errorf("%w: %q looks like a URL but has no host", ErrInvalid, s)
		}
		return Value{Input: s, Kind: URL, Key: "value", Forms: []string{s}, ObservableType: "Url"}, nil
	}
	if local, domain, ok := strings.Cut(s, "@"); ok {
		if local == "" || !validDomain(domain) || strings.Contains(domain, "@") {
			return Value{}, fmt.Errorf("%w: %q is not an email address", ErrInvalid, s)
		}
		return Value{Input: s, Kind: Email, Key: "value", Forms: dedupe(s, strings.ToLower(s)), ObservableType: "Email-Addr"}, nil
	}
	if validDomain(s) {
		lower := strings.ToLower(s)
		return Value{Input: s, Kind: Domain, Key: "value",
			Forms: dedupe(s, lower, strings.TrimSuffix(lower, ".")), ObservableType: "Domain-Name"}, nil
	}
	return Value{}, fmt.Errorf("%w: %q (expected an IP address or CIDR, a domain, a URL with a scheme, an email address, or an MD5/SHA-1/SHA-256/SHA-512 hash)", ErrInvalid, s)
}

func classifyIP(s string) (Value, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		kind, typ := IPv4, "IPv4-Addr"
		if p.Addr().Is6() {
			kind, typ = IPv6, "IPv6-Addr"
		}
		forms := []string{s, p.String()}
		if kind == IPv6 {
			forms = append(forms, fmt.Sprintf("%s/%d", p.Addr().StringExpanded(), p.Bits()))
		}
		return Value{Input: s, Kind: kind, Key: "value", Forms: dedupe(forms...), ObservableType: typ}, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return Value{}, false
	}
	if a.Is4() {
		return Value{Input: s, Kind: IPv4, Key: "value", Forms: dedupe(s, a.String()), ObservableType: "IPv4-Addr"}, true
	}
	return Value{Input: s, Kind: IPv6, Key: "value", Forms: dedupe(s, a.String(), a.StringExpanded()), ObservableType: "IPv6-Addr"}, true
}

func hashKind(s string) (Kind, bool) {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return "", false
		}
	}
	switch len(s) {
	case 32:
		return MD5, true
	case 40:
		return SHA1, true
	case 64:
		return SHA256, true
	case 128:
		return SHA512, true
	}
	return "", false
}

func hashAlgorithm(k Kind) string {
	switch k {
	case MD5:
		return "MD5"
	case SHA1:
		return "SHA-1"
	case SHA256:
		return "SHA-256"
	}
	return "SHA-512"
}

func validURL(s string) bool {
	scheme, rest, _ := strings.Cut(s, "://")
	if scheme == "" || strings.IndexFunc(scheme, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')
	}) >= 0 {
		return false
	}
	host := rest
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	return host != ""
}

// validDomain accepts a name with at least two labels whose last label is not
// all digits. Labels are letters (any script), digits, hyphens and
// underscores; a trailing dot is allowed. It is a sieve against typos, not a
// registry check: OpenCTI stores what feeds sent.
func validDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	labels := strings.Split(s, ".")
	if len(labels) < 2 || len(s) > 253 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, r := range l {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	return strings.IndexFunc(tld, func(r rune) bool { return !unicode.IsDigit(r) }) >= 0
}

func dedupe(values ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Equivalent reports whether a stored value is this input in another form:
// the same IP or network, or the same text ignoring case (OpenCTI's own
// matching, which also ignores case in URL paths).
func (v Value) Equivalent(stored string) bool {
	stored = strings.TrimSpace(stored)
	switch v.Kind {
	case IPv4, IPv6:
		return sameIP(v.Input, stored)
	case Domain:
		return strings.EqualFold(strings.TrimSuffix(v.Input, "."), strings.TrimSuffix(stored, "."))
	}
	return strings.EqualFold(v.Input, stored)
}

func sameIP(a, b string) bool {
	if pa, err := netip.ParsePrefix(a); err == nil {
		pb, err := netip.ParsePrefix(b)
		return err == nil && pa == pb
	}
	aa, err1 := netip.ParseAddr(a)
	ab, err2 := netip.ParseAddr(b)
	return err1 == nil && err2 == nil && aa == ab
}

// Match describes how a stored value relates to the input.
type Match string

const (
	MatchExact      Match = "exact"      // stored exactly as given
	MatchEquivalent Match = "equivalent" // the same value in another form (case, IP notation)
)

// MatchOf classifies a stored value already known to be Equivalent.
func (v Value) MatchOf(stored string) Match {
	if strings.TrimSpace(stored) == v.Input {
		return MatchExact
	}
	return MatchEquivalent
}
