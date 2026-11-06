package ioc

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	sha256 := "491fc027d8e22a569e67a40c16b98c93a4586c5421b18894cdd5c40201277d20"
	cases := []struct {
		in    string
		kind  Kind
		key   string
		forms []string
		typ   string
	}{
		{"192.0.2.10", IPv4, "value", []string{"192.0.2.10"}, "IPv4-Addr"},
		{" 192.0.2.10 ", IPv4, "value", []string{"192.0.2.10"}, "IPv4-Addr"},
		{"192.0.2.0/24", IPv4, "value", []string{"192.0.2.0/24"}, "IPv4-Addr"},
		{"2001:db8::10", IPv6, "value", []string{"2001:db8::10", "2001:0db8:0000:0000:0000:0000:0000:0010"}, "IPv6-Addr"},
		// Stored expanded upper-case (Phase 0: ioc-ipv6-stored-expanded-*): the
		// input form, the canonical and the expanded are all asked for.
		{"2001:0DB8:0000:0000:0000:0000:0000:0020", IPv6, "value",
			[]string{"2001:0DB8:0000:0000:0000:0000:0000:0020", "2001:db8::20", "2001:0db8:0000:0000:0000:0000:0000:0020"}, "IPv6-Addr"},
		{"2001:db8::/32", IPv6, "value", []string{"2001:db8::/32", "2001:0db8:0000:0000:0000:0000:0000:0000/32"}, "IPv6-Addr"},
		{"bad.example.com", Domain, "value", []string{"bad.example.com"}, "Domain-Name"},
		{"BAD.Example.COM.", Domain, "value", []string{"BAD.Example.COM.", "bad.example.com.", "bad.example.com"}, "Domain-Name"},
		{"例え.テスト", Domain, "value", []string{"例え.テスト"}, "Domain-Name"},
		{"http://bad.example.com/PAYLOAD.BIN", URL, "value", []string{"http://bad.example.com/PAYLOAD.BIN"}, "Url"},
		{"phisher@example.net", Email, "value", []string{"phisher@example.net"}, "Email-Addr"},
		{strings.ToUpper(sha256), SHA256, "hashes.SHA-256", []string{strings.ToUpper(sha256), sha256}, "StixFile"},
		{strings.Repeat("a", 32), MD5, "hashes.MD5", []string{strings.Repeat("a", 32)}, "StixFile"},
		{strings.Repeat("b", 40), SHA1, "hashes.SHA-1", []string{strings.Repeat("b", 40)}, "StixFile"},
		{strings.Repeat("c", 128), SHA512, "hashes.SHA-512", []string{strings.Repeat("c", 128)}, "StixFile"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			v, err := Classify(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if v.Kind != c.kind || v.Key != c.key || v.ObservableType != c.typ || !reflect.DeepEqual(v.Forms, c.forms) {
				t.Fatalf("got %+v", v)
			}
		})
	}
}

func TestClassifyRefuses(t *testing.T) {
	for _, in := range []string{
		"", "   ", "localhost", "192.0.2.10 192.0.2.11", "a\tb", "x\x00y",
		"fe80::1%en0", "010.0.0.1", "1.2.3.4.5", strings.Repeat("a", 31),
		"ftp:///nohost", "@example.com", "a@b", "-bad.example.com", "example.123",
		strings.Repeat("a", MaxValueLength+1),
	} {
		t.Run(in, func(t *testing.T) {
			if v, err := Classify(in); err == nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("Classify(%q) = %+v, %v; want ErrInvalid", in, v, err)
			}
		})
	}
}

func TestEquivalentAndMatch(t *testing.T) {
	v6, _ := Classify("2001:db8::20")
	for stored, want := range map[string]bool{
		"2001:0DB8:0000:0000:0000:0000:0000:0020": true,
		"2001:db8::20": true,
		"2001:db8::21": false,
		"not-an-ip":    false,
	} {
		if v6.Equivalent(stored) != want {
			t.Errorf("Equivalent(%q) != %v", stored, want)
		}
	}
	if v6.MatchOf("2001:db8::20") != MatchExact || v6.MatchOf("2001:0DB8:0000:0000:0000:0000:0000:0020") != MatchEquivalent {
		t.Error("MatchOf")
	}

	u, _ := Classify("http://bad.example.com/PAYLOAD.BIN")
	if !u.Equivalent("http://bad.example.com/payload.bin") || u.MatchOf("http://bad.example.com/payload.bin") != MatchEquivalent {
		t.Error("a URL stored in another case must be equivalent, and reported as such")
	}
	d, _ := Classify("bad.example.com.")
	if !d.Equivalent("BAD.EXAMPLE.COM") {
		t.Error("domain trailing dot and case")
	}
	n, _ := Classify("192.0.2.0/24")
	if !n.Equivalent("192.0.2.0/24") || n.Equivalent("192.0.2.0/25") || n.Equivalent("192.0.2.0") {
		t.Error("prefix equivalence")
	}
}

func TestPatternLiterals(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
		ok      bool
	}{
		{"[ipv4-addr:value = '192.0.2.10']", []string{"192.0.2.10"}, true},
		{"[file:hashes.'SHA-256' = 'abc'] OR [domain-name:value = 'x.example']", []string{"SHA-256", "abc", "x.example"}, true},
		{"[url:value IN ('a', 'b\\'c')]", []string{"a", "b'c"}, true},
		{"[x:value = 'back\\\\slash']", []string{"back\\slash"}, true},
		{"rule yara_rule { strings: $a = \"orphan.example.org\" }", nil, true},
		{"[x:value = 'unterminated", nil, false},
	}
	for _, c := range cases {
		got, ok := PatternLiterals(c.pattern)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("PatternLiterals(%q) = %q, %v; want %q, %v", c.pattern, got, ok, c.want, c.ok)
		}
	}
}

func TestPatternMatchRejectsSubstrings(t *testing.T) {
	v, _ := Classify("orphan.example.org")
	if l, ok := v.PatternMatch("[domain-name:value = 'orphan.example.org']"); !ok || l != "orphan.example.org" {
		t.Fatal("exact literal not matched")
	}
	if l, ok := v.PatternMatch("[domain-name:value = 'ORPHAN.example.org']"); !ok || l != "ORPHAN.example.org" {
		t.Fatal("case-folded literal not matched")
	}
	// contains("orphan.example") returned this indicator in Phase 0; the exact
	// check must drop the converse case.
	sub, _ := Classify("orphan.example")
	if _, ok := sub.PatternMatch("[domain-name:value = 'orphan.example.org']"); ok {
		t.Fatal("a substring was accepted as a match")
	}
	ip, _ := Classify("192.0.2.1")
	if _, ok := ip.PatternMatch("[ipv4-addr:value = '192.0.2.10']"); ok {
		t.Fatal("an IP prefix was accepted as a match")
	}
}
