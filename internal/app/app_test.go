package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/mcp"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// hostile is third-party text that tries to drive the terminal: an escape
// sequence, a right-to-left override and a lone carriage return.
const hostile = "evil\x1b[2J\u202ename\rforged"

type stub struct {
	err    error
	lookup *engine.LookupResult
	status *engine.Status
	got    []string
}

func (s *stub) LookupIOC(_ context.Context, v []string) (*engine.LookupResult, error) {
	s.got = v
	if s.lookup != nil {
		return s.lookup, s.err
	}
	return &engine.LookupResult{Results: []engine.IOCResult{{Input: v[0], Found: true,
		Observables: []engine.Observable{{Type: "IPv4-Addr", Value: hostile, Markings: []string{"TLP:GREEN"}}}}}}, s.err
}
func (s *stub) SearchThreats(_ context.Context, q string, types []string, limit int) (*engine.SearchResult, error) {
	s.got = append([]string{q}, types...)
	return &engine.SearchResult{Query: q, Mode: "exact", Rows: []engine.ThreatRow{{Ref: engine.Ref{Name: hostile}, Excerpt: hostile}}}, s.err
}
func (s *stub) GetEntity(_ context.Context, id string) (*engine.Entity, error) {
	s.got = []string{id}
	return &engine.Entity{Ref: engine.Ref{ID: id, Name: "N"}, Description: "line1\nline2" + hostile}, s.err
}
func (s *stub) GetRelated(_ context.Context, q engine.RelatedQuery) (*engine.RelatedResult, error) {
	s.got = append([]string{q.ID}, append(q.RelationshipTypes, q.TargetTypes...)...)
	return &engine.RelatedResult{Of: engine.Ref{ID: q.ID}, Rows: []engine.RelatedRow{{Relationship: "uses", Direction: "outgoing"}},
		Page: engine.Page{Total: 3, Returned: 1, Remaining: 2, NextCursor: "CUR"}}, s.err
}
func (s *stub) GetReports(_ context.Context, id string, limit int, cursor string) (*engine.ReportsResult, error) {
	s.got = []string{id, cursor}
	return &engine.ReportsResult{Of: engine.Ref{ID: id}}, s.err
}
func (s *stub) ServerStatus(context.Context) *engine.Status {
	if s.status != nil {
		return s.status
	}
	return &engine.Status{Version: "6.7.4", VerifiedVersion: "6.7.4", VersionMatches: true, ConfigFile: "(none)"}
}

// setup isolates the config and installs the stub; it returns a runner.
func setup(t *testing.T, s *stub) func(args ...string) (int, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("OPENCTI_LOOKUP_URL", "https://cti.example")
	t.Setenv("OPENCTI_LOOKUP_TOKEN", "t")
	for _, v := range []string{"OPENCTI_LOOKUP_CA_FILE", "OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY", "OPENCTI_LOOKUP_TIMEOUT_SECONDS"} {
		t.Setenv(v, "")
	}
	prev := newEngine
	newEngine = func(*config.Config) mcp.Engine { return s }
	t.Cleanup(func() { newEngine = prev })
	return func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(args, "v1.2.3", strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}
}

func TestVersionBannersAreIdentical(t *testing.T) {
	r := setup(t, &stub{})
	c1, a, _ := r("--version")
	c2, b, _ := r("version")
	if c1 != 0 || c2 != 0 || a != b || !strings.HasPrefix(a, "opencti-lookup v1.2.3\n") {
		t.Fatalf("%q vs %q", a, b)
	}
}

func TestDispatch(t *testing.T) {
	r := setup(t, &stub{})
	if code, _, _ := r(); code != exitError {
		t.Error("no command")
	}
	if code, _, errs := r("frobnicate"); code != exitError || !strings.Contains(errs, "unknown command") {
		t.Error("unknown command")
	}
	if code, out, _ := r("help"); code != exitOK || !strings.Contains(out, "Exit codes") {
		t.Error("help")
	}
	if code, _, _ := r("ioc"); code != exitError {
		t.Error("ioc without values")
	}
	if code, _, _ := r("entity", "a", "b"); code != exitError {
		t.Error("entity with two ids")
	}
	if code, _, _ := r("status", "extra"); code != exitError {
		t.Error("status with an argument")
	}
	if code, _, errs := r("ioc", "192.0.2.10", "--timeout", "0.5"); code != exitError || !strings.Contains(errs, "--timeout") {
		t.Error("fractional timeout")
	}
}

func TestFlagsAfterArguments(t *testing.T) {
	s := &stub{}
	r := setup(t, s)
	code, out, _ := r("ioc", "192.0.2.10", "--json", "bad.example.com")
	if code != exitOK || !strings.HasPrefix(strings.TrimSpace(out), "{") || strings.Join(s.got, ",") != "192.0.2.10,bad.example.com" {
		t.Fatalf("code %d got %v out %q", code, s.got, out)
	}
	r("related", "ID", "--relationship", "uses", "--target-type", "Malware", "--target-type", "Tool")
	if strings.Join(s.got, ",") != "ID,uses,Malware,Tool" {
		t.Fatalf("related got %v", s.got)
	}
	_, out, _ = r("related", "ID")
	if !strings.Contains(out, "--cursor CUR") {
		t.Fatalf("the continuation is not printed: %q", out)
	}
}

func TestTextIsInert(t *testing.T) {
	r := setup(t, &stub{})
	for _, args := range [][]string{{"ioc", "192.0.2.10"}, {"search", "x"}, {"entity", "x"}} {
		_, out, _ := r(args...)
		if strings.ContainsAny(out, "\x1b\r\u202e") {
			t.Errorf("%v printed a raw control: %q", args, out)
		}
		if !strings.Contains(out, `\x1b`) {
			t.Errorf("%v: the escape is not shown: %q", args, out)
		}
	}
	_, out, _ := r("entity", "x")
	if !strings.Contains(out, "| line1\n") || !strings.Contains(out, "| line2") {
		t.Errorf("a description keeps its lines behind the gutter: %q", out)
	}
	_, js, _ := r("ioc", "192.0.2.10", "--json")
	if strings.ContainsAny(js, "\x1b\r\u202e") || !strings.Contains(js, `\u202e`) {
		t.Errorf("JSON carries a raw control: %q", js)
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{&engine.Error{Code: engine.CodeInvalidArgument, Message: "bad"}, exitError},
		{&opencti.Error{Code: opencti.CodeAuthFailed, Message: "token"}, exitError},
		{&opencti.Error{Code: opencti.CodeForbidden, Message: "no"}, exitError},
		{&opencti.Error{Code: opencti.CodeUnreachable, Message: "down"}, exitUpstream},
		{&opencti.Error{Code: opencti.CodeQueryRejected, Message: "version"}, exitUpstream},
	}
	for _, c := range cases {
		r := setup(t, &stub{err: c.err})
		if code, _, errs := r("search", "x"); code != c.code || !strings.Contains(errs, c.err.Error()) {
			t.Errorf("%v: exit %d (%q)", c.err, code, errs)
		}
	}
	r := setup(t, &stub{err: &engine.Error{Code: engine.CodeNotFound, Message: "no object"}})
	if code, out, _ := r("entity", "x"); code != exitOK || !strings.Contains(out, "no object") {
		t.Errorf("not_found is an answer: %d %q", code, out)
	}
	r = setup(t, &stub{lookup: &engine.LookupResult{Results: []engine.IOCResult{{Input: "192.0.2.1", Inconclusive: true, Note: "cut"}}}})
	if code, out, _ := r("ioc", "192.0.2.1"); code != exitUpstream || !strings.Contains(out, "INCONCLUSIVE") {
		t.Errorf("inconclusive: %d %q", code, out)
	}
}

func TestStatusExit(t *testing.T) {
	r := setup(t, &stub{status: &engine.Status{Error: &engine.StatusError{Code: opencti.CodeAuthFailed, Message: "refused"}}})
	if code, out, _ := r("status"); code != exitError || !strings.Contains(out, "auth_failed") {
		t.Errorf("%d %q", code, out)
	}
	r = setup(t, &stub{status: &engine.Status{Error: &engine.StatusError{Code: opencti.CodeUnreachable, Message: "down"}}})
	if code, _, _ := r("status"); code != exitUpstream {
		t.Errorf("unreachable: %d", code)
	}
}

func TestConfigWarningsAndErrors(t *testing.T) {
	r := setup(t, &stub{})
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte("[opencti]\ntoken = \"t\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := r("status", "--config", p); code != exitOK || !strings.Contains(errs, "Warning: config file "+p+" has permissions 0644") {
		t.Errorf("%d %q", code, errs)
	}
	if code, _, errs := r("status", "-c", filepath.Join(t.TempDir(), "missing.toml")); code != exitError || !strings.Contains(errs, "does not exist") {
		t.Errorf("%d %q", code, errs)
	}
}

func TestMCPCommand(t *testing.T) {
	setup(t, &stub{})
	var out, errb bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	if code := run([]string{"mcp"}, "v9", in, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"version":"v9"`) {
		t.Fatalf("%q", out.String())
	}
	if code := run([]string{"mcp", "extra"}, "v9", strings.NewReader(""), &out, &errb); code != exitError {
		t.Fatal("mcp with an argument")
	}
}
