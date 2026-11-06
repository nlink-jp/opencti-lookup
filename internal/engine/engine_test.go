package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// fake answers by operation name and records what it was sent. Replies are
// hand-written in the shapes the live tests (e2e/) confirm against 6.7.4.
type fake struct {
	replies map[string]string // operation name -> data JSON
	errs    map[string]error
	calls   []call
}

type call struct {
	op   string
	vars map[string]any
}

func (f *fake) Query(_ context.Context, q string, vars map[string]any, out any) error {
	op := opName(q)
	f.calls = append(f.calls, call{op, vars})
	if err := f.errs[op]; err != nil {
		return err
	}
	data, ok := f.replies[op]
	if !ok {
		return errors.New("fake: no reply for " + op)
	}
	return json.Unmarshal([]byte(data), out)
}

func (f *fake) varsOf(op string) map[string]any {
	for _, c := range f.calls {
		if c.op == op {
			return c.vars
		}
	}
	return nil
}

func opName(q string) string {
	q = strings.TrimSpace(q)
	q = strings.TrimPrefix(q, "query ")
	if i := strings.IndexAny(q, "( {"); i > 0 {
		return q[:i]
	}
	return q
}

func newEngine(f *fake) *Engine {
	return &Engine{Client: f, Cfg: &config.Config{URL: "https://cti.example", Token: "t", DefaultLimit: 25, MaxLimit: 500}}
}

const (
	obs192 = `{"id":"obs-1","standard_id":"ipv4-addr--1","entity_type":"IPv4-Addr","observable_value":"192.0.2.10","x_opencti_score":85,
	  "createdBy":{"name":"Example CERT"},"objectMarking":[{"definition":"TLP:GREEN"}],"objectLabel":[],
	  "containers":{"pageInfo":{"globalCount":12},"edges":[{"node":{"id":"rep-1","entity_type":"Report","representative":{"main":"R1"},"created":"2026-10-01","objectMarking":[{"definition":"TLP:GREEN"}]}}]},
	  "stixCoreRelationships":{"pageInfo":{"globalCount":1},"edges":[{"node":{"id":"r1","relationship_type":"based-on",
	     "from":{"id":"ind-1","entity_type":"Indicator","representative":{"main":"192.0.2.10"}},
	     "to":{"id":"obs-1","entity_type":"IPv4-Addr","representative":{"main":"192.0.2.10"}}}}]},
	  "indicators":{"pageInfo":{"globalCount":1},"edges":[{"node":` + ind192 + `}]}}`
	ind192 = `{"id":"ind-1","standard_id":"indicator--1","name":"192.0.2.10","pattern":"[ipv4-addr:value = '192.0.2.10']","pattern_type":"stix",
	  "valid_from":"2026-09-01","valid_until":"2026-10-01","x_opencti_score":20,"confidence":70,"revoked":true,
	  "decay_base_score":85,"decay_applied_rule":{"decay_lifetime":47},"createdBy":{"name":"Example CERT"},
	  "objectMarking":[{"definition":"TLP:GREEN"}],"objectLabel":[{"value":"fixture"}],
	  "stixCoreRelationships":{"pageInfo":{"globalCount":2},"edges":[{"node":{"id":"r2","relationship_type":"indicates",
	     "from":{"id":"ind-1","entity_type":"Indicator","representative":{"main":"192.0.2.10"}},
	     "to":{"id":"mal-1","entity_type":"Malware","representative":{"main":"FixtureLoader"}}}}]}}`
	indOrphan = `{"id":"ind-2","name":"orphan","pattern":"[domain-name:value = 'orphan.example.org']","pattern_type":"stix",
	  "objectMarking":[],"stixCoreRelationships":{"pageInfo":{"globalCount":0},"edges":[]}}`
	indYara = `{"id":"ind-3","name":"yara","pattern":"rule r { strings: $a = \"orphan.example.org\" }","pattern_type":"yara",
	  "objectMarking":[],"stixCoreRelationships":{"pageInfo":{"globalCount":0},"edges":[]}}`
	indSub = `{"id":"ind-4","name":"longer","pattern":"[domain-name:value = 'xorphan.example.org']","pattern_type":"stix",
	  "objectMarking":[],"stixCoreRelationships":{"pageInfo":{"globalCount":0},"edges":[]}}`
	fileObs = `{"id":"obs-f","entity_type":"StixFile","observable_value":"cccc","hashes":[{"algorithm":"MD5","hash":"63E5896B25163A4CDE6D19885EB9F9AD"},{"algorithm":"SHA-512","hash":"cccc"}],
	  "objectMarking":[],"containers":{"pageInfo":{"globalCount":0},"edges":[]},"stixCoreRelationships":{"pageInfo":{"globalCount":0},"edges":[]},
	  "indicators":{"pageInfo":{"globalCount":0},"edges":[]}}`
)

func lookupFake() *fake {
	return &fake{replies: map[string]string{
		"LookupObservables": `{"stixCyberObservables":{"pageInfo":{"globalCount":2},"edges":[{"node":` + obs192 + `},{"node":` + fileObs + `}]}}`,
		"LookupIndicators":  `{"indicators":{"pageInfo":{"globalCount":4},"edges":[{"node":` + ind192 + `},{"node":` + indOrphan + `},{"node":` + indYara + `},{"node":` + indSub + `}]}}`,
		"Sightings": `{"stixSightingRelationships":{"pageInfo":{"globalCount":2},"edges":[
		   {"node":{"id":"s1","attribute_count":3,"x_opencti_negative":false,"confidence":100,"objectMarking":[{"definition":"TLP:AMBER"}],
		     "from":{"id":"ind-1","entity_type":"Indicator","representative":{"main":"192.0.2.10"}},"to":{"id":"org-1","entity_type":"Organization","representative":{"main":"Example Corp"}}}},
		   {"node":{"id":"s2","attribute_count":1,"x_opencti_negative":true,"objectMarking":[],
		     "from":{"id":"ind-1","entity_type":"Indicator","representative":{"main":"192.0.2.10"}},"to":{"id":"org-2","entity_type":"Organization","representative":{"main":"Example Bank"}}}}]}}`,
	}}
}

func TestLookupIOC(t *testing.T) {
	f := lookupFake()
	res, err := newEngine(f).LookupIOC(context.Background(), []string{"192.0.2.10", "orphan.example.org", "63e5896b25163a4cde6d19885eb9f9ad", "192.0.2.200", "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 4 {
		t.Fatalf("duplicate input not folded: %d results", len(res.Results))
	}
	ip, orphan, md5, none := res.Results[0], res.Results[1], res.Results[2], res.Results[3]

	if !ip.Found || len(ip.Observables) != 1 || len(ip.Indicators) != 1 {
		t.Fatalf("ip: %+v", ip)
	}
	ind := ip.Indicators[0]
	if strings.Join(ind.FoundVia, ",") != "observable,pattern" || ind.PatternLiteral != "192.0.2.10" || ind.Match != "exact" {
		t.Fatalf("indicator paths: %+v", ind)
	}
	if !ind.Revoked || *ind.Score != 20 || *ind.DecayBaseScore != 85 || *ind.DecayLifetimeDays != 47 || *ip.Observables[0].Score != 85 {
		t.Fatalf("decay must be passed through, observable and indicator scores apart: %+v", ind)
	}
	if ind.Related.Total != 2 || ind.Related.Items[0].Direction != "outgoing" || ind.Related.Items[0].Name != "FixtureLoader" {
		t.Fatalf("indicator relationships: %+v", ind.Related)
	}
	if o := ip.Observables[0]; o.Containers.Total != 12 || len(o.Containers.Items) != 1 || o.Related.Items[0].Direction != "incoming" {
		t.Fatalf("observable lists: %+v", o)
	}
	if len(ip.Sightings) != 2 || ip.Sightings[1].Negative != true || ip.Sightings[0].Where.Name != "Example Corp" {
		t.Fatalf("sightings: %+v", ip.Sightings)
	}

	if len(orphan.Observables) != 0 || len(orphan.Indicators) != 1 || orphan.Indicators[0].ID != "ind-2" ||
		strings.Join(orphan.Indicators[0].FoundVia, ",") != "pattern" {
		t.Fatalf("orphan: the substring candidate must be dropped, the exact one kept: %+v", orphan.Indicators)
	}
	if len(orphan.PatternMentions) != 1 || orphan.PatternMentions[0].ID != "ind-3" {
		t.Fatalf("a non-STIX pattern mentioning the value is listed apart: %+v", orphan.PatternMentions)
	}

	if len(md5.Observables) != 1 || md5.Observables[0].ID != "obs-f" || md5.Observables[0].Match != "equivalent" {
		t.Fatalf("hash matched through hashes, in another case: %+v", md5.Observables)
	}

	if none.Found || !strings.Contains(none.Note, "not visible to this key") {
		t.Fatalf("not found: %+v", none)
	}
	if res.Results[0].Observables == nil || none.Observables == nil || none.Sightings == nil {
		t.Fatal("lists are empty arrays, never null")
	}

	// What was sent: every stored form, the hash under its own key.
	obsVars, _ := json.Marshal(f.varsOf("LookupObservables"))
	for _, want := range []string{`"hashes.MD5"`, `"192.0.2.200"`, `"eq"`} {
		if !strings.Contains(string(obsVars), want) {
			t.Fatalf("observable filter lacks %s: %s", want, obsVars)
		}
	}
	patVars, _ := json.Marshal(f.varsOf("LookupIndicators"))
	if !strings.Contains(string(patVars), `"contains"`) || !strings.Contains(string(patVars), `"pattern"`) {
		t.Fatalf("pattern filter: %s", patVars)
	}
	sVars, _ := json.Marshal(f.varsOf("Sightings"))
	if !strings.Contains(string(sVars), `"fromId"`) || !strings.Contains(string(sVars), `"ind-1"`) || !strings.Contains(string(sVars), `"obs-1"`) {
		t.Fatalf("sightings filter: %s", sVars)
	}
}

func TestLookupTruncationIsNoted(t *testing.T) {
	f := lookupFake()
	f.replies["LookupObservables"] = `{"stixCyberObservables":{"pageInfo":{"globalCount":900},"edges":[{"node":` + obs192 + `}]}}`
	res, err := newEngine(f).LookupIOC(context.Background(), []string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "900 matched, 1 read") {
		t.Fatalf("notes %v", res.Notes)
	}

	// A miss after a cut list is not "not found".
	res, err = newEngine(f).LookupIOC(context.Background(), []string{"192.0.2.10", "192.0.2.200"})
	if err != nil {
		t.Fatal(err)
	}
	miss := res.Results[1]
	if miss.Found || !miss.Inconclusive || strings.Contains(miss.Note, "nothing within") {
		t.Fatalf("%+v", miss)
	}
	if res.Results[0].Inconclusive {
		t.Fatal("a found value is never inconclusive")
	}
}

func TestLookupRefusals(t *testing.T) {
	e := newEngine(&fake{})
	many := make([]string, MaxLookupValues+1)
	for i := range many {
		many[i] = "192.0.2.1"
	}
	for name, in := range map[string][]string{"none": nil, "too many": many, "bad": {"192.0.2.10", "not a value"}} {
		if _, err := e.LookupIOC(context.Background(), in); Code(err) != CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.Cfg.Token = ""
	if _, err := e.LookupIOC(context.Background(), []string{"192.0.2.10"}); Code(err) != CodeNotConfigured {
		t.Fatalf("not configured: %v", err)
	}
}

func TestUpstreamErrorPassesThrough(t *testing.T) {
	f := lookupFake()
	f.errs = map[string]error{"LookupIndicators": &opencti.Error{Code: opencti.CodeForbidden, Message: "no"}}
	if _, err := newEngine(f).LookupIOC(context.Background(), []string{"192.0.2.10"}); Code(err) != opencti.CodeForbidden {
		t.Fatalf("%v", err)
	}
}

func TestCursorAndPage(t *testing.T) {
	p := pageOf(130, 50, cursor{}, "c1")
	if p.Remaining != 80 || p.NextCursor == "" {
		t.Fatalf("%+v", p)
	}
	c, err := decodeCursor(p.NextCursor)
	if err != nil || c.Seen != 50 || c.After != "c1" {
		t.Fatalf("%+v %v", c, err)
	}
	last := pageOf(130, 30, cursor{After: "c2", Seen: 100}, "c3")
	if last.Remaining != 0 || last.NextCursor != "" {
		t.Fatalf("last page %+v", last)
	}
	// OpenCTI said nothing more but the total says otherwise: the gap is reported.
	short := pageOf(10, 4, cursor{}, "")
	if short.Remaining != 6 {
		t.Fatalf("short %+v", short)
	}
	for _, bad := range []string{"%%%", "eyJ4IjoxfQ"} {
		if _, err := decodeCursor(bad); Code(err) != CodeInvalidArgument {
			t.Errorf("cursor %q accepted", bad)
		}
	}
}

func TestLimit(t *testing.T) {
	e := newEngine(&fake{})
	if n, _ := e.limit(0); n != 25 {
		t.Fatal(n)
	}
	for _, bad := range []int{-1, 501} {
		if _, err := e.limit(bad); Code(err) != CodeInvalidArgument {
			t.Errorf("limit %d accepted", bad)
		}
	}
}

func TestSearchExactThenFulltext(t *testing.T) {
	exact := `{"stixDomainObjects":{"pageInfo":{"globalCount":2},"edges":[
	  {"node":{"id":"is-1","entity_type":"Intrusion-Set","representative":{"main":"APT28"},"name":"APT28","aliases":["Sofacy"],"description":"` + strings.Repeat("x", 400) + `","objectMarking":[]}},
	  {"node":{"id":"m-1","entity_type":"Malware","representative":{"main":"CORESHELL"},"name":"CORESHELL","aliases":["Sofacy"],"objectMarking":[]}}]}}`
	f := &fake{replies: map[string]string{"Search": exact}}
	res, err := newEngine(f).SearchThreats(context.Background(), "sofacy", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "exact" || len(res.Rows) != 2 || res.Rows[0].MatchedOn != "alias" || len([]rune(res.Rows[0].Excerpt)) != excerptRunes+1 {
		t.Fatalf("%+v", res)
	}
	if v := f.calls[0].vars; v["search"] != nil || len(v["types"].([]string)) != 9 {
		t.Fatalf("exact call vars %v", v)
	}

	f2 := &fake{replies: map[string]string{"Search": `{"stixDomainObjects":{"pageInfo":{"globalCount":0},"edges":[]}}`}}
	calls := 0
	f2wrap := &sequence{f: f2, after: map[int]string{1: `{"stixDomainObjects":{"pageInfo":{"globalCount":305},"edges":[{"node":{"id":"x","entity_type":"Report","representative":{"main":"R"},"objectMarking":[]}}]}}`}, n: &calls}
	e := newEngine(f2)
	e.Client = f2wrap
	res, err = e.SearchThreats(context.Background(), "heron infrastructure", []string{"report"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "fulltext" || !res.MoreRanked || len(res.Rows) != 1 {
		t.Fatalf("%+v", res)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), "305") {
		t.Fatal("the full-text total must not be reported as a match count")
	}
}

// sequence returns a different reply for the nth call.
type sequence struct {
	f     *fake
	after map[int]string
	n     *int
}

func (s *sequence) Query(ctx context.Context, q string, vars map[string]any, out any) error {
	i := *s.n
	*s.n++
	if r, ok := s.after[i]; ok {
		return json.Unmarshal([]byte(r), out)
	}
	return s.f.Query(ctx, q, vars, out)
}

func TestSearchRefusalsAndMitreNote(t *testing.T) {
	e := newEngine(&fake{replies: map[string]string{"Search": `{"stixDomainObjects":{"pageInfo":{"globalCount":1},"edges":[{"node":{"id":"a","entity_type":"Attack-Pattern","representative":{"main":"P"},"x_mitre_id":"G0007","objectMarking":[]}}]}}`}})
	for _, c := range []struct {
		q     string
		types []string
	}{{"", nil}, {strings.Repeat("a", 201), nil}, {"x", []string{"actor"}}} {
		if _, err := e.SearchThreats(context.Background(), c.q, c.types, 0); Code(err) != CodeInvalidArgument {
			t.Errorf("%q %v accepted", c.q, c.types)
		}
	}
	res, err := e.SearchThreats(context.Background(), "G0007", nil, 0)
	if err != nil || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "attack patterns only") {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestGetEntity(t *testing.T) {
	e := newEngine(&fake{replies: map[string]string{"Entity": `{"stixCoreObject":null}`}})
	if _, err := e.GetEntity(context.Background(), "nope"); Code(err) != CodeNotFound {
		t.Fatal(err)
	}
	e = newEngine(&fake{replies: map[string]string{"Entity": `{"stixCoreObject":{"id":"n1","entity_type":"Note","representative":{"main":"A"},
	  "attribute_abstract":"Abstract","content":"Body","objectMarking":[{"definition":"TLP:GREEN"}],
	  "externalReferences":{"pageInfo":{"globalCount":40},"edges":[{"node":{"source_name":"cve","external_id":"CVE-2099-0001"}}]}}}`}})
	ent, err := e.GetEntity(context.Background(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if ent.Description != "Abstract\n\nBody" || ent.ExternalRefs.Total != 40 || ent.ExternalRefs.Items[0].ExternalID != "CVE-2099-0001" {
		t.Fatalf("%+v", ent)
	}
	if _, err := e.GetEntity(context.Background(), " "); Code(err) != CodeInvalidArgument {
		t.Fatal("blank id accepted")
	}
}

const existsReply = `{"stixCoreObject":{"id":"is-1","entity_type":"Intrusion-Set","representative":{"main":"FIXTURE-HERON"},"objectMarking":[]}}`

func TestGetRelated(t *testing.T) {
	f := &fake{replies: map[string]string{"Exists": existsReply, "Related": `{"stixCoreRelationships":{"pageInfo":{"globalCount":3,"endCursor":"E1"},"edges":[
	  {"node":{"id":"r1","relationship_type":"uses","start_time":"1970-01-01T00:00:00.000Z","stop_time":"5138-11-16T09:46:40.000Z","objectMarking":[],
	    "from":{"id":"is-1","entity_type":"Intrusion-Set","representative":{"main":"FIXTURE-HERON"}},"to":{"id":"m-1","entity_type":"Malware","representative":{"main":"FixtureLoader"}}}},
	  {"node":{"id":"r2","relationship_type":"attributed-to","start_time":"2026-09-01T00:00:00.000Z","objectMarking":[{"definition":"TLP:AMBER"}],
	    "from":{"id":"c-1","entity_type":"Campaign","representative":{"main":"Tide"}},"to":{"id":"is-1","entity_type":"Intrusion-Set","representative":{"main":"FIXTURE-HERON"}}}}]}}`}}
	res, err := newEngine(f).GetRelated(context.Background(), RelatedQuery{ID: "is-1", TargetTypes: []string{"malware", "Campaign"}, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Of.Name != "FIXTURE-HERON" || len(res.Rows) != 2 || res.Remaining != 1 || res.NextCursor == "" {
		t.Fatalf("%+v", res)
	}
	if res.Rows[0].Direction != "outgoing" || res.Rows[0].Other.Name != "FixtureLoader" || res.Rows[0].StartTime != "" || res.Rows[0].StopTime != "" {
		t.Fatalf("row 0 %+v", res.Rows[0])
	}
	if res.Rows[1].Direction != "incoming" || res.Rows[1].Other.Name != "Tide" || res.Rows[1].StartTime == "" {
		t.Fatalf("row 1 %+v", res.Rows[1])
	}
	if got := f.varsOf("Related")["targets"].([]string); strings.Join(got, ",") != "Malware,Campaign" {
		t.Fatalf("target types not canonicalized: %v", got)
	}
	if _, has := f.varsOf("Related")["types"]; has {
		t.Fatal("an absent relationship filter must not be sent")
	}
}

func TestGetRelatedRefusals(t *testing.T) {
	f := &fake{replies: map[string]string{"Exists": `{"stixCoreObject":null}`}}
	e := newEngine(f)
	cases := []RelatedQuery{
		{ID: "x", TargetTypes: []string{"No-Such-Type"}},
		{ID: "x", RelationshipTypes: []string{"Uses"}},
		{ID: "x", Cursor: "garbage!"},
		{ID: ""},
	}
	for _, q := range cases {
		if _, err := e.GetRelated(context.Background(), q); Code(err) != CodeInvalidArgument {
			t.Errorf("%+v: %v", q, err)
		}
	}
	if _, err := e.GetRelated(context.Background(), RelatedQuery{ID: "x"}); Code(err) != CodeNotFound {
		t.Fatalf("missing object: %v", err)
	}
	for _, c := range f.calls {
		if c.op == "Related" {
			t.Fatal("a refused query reached the instance")
		}
	}

	f = &fake{replies: map[string]string{"Exists": existsReply},
		errs: map[string]error{"Related": &opencti.Error{Code: opencti.CodeQueryRejected, UpstreamCode: "UNSUPPORTED_ERROR", Message: "This API only support Stix core relationships"}}}
	if _, err := newEngine(f).GetRelated(context.Background(), RelatedQuery{ID: "is-1", RelationshipTypes: []string{"no-such"}}); Code(err) != CodeInvalidArgument {
		t.Fatalf("an unknown relationship type is the caller's argument: %v", err)
	}
}

func TestGetReports(t *testing.T) {
	f := &fake{replies: map[string]string{"Exists": existsReply, "Containers": `{"containers":{"pageInfo":{"globalCount":4,"endCursor":"E"},"edges":[
	  {"node":{"id":"rep-1","entity_type":"Report","representative":{"main":"R1"},"created":"2026-10-01","published":"2026-10-02","objectMarking":[{"definition":"TLP:GREEN"}],"createdBy":{"name":"CERT"}}}]}}`}}
	c, _ := decodeCursor(encodeCursor(cursor{After: "PREV", Seen: 2}))
	res, err := newEngine(f).GetReports(context.Background(), "is-1", 1, encodeCursor(c))
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 4 || res.Remaining != 1 || res.Containers[0].Published != "2026-10-02" || res.Containers[0].Markings[0] != "TLP:GREEN" {
		t.Fatalf("%+v", res)
	}
	if f.varsOf("Containers")["after"] != "PREV" {
		t.Fatal("cursor not forwarded")
	}
}

func TestServerStatus(t *testing.T) {
	f := &fake{replies: map[string]string{"Status": `{"about":{"version":"6.8.0"},"me":{"name":"ro","capabilities":[{"name":"KNOWLEDGE"}],"allowed_marking":[{"definition":"TLP:GREEN"},{"definition":"TLP:AMBER"}]}}`}}
	e := newEngine(f)
	e.Cfg.Path = "/cfg.toml"
	st := e.ServerStatus(context.Background())
	if st.Error != nil || st.VersionMatches || len(st.Warnings) != 1 || st.TLSVerification != "on" ||
		strings.Join(st.VisibleMarkings, ",") != "TLP:AMBER,TLP:GREEN" || st.ConfigFile != "/cfg.toml" {
		t.Fatalf("%+v", st)
	}

	f.errs = map[string]error{"Status": &opencti.Error{Code: opencti.CodeAuthFailed, Message: "refused"}}
	e.Cfg.URL, e.Cfg.Path, e.Cfg.Searched = "http://10.0.0.5", "", []string{"/a", "/b"}
	st = e.ServerStatus(context.Background())
	if st.Error == nil || st.Error.Code != opencti.CodeAuthFailed || st.TLSVerification != "n/a (http)" || !st.PlainHTTP ||
		st.ConfigFile != "(none)" || len(st.ConfigSearched) != 2 {
		t.Fatalf("%+v", st)
	}

	e.Cfg.Token = ""
	st = e.ServerStatus(context.Background())
	if st.Error == nil || st.Error.Code != CodeNotConfigured {
		t.Fatalf("not configured: %+v", st.Error)
	}
}
