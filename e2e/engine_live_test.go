//go:build e2e

// Live tests against the development OpenCTI 6.7.4 stack, seeded as in
// docs/ja/opencti-lookup-phase0.ja.md (make dev-up, dev/seed/push.sh,
// readonly_user.py, attach.py). Run with `make e2e`, which reads the tokens
// from dev/.env without printing them.
//
// They drive the engine directly, as the read-only user unless a test says
// otherwise, and assert behaviour on the fictional fixtures — never on MITRE
// counts, which move with the MITRE dataset.
package e2e

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

func liveEngine(t *testing.T, tokenVar string) *engine.Engine {
	t.Helper()
	url, token := os.Getenv("OPENCTI_E2E_URL"), os.Getenv(tokenVar)
	if url == "" || token == "" {
		t.Fatalf("OPENCTI_E2E_URL and %s must be set (run make e2e)", tokenVar)
	}
	cfg := &config.Config{URL: url, Token: token, Timeout: 60 * time.Second, DefaultLimit: 25, MaxLimit: 500}
	return &engine.Engine{Client: opencti.New(cfg), Cfg: cfg}
}

func readonly(t *testing.T) *engine.Engine { return liveEngine(t, "OPENCTI_E2E_READONLY_TOKEN") }
func admin(t *testing.T) *engine.Engine    { return liveEngine(t, "OPENCTI_E2E_ADMIN_TOKEN") }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

func lookupOne(t *testing.T, e *engine.Engine, value string) engine.IOCResult {
	t.Helper()
	res, err := e.LookupIOC(ctx(t), []string{value})
	if err != nil {
		t.Fatalf("LookupIOC(%q): %v", value, err)
	}
	if len(res.Results) != 1 {
		t.Fatalf("%d results", len(res.Results))
	}
	return res.Results[0]
}

func TestLiveStatus(t *testing.T) {
	st := readonly(t).ServerStatus(ctx(t))
	if st.Error != nil {
		t.Fatalf("status error: %+v", st.Error)
	}
	if st.Version != engine.VerifiedVersion || !st.VersionMatches {
		t.Fatalf("version %q", st.Version)
	}
	if strings.Join(st.Capabilities, ",") != "KNOWLEDGE" {
		t.Fatalf("capabilities %v", st.Capabilities)
	}
	if strings.Join(st.VisibleMarkings, ",") != "TLP:AMBER,TLP:CLEAR,TLP:GREEN" {
		t.Fatalf("markings %v", st.VisibleMarkings)
	}
}

func TestLiveStatusBadToken(t *testing.T) {
	e := readonly(t)
	e.Cfg.Token = "00000000-0000-4000-8000-000000000000"
	e.Client = opencti.New(e.Cfg)
	st := e.ServerStatus(ctx(t))
	if st.Error == nil || st.Error.Code != opencti.CodeAuthFailed {
		t.Fatalf("status %+v", st.Error)
	}
}

func TestLiveLookupIPv4(t *testing.T) {
	r := lookupOne(t, readonly(t), "192.0.2.10")
	if !r.Found || len(r.Observables) != 1 || len(r.Indicators) != 1 {
		t.Fatalf("found=%v obs=%d ind=%d", r.Found, len(r.Observables), len(r.Indicators))
	}
	o, ind := r.Observables[0], r.Indicators[0]
	if o.Match != "exact" || o.Score == nil || *o.Score != 85 {
		t.Fatalf("observable %+v", o)
	}
	// Decay (Phase 0 §3): revoked, current score below the base, both reported.
	if !ind.Revoked || ind.Score == nil || ind.DecayBaseScore == nil || *ind.DecayBaseScore != 85 || *ind.Score >= 85 {
		t.Fatalf("indicator decay fields %+v", ind)
	}
	if !contains(ind.FoundVia, "observable") || !contains(ind.FoundVia, "pattern") {
		t.Fatalf("found_via %v", ind.FoundVia)
	}
	var indicates bool
	for _, rel := range ind.Related.Items {
		indicates = indicates || (rel.Relationship == "indicates" && rel.Name == "FixtureLoader")
	}
	if !indicates {
		t.Fatalf("indicates FixtureLoader missing: %+v", ind.Related)
	}
	// One normal and one false-positive sighting.
	var normal, negative int
	for _, s := range r.Sightings {
		if s.Negative {
			negative++
		} else {
			normal++
		}
	}
	if normal != 1 || negative != 1 {
		t.Fatalf("sightings %+v", r.Sightings)
	}
	if o.Containers.Total != 4 { // GREEN report, AMBER report, note, grouping
		t.Fatalf("containers total %d: %+v", o.Containers.Total, o.Containers.Items)
	}
}

func TestLiveLookupForms(t *testing.T) {
	e := readonly(t)
	cases := map[string]string{
		"BAD.EXAMPLE.COM":                    "bad.example.com",
		"http://bad.example.com/PAYLOAD.BIN": "http://bad.example.com/payload.bin",
		"2001:db8::20":                       "2001:0DB8:0000:0000:0000:0000:0000:0020", // stored expanded
		"2001:0db8::0010":                    "2001:db8::10",
	}
	for in, stored := range cases {
		r := lookupOne(t, e, in)
		if len(r.Observables) != 1 || r.Observables[0].Value != stored || r.Observables[0].Match != "equivalent" {
			t.Errorf("%s: %+v", in, r.Observables)
		}
	}
}

func TestLiveLookupHashes(t *testing.T) {
	e := readonly(t)
	for _, h := range []string{
		"491fc027d8e22a569e67a40c16b98c93a4586c5421b18894cdd5c40201277d20",
		"491FC027D8E22A569E67A40C16B98C93A4586C5421B18894CDD5C40201277D20",
	} {
		if r := lookupOne(t, e, h); len(r.Observables) != 1 {
			t.Errorf("%s: %d observables", h, len(r.Observables))
		}
	}
	// fixture2.bin carries MD5, SHA-1 and SHA-512 of "opencti-lookup fixture sample 2";
	// each finds the same file through hashes.<algorithm>.
	var ids []string
	for _, h := range []string{
		"63e5896b25163a4cde6d19885eb9f9ad",
		"748885c8b266b1d8ae6184cf0769eca401e4308b",
	} {
		r := lookupOne(t, e, h)
		if len(r.Observables) != 1 || r.Observables[0].Type != "StixFile" {
			t.Fatalf("%s: %+v", h, r.Observables)
		}
		ids = append(ids, r.Observables[0].ID)
	}
	if ids[0] != ids[1] {
		t.Fatalf("MD5 and SHA-1 found different files: %v", ids)
	}
}

func TestLiveLookupOrphanIndicator(t *testing.T) {
	r := lookupOne(t, readonly(t), "orphan.example.org")
	if len(r.Observables) != 0 || len(r.Indicators) != 1 || r.Indicators[0].FoundVia[0] != "pattern" {
		t.Fatalf("obs=%d ind=%+v", len(r.Observables), r.Indicators)
	}
	sub := lookupOne(t, readonly(t), "orphan.example")
	if sub.Found {
		t.Fatalf("a substring of a pattern was reported as a match: %+v", sub.Indicators)
	}
}

func TestLiveLookupNotFoundAndRED(t *testing.T) {
	r := lookupOne(t, readonly(t), "192.0.2.200")
	if r.Found || !strings.Contains(r.Note, "not visible to this key") {
		t.Fatalf("%+v", r)
	}
	red := lookupOne(t, readonly(t), "198.51.100.7")
	if red.Found {
		t.Fatal("a TLP:RED observable was visible to the read-only user")
	}
	if !lookupOne(t, admin(t), "198.51.100.7").Found {
		t.Fatal("admin cannot see the TLP:RED observable")
	}
}

func TestLiveLookupBatch(t *testing.T) {
	res, err := readonly(t).LookupIOC(ctx(t), []string{"192.0.2.10", "bad.example.com", "192.0.2.200", "phisher@example.net"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"192.0.2.10": true, "bad.example.com": true, "192.0.2.200": false, "phisher@example.net": true}
	for _, r := range res.Results {
		if r.Found != want[r.Input] {
			t.Errorf("%s found=%v", r.Input, r.Found)
		}
	}
	// The observable sighting of bad.example.com (Phase 0 fixture).
	for _, r := range res.Results {
		if r.Input == "bad.example.com" && len(r.Sightings) != 1 {
			t.Errorf("bad.example.com sightings %+v", r.Sightings)
		}
	}
}

func TestLiveSearch(t *testing.T) {
	e := readonly(t)
	res, err := e.SearchThreats(ctx(t), "TA-FIXTURE-01", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "exact" || len(res.Rows) != 1 || res.Rows[0].Name != "FIXTURE-HERON" || res.Rows[0].MatchedOn != "alias" {
		t.Fatalf("%+v", res)
	}
	res, err = e.SearchThreats(ctx(t), "Sofacy", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "exact" || len(res.Rows) < 2 {
		t.Fatalf("Sofacy: %+v", res)
	}
	res, err = e.SearchThreats(ctx(t), "t1566", []string{"attack-pattern"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "exact" || len(res.Rows) != 1 || res.Rows[0].MitreID != "T1566" {
		t.Fatalf("t1566: %+v", res)
	}
	res, err = e.SearchThreats(ctx(t), "heron infrastructure", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "fulltext" || len(res.Rows) == 0 {
		t.Fatalf("fulltext: %+v", res)
	}
	if _, err := e.SearchThreats(ctx(t), "x", []string{"no-such-type"}, 0); engine.Code(err) != engine.CodeInvalidArgument {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestLiveEntityRelatedReports(t *testing.T) {
	e := readonly(t)
	s, err := e.SearchThreats(ctx(t), "FIXTURE-HERON", []string{"intrusion-set"}, 0)
	if err != nil || len(s.Rows) != 1 {
		t.Fatalf("%v %+v", err, s)
	}
	id := s.Rows[0].ID

	ent, err := e.GetEntity(ctx(t), id)
	if err != nil {
		t.Fatal(err)
	}
	if ent.Name != "FIXTURE-HERON" || !contains(ent.Aliases, "TA-FIXTURE-01") || ent.CreatedBy != "Example CERT (fixture)" {
		t.Fatalf("%+v", ent)
	}

	rel, err := e.GetRelated(ctx(t), engine.RelatedQuery{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	if rel.Of.ID != id || rel.Total == 0 || len(rel.Rows) == 0 {
		t.Fatalf("%+v", rel)
	}
	for _, row := range rel.Rows {
		if row.Description != "" {
			t.Fatal("descriptions must be omitted by default")
		}
	}
	uses, err := e.GetRelated(ctx(t), engine.RelatedQuery{ID: id, RelationshipTypes: []string{"uses"}, TargetTypes: []string{"Malware"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(uses.Rows) != 1 || uses.Rows[0].Other.Name != "FixtureLoader" || uses.Rows[0].Direction != "outgoing" {
		t.Fatalf("uses: %+v", uses.Rows)
	}

	reps, err := e.GetReports(ctx(t), id, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if reps.Total != 4 { // GREEN, AMBER, note, grouping; RED is invisible
		t.Fatalf("containers %d: %+v", reps.Total, reps.Containers)
	}
	adminReps, err := admin(t).GetReports(ctx(t), id, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if adminReps.Total != 5 {
		t.Fatalf("admin containers %d", adminReps.Total)
	}

	if _, err := e.GetRelated(ctx(t), engine.RelatedQuery{ID: "00000000-0000-4000-8000-000000000000"}); engine.Code(err) != engine.CodeNotFound {
		t.Fatalf("nonexistent id: %v", err)
	}
	if _, err := e.GetRelated(ctx(t), engine.RelatedQuery{ID: id, TargetTypes: []string{"No-Such-Type"}}); engine.Code(err) != engine.CodeInvalidArgument {
		t.Fatalf("unknown target type: %v", err)
	}
	if _, err := e.GetRelated(ctx(t), engine.RelatedQuery{ID: id, RelationshipTypes: []string{"no-such-relationship"}}); engine.Code(err) != engine.CodeInvalidArgument {
		t.Fatalf("unknown relationship type: %s: %v", engine.Code(err), err)
	}
}

func TestLivePaging(t *testing.T) {
	// FixtureLoader is indicated by every fixture indicator (130), so its
	// "indicates" relationships span three pages of 50; no row may repeat and
	// none may be missing.
	e := readonly(t)
	seen := map[string]bool{}
	cursor := ""
	ml, err := e.SearchThreats(ctx(t), "FixtureLoader", []string{"malware"}, 0)
	if err != nil || len(ml.Rows) != 1 {
		t.Fatalf("%v %+v", err, ml)
	}
	total := -1
	for page := 0; page < 20; page++ {
		rel, err := e.GetRelated(ctx(t), engine.RelatedQuery{ID: ml.Rows[0].ID, RelationshipTypes: []string{"indicates"}, Limit: 50, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		total = rel.Total
		for _, r := range rel.Rows {
			if seen[r.Other.ID] {
				t.Fatalf("row repeated across pages: %s", r.Other.ID)
			}
			seen[r.Other.ID] = true
		}
		if rel.NextCursor == "" {
			if rel.Remaining != 0 {
				t.Fatalf("no cursor but %d remaining", rel.Remaining)
			}
			break
		}
		cursor = rel.NextCursor
	}
	if len(seen) != total || total < 128 {
		t.Fatalf("paged %d of %d", len(seen), total)
	}
}

// A continuation keeps its filters: page through FIXTURE-HERON's "targets"
// one row at a time and every row is a "targets" relationship (the
// pre-release review reproduced the opposite through the CLI's printed
// continuation). A cursor taken to another query is refused.
func TestLiveContinuationKeepsFilters(t *testing.T) {
	e := readonly(t)
	s, err := e.SearchThreats(ctx(t), "FIXTURE-HERON", []string{"intrusion-set"}, 0)
	if err != nil || len(s.Rows) != 1 {
		t.Fatalf("%v %+v", err, s)
	}
	q := engine.RelatedQuery{ID: s.Rows[0].ID, RelationshipTypes: []string{"targets"}, Limit: 1}
	seen := 0
	for page := 0; page < 10; page++ {
		res, err := e.GetRelated(ctx(t), q)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range res.Rows {
			if row.Relationship != "targets" {
				t.Fatalf("page %d holds %s", page, row.Relationship)
			}
			seen++
		}
		if res.NextCursor == "" {
			if seen != res.Total || res.Remaining != 0 {
				t.Fatalf("saw %d of %d, remaining %d", seen, res.Total, res.Remaining)
			}
			break
		}
		q.Cursor = res.NextCursor
		if _, err := e.GetReports(ctx(t), s.Rows[0].ID, 1, q.Cursor); engine.Code(err) != engine.CodeInvalidArgument {
			t.Fatalf("a get_related cursor was accepted by get_reports: %v", err)
		}
	}
	if seen != 2 { // CVE-2099-0001 and the fixture sector
		t.Fatalf("targets: %d", seen)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
