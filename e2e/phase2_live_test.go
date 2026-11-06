//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

func greenReport(t *testing.T, e *engine.Engine) string {
	t.Helper()
	s, err := e.SearchThreats(ctx(t), "Fixture report: Operation Fixture Tide (GREEN)", []string{"report"}, 0)
	if err != nil || len(s.Rows) != 1 {
		t.Fatalf("%v %+v", err, s)
	}
	return s.Rows[0].ID
}

func TestLiveListRecent(t *testing.T) {
	e := readonly(t)
	// The fixtures were ingested by the dev stack recently, but their source
	// dates (created, published) are 2026-10-01: the two axes must differ.
	byIngest, err := e.ListRecent(ctx(t), engine.RecentQuery{Type: "report", Days: 365})
	if err != nil {
		t.Fatal(err)
	}
	if byIngest.Total < 3 { // GREEN, AMBER, paging; RED is invisible
		t.Fatalf("reports by created_at: %d", byIngest.Total)
	}
	for _, r := range byIngest.Rows {
		if strings.Contains(r.Name, "(RED)") {
			t.Fatal("a TLP:RED report was listed for the read-only user")
		}
	}
	inds, err := e.ListRecent(ctx(t), engine.RecentQuery{Type: "indicator", Days: 365, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if inds.Total < 129 || len(inds.Rows) != 5 || inds.NextCursor == "" || inds.Rows[0].Pattern == "" {
		t.Fatalf("indicators: total %d rows %d", inds.Total, len(inds.Rows))
	}
	if _, err := e.ListRecent(ctx(t), engine.RecentQuery{Type: "indicator", Axis: "published"}); engine.Code(err) != engine.CodeInvalidArgument {
		t.Fatalf("indicator by published: %v", err)
	}
	pub, err := e.ListRecent(ctx(t), engine.RecentQuery{Type: "report", Axis: "published", Days: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pub.Rows {
		if strings.HasPrefix(r.Name, "Fixture report") {
			t.Fatalf("a report published 2026-10-01 appeared in the last day by published: %+v", r)
		}
	}
}

func TestLiveFiles(t *testing.T) {
	e := readonly(t)
	id := greenReport(t, e)
	ent, err := e.GetEntity(ctx(t), id)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]int64{}
	for _, f := range ent.Files {
		names[f.Name] = f.Size
	}
	if names["fixture-report.pdf"] != 618 || names["escape attempt.txt"] != 48 {
		t.Fatalf("files %+v (run dev/seed/attach.py)", ent.Files)
	}

	var buf bytes.Buffer
	info, err := e.GetFile(ctx(t), id, "fixture-report.pdf", &buf)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	if info.Bytes != 618 || info.SHA256 != hex.EncodeToString(sum[:]) || info.MimeType != "application/pdf" || !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-1.4")) {
		t.Fatalf("%+v", info)
	}
	if _, err := e.GetFile(ctx(t), id, "../red-attachment.txt", &buf); engine.Code(err) != engine.CodeNotFound {
		t.Fatalf("unlisted name: %v", err)
	}

	// The RED report is invisible to this key: its attachment cannot even be
	// named, and admin can fetch it.
	a := admin(t)
	red, err := a.SearchThreats(ctx(t), "Fixture report: restricted (RED)", []string{"report"}, 0)
	if err != nil || len(red.Rows) != 1 {
		t.Fatalf("%v %+v", err, red)
	}
	if _, err := e.GetFile(ctx(t), red.Rows[0].ID, "red-attachment.txt", &buf); engine.Code(err) != engine.CodeNotFound {
		t.Fatalf("RED attachment for the read-only user: %v", err)
	}
	buf.Reset()
	if info, err := a.GetFile(ctx(t), red.Rows[0].ID, "red-attachment.txt", &buf); err != nil || info.Bytes != 21 {
		t.Fatalf("admin: %v %+v", err, info)
	}

	bad := readonly(t)
	bad.Cfg.Token = "00000000-0000-4000-8000-000000000000"
	bad.Client = opencti.New(bad.Cfg)
	if _, err := bad.GetFile(ctx(t), id, "fixture-report.pdf", &buf); engine.Code(err) != opencti.CodeAuthFailed {
		t.Fatalf("bad token: %v", err)
	}
}

func TestBinaryFileAndRecent(t *testing.T) {
	cfg := configFile(t)
	id := greenReport(t, readonly(t))

	out := t.TempDir()
	res, err := command(t, "file", id, "fixture-report.pdf", "--out", out, "--json", "-c", cfg).Output()
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	var saved struct {
		AbsPath string `json:"abs_path"`
		Path    string `json:"path"`
		Bytes   int64  `json:"bytes"`
	}
	if err := json.Unmarshal(res, &saved); err != nil || saved.Bytes != 618 || !strings.HasPrefix(saved.Path, "opencti-lookup-") {
		t.Fatalf("%v %s", err, res)
	}
	if b, err := os.ReadFile(saved.AbsPath); err != nil || len(b) != 618 {
		t.Fatalf("%v %d", err, len(b))
	}
	if resolved, _ := filepath.EvalSymlinks(out); filepath.Dir(saved.AbsPath) != resolved {
		t.Fatalf("saved outside --out: %s", saved.AbsPath)
	}

	recent, err := command(t, "recent", "--days", "365", "-c", cfg).Output()
	if err != nil || !strings.Contains(string(recent), "Fixture report") {
		t.Fatalf("recent: %v %s", err, recent)
	}
}
