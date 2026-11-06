package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

func TestListRecent(t *testing.T) {
	prev := now
	now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = prev })

	f := &fake{replies: map[string]string{"Recent": `{"reports":{"pageInfo":{"globalCount":4,"endCursor":"E"},"edges":[
	  {"node":{"id":"r1","entity_type":"Report","representative":{"main":"R1"},"created":"2026-10-01","created_at":"2026-11-06","published":"2026-10-01","report_types":["threat-report"],"objectMarking":[{"definition":"TLP:GREEN"}],"createdBy":{"name":"CERT"}}}]}}`}}
	res, err := newEngine(f).ListRecent(context.Background(), RecentQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != "report" || res.Axis != "created_at" || res.Since != "2026-10-30T12:00:00.000Z" ||
		res.Total != 4 || res.Remaining != 3 || res.Rows[0].Published != "2026-10-01" || res.Rows[0].Markings[0] != "TLP:GREEN" {
		t.Fatalf("%+v", res)
	}
	vars, _ := json.Marshal(f.varsOf("Recent"))
	if !strings.Contains(string(vars), `"created_at"`) || !strings.Contains(string(vars), `"gte"`) || !strings.Contains(string(vars), "2026-10-30") {
		t.Fatalf("filter %s", vars)
	}

	f = &fake{replies: map[string]string{"Recent": `{"indicators":{"pageInfo":{"globalCount":1},"edges":[
	  {"node":{"id":"i1","entity_type":"Indicator","representative":{"main":"x"},"pattern":"[x:value = 'y']","x_opencti_score":20,"revoked":true,"objectMarking":[]}}]}}`}}
	res, err = newEngine(f).ListRecent(context.Background(), RecentQuery{Type: "indicator", Axis: "created", Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0].Pattern == "" || !res.Rows[0].Revoked || *res.Rows[0].Score != 20 || res.Remaining != 0 {
		t.Fatalf("%+v", res.Rows)
	}
}

// A continuation keeps the window of its first page, even when the clock moved.
func TestListRecentKeepsItsWindow(t *testing.T) {
	prev := now
	t.Cleanup(func() { now = prev })
	now = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
	f := &fake{replies: map[string]string{"Recent": `{"reports":{"pageInfo":{"globalCount":3,"endCursor":"E"},"edges":[{"node":{"id":"r1","entity_type":"Report","representative":{"main":"R1"},"objectMarking":[]}}]}}`}}
	first, err := newEngine(f).ListRecent(context.Background(), RecentQuery{Limit: 1})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("%v %+v", err, first)
	}
	now = func() time.Time { return time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC) }
	second, err := newEngine(f).ListRecent(context.Background(), RecentQuery{Limit: 1, Cursor: first.NextCursor})
	if err != nil || second.Since != first.Since {
		t.Fatalf("since moved from %s to %s (%v)", first.Since, second.Since, err)
	}
	if _, err := newEngine(f).ListRecent(context.Background(), RecentQuery{Limit: 1, Days: 30, Cursor: first.NextCursor}); Code(err) != CodeInvalidArgument {
		t.Fatalf("a cursor for 7 days was accepted for 30: %v", err)
	}
}

func TestListRecentRefusals(t *testing.T) {
	f := &fake{}
	e := newEngine(f)
	for _, q := range []RecentQuery{
		{Type: "malware"},
		{Type: "indicator", Axis: "published"}, // an indicator has no published date: OpenCTI would answer zero rows
		{Axis: "modified"},
		{Days: 366},
		{Days: -1},
		{Limit: 501},
		{Cursor: "junk!"},
	} {
		if _, err := e.ListRecent(context.Background(), q); Code(err) != CodeInvalidArgument {
			t.Errorf("%+v: %v", q, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("a refused query reached the instance")
	}
}

const filesReply = `{"stixCoreObject":{"importFiles":{"edges":[
  {"node":{"id":"import/Report/r1/fixture-report.pdf","name":"fixture-report.pdf","size":618,"metaData":{"mimetype":"application/pdf"}}},
  {"node":{"id":"import/Report/r1/escape attempt.txt","name":"escape attempt.txt","size":48,"metaData":{"mimetype":"text/plain"}}}]}}}`

func TestGetFile(t *testing.T) {
	body := "%PDF-1.4 fixture"
	f := &fake{replies: map[string]string{
		"Exists":   `{"stixCoreObject":{"id":"r1","entity_type":"Report","representative":{"main":"R1"},"objectMarking":[]}}`,
		"Files":    filesReply,
		"Download": body,
	}}
	var buf bytes.Buffer
	info, err := newEngine(f).GetFile(context.Background(), "r1", "fixture-report.pdf", &buf)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	if buf.String() != body || info.Bytes != int64(len(body)) || info.SHA256 != hex.EncodeToString(sum[:]) || info.MimeType != "application/pdf" || info.Of.Name != "R1" {
		t.Fatalf("%+v", info)
	}
	if got := f.varsOf("Download")["id"]; got != "import/Report/r1/fixture-report.pdf" {
		t.Fatalf("the storage id must come from the listing: %v", got)
	}

	// A name the object does not list is not sent anywhere — not even one that
	// would make a storage path of its own.
	for _, name := range []string{"../../other/secret.pdf", "FIXTURE-REPORT.PDF", "missing.pdf"} {
		f.calls = nil
		_, err := newEngine(f).GetFile(context.Background(), "r1", name, &buf)
		if Code(err) != CodeNotFound || !strings.Contains(err.Error(), `"fixture-report.pdf"`) {
			t.Errorf("%s: %v", name, err)
		}
		for _, c := range f.calls {
			if c.op == "Download" {
				t.Errorf("%s reached the storage endpoint", name)
			}
		}
	}
	if _, err := newEngine(f).GetFile(context.Background(), "r1", " ", &buf); Code(err) != CodeInvalidArgument {
		t.Fatalf("blank name: %v", err)
	}

	f.errs = map[string]error{"Download": &opencti.Error{Code: opencti.CodeNotFound, Message: "restricted"}}
	if _, err := newEngine(f).GetFile(context.Background(), "r1", "fixture-report.pdf", &buf); Code(err) != opencti.CodeNotFound {
		t.Fatalf("storage refusal: %v", err)
	}
}

func TestGetFileTooLarge(t *testing.T) {
	f := &fake{replies: map[string]string{
		"Exists": `{"stixCoreObject":{"id":"r1","entity_type":"Report","representative":{"main":"R1"},"objectMarking":[]}}`,
		"Files":  `{"stixCoreObject":{"importFiles":{"edges":[{"node":{"id":"x","name":"huge.bin","size":209715200}}]}}}`,
	}}
	if _, err := newEngine(f).GetFile(context.Background(), "r1", "huge.bin", &bytes.Buffer{}); Code(err) != opencti.CodeFileTooLarge {
		t.Fatalf("%v", err)
	}
}

func TestEntityListsFiles(t *testing.T) {
	f := &fake{replies: map[string]string{"Entity": `{"stixCoreObject":{"id":"r1","entity_type":"Report","representative":{"main":"R1"},"objectMarking":[],
	  "externalReferences":{"pageInfo":{"globalCount":0},"edges":[]},` + strings.TrimSuffix(strings.TrimPrefix(filesReply, `{"stixCoreObject":{`), `}}`) + `}}`}}
	ent, err := newEngine(f).GetEntity(context.Background(), "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ent.Files) != 2 || ent.Files[0].Name != "fixture-report.pdf" || ent.Files[0].Size != 618 || ent.Files[0].MimeType != "application/pdf" {
		t.Fatalf("%+v", ent.Files)
	}
	b, _ := json.Marshal(ent)
	if strings.Contains(string(b), "import/Report") {
		t.Fatal("the storage id is internal and must not be shown")
	}
}
