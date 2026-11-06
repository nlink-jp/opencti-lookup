package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/save"
	"github.com/nlink-jp/pathguard"
	"github.com/nlink-jp/pathguard/workdir"
)

// serverWith builds a server whose resolver protects configDir, as the app does.
func serverWith(eng Engine, configDir string) *Server {
	return &Server{Eng: eng, Version: "v", WorkDirs: workdir.NewResolver(workdir.Options{
		Protected:    []pathguard.Place{pathguard.ServerDir(configDir, "which holds the OpenCTI token")},
		RequiredHint: "The attachment is written there and returned as a path.",
	})}
}

func run(t *testing.T, srv *Server, frames ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(strings.Join(frames, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var replies []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		replies = append(replies, m)
	}
	return replies
}

func errCode(t *testing.T, reply map[string]any) (string, map[string]any) {
	t.Helper()
	text, isErr := toolResult(t, reply)
	if !isErr {
		return "", nil
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(text), &e); err != nil {
		t.Fatal(err)
	}
	d, _ := e["details"].(map[string]any)
	return e["code"].(string), d
}

func TestListRecentTool(t *testing.T) {
	s := &stubEngine{}
	r := run(t, serverWith(s, t.TempDir()), callFrame(1, ToolListRecent, `{"type":"indicator","date_field":"created","days":30,"limit":5,"cursor":"c"}`))
	if _, isErr := toolResult(t, r[0]); isErr {
		t.Fatal(r[0])
	}
	if fmt.Sprint(s.got["recent"]) != fmt.Sprint(engine.RecentQuery{Type: "indicator", Axis: "created", Days: 30, Limit: 5, Cursor: "c"}) {
		t.Fatalf("%v", s.got["recent"])
	}
}

func TestGetReportFile(t *testing.T) {
	work := t.TempDir()
	s := &stubEngine{}
	srv := serverWith(s, t.TempDir())
	r := run(t, srv, callFrame(1, ToolGetReportFile, fmt.Sprintf(`{"id":"84ec431c-fe0f","name":"../escape attempt.txt","work_dir":%q}`, work)))
	text, isErr := toolResult(t, r[0])
	if isErr {
		t.Fatal(text)
	}
	var res map[string]any
	_ = json.Unmarshal([]byte(text), &res)
	resolved, _ := filepath.EvalSymlinks(work)
	want := save.FileName("84ec431c-fe0f-4b73-b1b1-bdc344fded85", "../escape attempt.txt")
	if res["work_dir"] != resolved || res["path"] != want || !strings.HasSuffix(want, "-escape_attempt.txt") ||
		res["abs_path"] != filepath.Join(resolved, want) || res["sha256"] != "sha" {
		t.Fatalf("%v", res)
	}
	if b, err := os.ReadFile(res["abs_path"].(string)); err != nil || string(b) != "attachment body" {
		t.Fatalf("%q %v", b, err)
	}
	if s.got["file"] != "84ec431c-fe0f/../escape attempt.txt" {
		t.Fatalf("the engine must get the name as listed: %v", s.got["file"])
	}
}

func TestGetReportFileWorkDirFromMeta(t *testing.T) {
	work := t.TempDir()
	srv := serverWith(&stubEngine{}, t.TempDir())
	frame := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{"id":"r1","name":"a.pdf"},"_meta":{%q:%q}}}`,
		ToolGetReportFile, workdir.MetaKey, work)
	r := run(t, srv, frame)
	if text, isErr := toolResult(t, r[0]); isErr {
		t.Fatalf("_meta work_dir: %s", text)
	}
}

func TestGetReportFileRefusals(t *testing.T) {
	configDir := t.TempDir()
	s := &stubEngine{}
	srv := serverWith(s, configDir)
	r := run(t, srv,
		callFrame(1, ToolGetReportFile, `{"id":"r1","name":"a.pdf"}`),
		callFrame(2, ToolGetReportFile, `{"id":"r1","name":"a.pdf","work_dir":"relative/dir"}`),
		callFrame(3, ToolGetReportFile, fmt.Sprintf(`{"id":"r1","name":"a.pdf","work_dir":%q}`, filepath.Join(t.TempDir(), "missing"))),
		callFrame(4, ToolGetReportFile, fmt.Sprintf(`{"id":"r1","name":"a.pdf","work_dir":%q}`, configDir)),
	)
	want := []string{workdir.CodeRequired, workdir.CodeInvalid, workdir.CodeNotFound, workdir.CodeDenied}
	for i, reply := range r {
		code, details := errCode(t, reply)
		if code != want[i] {
			t.Errorf("call %d: %s (want %s)", i+1, code, want[i])
		}
		if want[i] == workdir.CodeDenied && details["reason"] == nil {
			t.Errorf("work_dir_denied carries no reason: %v", details)
		}
	}
	if s.got["file"] != nil {
		t.Fatal("a refused work directory reached the engine")
	}

	// An engine failure leaves nothing in the work directory.
	work := t.TempDir()
	failing := serverWith(&stubEngine{err: &engine.Error{Code: engine.CodeNotFound, Message: "no attachment"}}, t.TempDir())
	r = run(t, failing, callFrame(1, ToolGetReportFile, fmt.Sprintf(`{"id":"r1","name":"a.pdf","work_dir":%q}`, work)))
	if code, _ := errCode(t, r[0]); code != engine.CodeNotFound {
		t.Fatalf("%s", code)
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("a failed download left %v", entries)
	}
}
