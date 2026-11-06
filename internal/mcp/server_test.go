package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// stubEngine records what each tool passed and answers with canned values.
type stubEngine struct {
	got    map[string]any
	err    error
	lookup *engine.LookupResult
	rel    *engine.RelatedResult
}

func (s *stubEngine) note(k string, v any) {
	if s.got == nil {
		s.got = map[string]any{}
	}
	s.got[k] = v
}

func (s *stubEngine) LookupIOC(_ context.Context, values []string) (*engine.LookupResult, error) {
	s.note("lookup", values)
	if s.lookup != nil {
		return s.lookup, s.err
	}
	return &engine.LookupResult{Results: []engine.IOCResult{{Input: values[0]}}}, s.err
}
func (s *stubEngine) SearchThreats(_ context.Context, q string, types []string, limit int) (*engine.SearchResult, error) {
	s.note("search", fmt.Sprint(q, types, limit))
	return &engine.SearchResult{Query: q, Mode: "exact", Rows: []engine.ThreatRow{}}, s.err
}
func (s *stubEngine) GetEntity(_ context.Context, id string) (*engine.Entity, error) {
	s.note("entity", id)
	return &engine.Entity{Description: strings.Repeat("d", 5000)}, s.err
}
func (s *stubEngine) GetRelated(_ context.Context, q engine.RelatedQuery) (*engine.RelatedResult, error) {
	s.note("related", q)
	if s.rel != nil {
		return s.rel, s.err
	}
	return &engine.RelatedResult{Rows: []engine.RelatedRow{}}, s.err
}
func (s *stubEngine) GetReports(_ context.Context, id string, limit int, cursor string) (*engine.ReportsResult, error) {
	s.note("reports", fmt.Sprint(id, limit, cursor))
	return &engine.ReportsResult{Containers: []engine.ContainerRow{}}, s.err
}
func (s *stubEngine) ServerStatus(context.Context) *engine.Status {
	s.note("status", true)
	return &engine.Status{Version: "6.7.4", VerifiedVersion: "6.7.4"}
}

// exchange runs the server over the given frames and returns its replies.
func exchange(t *testing.T, eng Engine, frames ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	srv := &Server{Eng: eng, Version: "v-test"}
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

func callFrame(id int, tool string, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

// toolResult returns the text of a tools/call reply and whether it is an error.
func toolResult(t *testing.T, reply map[string]any) (string, bool) {
	t.Helper()
	res, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", reply)
	}
	content := res["content"].([]any)
	isErr, _ := res["isError"].(bool)
	return content[0].(map[string]any)["text"].(string), isErr
}

func TestProtocol(t *testing.T) {
	r := exchange(t, &stubEngine{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"no/such"}`,
		`not json`,
	)
	if len(r) != 5 {
		t.Fatalf("%d replies (a notification must not be answered): %v", len(r), r)
	}
	info := r[0]["result"].(map[string]any)
	if info["serverInfo"].(map[string]any)["version"] != "v-test" || !strings.Contains(info["instructions"].(string), "get_usage") {
		t.Fatalf("initialize %v", info)
	}
	tools := r[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 7 {
		t.Fatalf("%d tools", len(tools))
	}
	for _, tl := range tools {
		schema := tl.(map[string]any)["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Errorf("%v: schema not closed", tl.(map[string]any)["name"])
		}
	}
	if r[3]["error"].(map[string]any)["code"] != float64(-32601) || r[4]["error"].(map[string]any)["code"] != float64(-32700) {
		t.Fatalf("errors %v %v", r[3], r[4])
	}
}

func TestToolsPassArguments(t *testing.T) {
	s := &stubEngine{}
	r := exchange(t, s,
		callFrame(1, ToolLookupIOC, `{"values":["192.0.2.10","bad.example.com"]}`),
		callFrame(2, ToolSearchThreats, `{"query":"APT28","types":["intrusion-set"],"limit":5}`),
		callFrame(3, ToolGetEntity, `{"id":"x"}`),
		callFrame(4, ToolGetRelated, `{"id":"x","relationship_types":["uses"],"target_types":["Malware"],"with_descriptions":true,"limit":3,"cursor":"c"}`),
		callFrame(5, ToolGetReports, `{"id":"x","limit":2,"cursor":"c2"}`),
		callFrame(6, ToolServerStatus, `{}`),
		callFrame(7, ToolGetUsage, `null`),
	)
	for i, reply := range r {
		if _, isErr := toolResult(t, reply); isErr {
			t.Errorf("call %d failed: %v", i+1, reply)
		}
	}
	want := map[string]any{
		"lookup":  []string{"192.0.2.10", "bad.example.com"},
		"search":  "APT28[intrusion-set] 5",
		"entity":  "x",
		"related": engine.RelatedQuery{ID: "x", RelationshipTypes: []string{"uses"}, TargetTypes: []string{"Malware"}, WithDescriptions: true, Limit: 3, Cursor: "c"},
		"reports": "x2c2",
		"status":  true,
	}
	for k, v := range want {
		if fmt.Sprint(s.got[k]) != fmt.Sprint(v) {
			t.Errorf("%s got %v, want %v", k, s.got[k], v)
		}
	}
	usage, _ := toolResult(t, r[6])
	if usage != UsageDoc() {
		t.Error("get_usage must return the manual itself")
	}
	entity, _ := toolResult(t, r[2])
	if !strings.Contains(entity, strings.Repeat("d", 5000)) {
		t.Error("a description is carried whole")
	}
}

func TestUndeclaredArgumentsAreRefused(t *testing.T) {
	s := &stubEngine{}
	r := exchange(t, s,
		callFrame(1, ToolGetRelated, `{"id":"x","targettypes":["Malware"]}`),
		callFrame(2, ToolServerStatus, `{"verbose":true}`),
		callFrame(3, ToolLookupIOC, `{"values":"192.0.2.10"}`),
		callFrame(4, "no_such_tool", `{}`),
	)
	codes := []string{engine.CodeInvalidArgument, engine.CodeInvalidArgument, engine.CodeInvalidArgument, CodeUnknownTool}
	for i, reply := range r {
		text, isErr := toolResult(t, reply)
		var e map[string]string
		_ = json.Unmarshal([]byte(text), &e)
		if !isErr || e["code"] != codes[i] {
			t.Errorf("call %d: %s", i+1, text)
		}
	}
	if len(s.got) != 0 {
		t.Fatalf("a refused call reached the engine: %v", s.got)
	}
}

func TestEngineErrorsKeepTheirCodes(t *testing.T) {
	for _, err := range []error{
		&opencti.Error{Code: opencti.CodeForbidden, Message: "no"},
		&engine.Error{Code: engine.CodeNotFound, Message: "gone"},
		&config.NotConfiguredError{Missing: []string{"url"}},
		fmt.Errorf("plain"),
	} {
		r := exchange(t, &stubEngine{err: err}, callFrame(1, ToolGetEntity, `{"id":"x"}`))
		text, isErr := toolResult(t, r[0])
		var e map[string]string
		_ = json.Unmarshal([]byte(text), &e)
		want := engine.Code(err)
		if want == "" {
			want = CodeInternal
		}
		if !isErr || e["code"] != want {
			t.Errorf("%T: %s", err, text)
		}
	}
}

func TestOversizedLookupLosesTailValues(t *testing.T) {
	var results []engine.IOCResult
	for i := 0; i < 50; i++ {
		results = append(results, engine.IOCResult{Input: fmt.Sprintf("192.0.2.%d", i), Note: strings.Repeat("n", 999)})
		for j := 0; j < 5; j++ {
			results[i].Indicators = append(results[i].Indicators, engine.Indicator{Name: strings.Repeat("i", 900)})
		}
	}
	r := exchange(t, &stubEngine{lookup: &engine.LookupResult{Results: results}}, callFrame(1, ToolLookupIOC, `{"values":["x"]}`))
	text, isErr := toolResult(t, r[0])
	if isErr || len(text) > maxResultBytes {
		t.Fatalf("isErr=%v len=%d", isErr, len(text))
	}
	var got engine.LookupResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) == 50 || len(got.Results) == 0 || got.Results[0].Input != "192.0.2.0" {
		t.Fatalf("%d results kept", len(got.Results))
	}
	note := strings.Join(got.Notes, " ")
	if !strings.Contains(note, "values omitted for size") || !strings.Contains(note, "192.0.2.49") {
		t.Fatalf("the dropped values are not named: %q", note)
	}
}

func TestOversizedPagedListIsRefused(t *testing.T) {
	rows := make([]engine.RelatedRow, 0, 300)
	for i := 0; i < 300; i++ {
		rows = append(rows, engine.RelatedRow{Description: strings.Repeat("r", 900), Other: engine.Ref{Name: strings.Repeat("o", 200)}})
	}
	r := exchange(t, &stubEngine{rel: &engine.RelatedResult{Rows: rows}}, callFrame(1, ToolGetRelated, `{"id":"x"}`))
	text, isErr := toolResult(t, r[0])
	if !isErr || !strings.Contains(text, CodeTooLarge) || !strings.Contains(text, "limit") {
		t.Fatalf("%v %s", isErr, text)
	}
}

func TestUpsertDropped(t *testing.T) {
	n := upsertDropped(nil, "rows omitted: ", "1")
	n = upsertDropped(n, "rows omitted: ", "1")
	n = upsertDropped(n, "values: ", "a")
	n = upsertDropped(n, "values: ", "b")
	if strings.Join(n, "|") != "rows omitted: 2|values: a, b" {
		t.Fatalf("%q", n)
	}
}
