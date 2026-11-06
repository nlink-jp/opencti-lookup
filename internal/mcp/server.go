package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/pathguard/workdir"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// serverName is what initialize reports, and what a client lists the server as.
const serverName = "opencti-lookup"

// Server is a stdio JSON-RPC 2.0 MCP server.
type Server struct {
	Eng     Engine
	Version string
	// WorkDirs resolves and judges the directory get_report_file writes into
	// (organization ADR-021 / ADR-022). The zero value refuses every call.
	WorkDirs workdir.Resolver
}

// Serve reads newline-delimited JSON-RPC messages until stdin closes, which is
// the shutdown signal.
func (s *Server) Serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if stdin == nil {
		return fmt.Errorf("no input stream: the MCP server reads JSON-RPC from stdin")
	}
	sc := bufio.NewScanner(stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(stdout)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// A malformed frame gets a parse error with a null id, per the
			// JSON-RPC spec. Staying silent would hang the client.
			if err := enc.Encode(errorResponse(nil, -32700, "parse error: "+err.Error())); err != nil {
				return err
			}
			continue
		}
		resp, ok := s.handle(ctx, &req)
		if !ok {
			continue // a notification: no reply
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func errorResponse(id json.RawMessage, code int, msg string) response {
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func okResponse(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

// handle dispatches one message. The second return value is false for
// notifications, which must not be answered.
func (s *Server) handle(ctx context.Context, req *request) (response, bool) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		return okResponse(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": s.Version},
			"instructions":    instructions,
		}), true

	case "notifications/initialized", "notifications/cancelled":
		return response{}, false

	case "ping":
		return okResponse(req.ID, map[string]any{}), true

	case "tools/list":
		return okResponse(req.ID, map[string]any{"tools": toolDefinitions()}), true

	case "tools/call":
		if isNotification {
			return response{}, false
		}
		return s.callTool(ctx, req), true

	default:
		if isNotification {
			return response{}, false
		}
		return errorResponse(req.ID, -32601, "method not found: "+req.Method), true
	}
}

type callParams struct {
	Name      string                     `json:"name"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta"`
}

type metaKey struct{}

// requestMeta is the tools/call request's _meta, where a runtime that knows
// the session's work directory names it (jp.nlink/work_dir, ADR-021 §2).
func requestMeta(ctx context.Context) map[string]json.RawMessage {
	m, _ := ctx.Value(metaKey{}).(map[string]json.RawMessage)
	return m
}

func (s *Server) callTool(ctx context.Context, req *request) response {
	var p callParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errorResponse(req.ID, -32602, "invalid params: "+err.Error())
		}
	}
	result, err := s.dispatch(context.WithValue(ctx, metaKey{}, p.Meta), p.Name, p.Arguments)
	if err != nil {
		// Tool failures are results, not protocol errors: the model has to see
		// them and decide what to do, and a JSON-RPC error would be swallowed
		// by the client instead.
		return okResponse(req.ID, toolError(err))
	}
	// get_usage returns the manual itself, which is Markdown rather than a JSON
	// document. It is told apart here, after dispatch, so that it goes through
	// the same argument check as every other tool.
	if doc, ok := result.(rawText); ok {
		return okResponse(req.ID, toolRawText(string(doc)))
	}
	result, _ = capStrings(result)
	return okResponse(req.ID, toolText(result))
}

// rawText is a tool result that is already the text to return.
type rawText string

// maxResultBytes is the ceiling no tool result may cross. Every client this
// server is used from (gem-agent, lagent, Claude Code) spills a large result
// to a file on its own side, so the ceiling is not the client's budget; it is
// the bound for a result nobody planned for.
const maxResultBytes = 128 << 10

// toolText wraps a payload as MCP text content. A result over the ceiling is
// cut where the cut is clean, and says what it lost: a lookup loses its last
// values, then (for one value) its last items; a search its last rows; an
// object its longest text, then its last external references. A paged list is
// refused instead — dropping rows would make its cursor skip them.
func toolText(v any) map[string]any {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(fmt.Errorf("encode result: %w", err))
	}
	if len(b) > maxResultBytes {
		trimmed, ok := trimTail(v, len(b)-maxResultBytes)
		if !ok {
			return toolError(&argError{code: CodeTooLarge, msg: fmt.Sprintf(
				"the result is %d bytes, over this server's ceiling of %d; ask for less (a smaller limit, fewer values), or read it whole with the CLI's --json", len(b), maxResultBytes)})
		}
		return toolText(trimmed)
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
	}
}

// trimTail makes a result smaller by one clean step and says so in its notes;
// over is how many bytes too large it is. It reports false when nothing can
// be dropped cleanly.
func trimTail(v any, over int) (any, bool) {
	switch r := v.(type) {
	case *engine.LookupResult:
		if len(r.Results) > 1 {
			dropped := r.Results[len(r.Results)-1]
			r.Results = r.Results[:len(r.Results)-1]
			r.Notes = upsertDropped(r.Notes, "values omitted for size (look them up again on their own): ", dropped.Input)
			return r, true
		}
		if len(r.Results) == 1 {
			one := &r.Results[0]
			prefix := "omitted for size from " + one.Input + " (the CLI's ioc --json lists them all): "
			switch {
			case len(one.Indicators) > 0:
				one.Indicators = one.Indicators[:len(one.Indicators)-1]
				r.Notes = upsertDropped(r.Notes, "indicators "+prefix, "1")
			case len(one.PatternMentions) > 0:
				one.PatternMentions = one.PatternMentions[:len(one.PatternMentions)-1]
				r.Notes = upsertDropped(r.Notes, "pattern mentions "+prefix, "1")
			case len(one.Sightings) > 0:
				one.Sightings = one.Sightings[:len(one.Sightings)-1]
				r.Notes = upsertDropped(r.Notes, "sightings "+prefix, "1")
			case len(one.Observables) > 1:
				one.Observables = one.Observables[:len(one.Observables)-1]
				r.Notes = upsertDropped(r.Notes, "observables "+prefix, "1")
			default:
				return v, false
			}
			return r, true
		}
	case *engine.SearchResult:
		if len(r.Rows) <= 1 {
			return v, false
		}
		r.Rows = r.Rows[:len(r.Rows)-1]
		r.MoreRanked = r.MoreRanked || r.Mode == "fulltext"
		r.Notes = upsertDropped(r.Notes, "rows omitted for size from the end of this list: ", "1")
		return r, true
	case *engine.Entity:
		// Cut the largest of the three parts that can grow — the description,
		// the pattern, the external references taken together — one step at a
		// time. The part that is the weight goes first, so a short description
		// is never emptied to make room for references that were the real
		// weight (the second pre-release review found exactly that).
		const whole = " (the CLI's entity --json returns it whole)"
		refs := 0
		for _, x := range r.ExternalRefs.Items {
			refs += len(x.Source) + len(x.URL) + len(x.ExternalID) + len(x.Description) + 64
		}
		switch {
		case len(r.ExternalRefs.Items) > 0 && refs >= len(r.Description) && refs >= len(r.Pattern):
			r.ExternalRefs.Items = r.ExternalRefs.Items[:len(r.ExternalRefs.Items)-1]
			r.Notes = upsertDropped(r.Notes, "external references omitted for size"+whole+": ", "1")
		case len(r.Description) > 1024 && len(r.Description) >= len(r.Pattern):
			r.Description, r.Notes = shorten(r.Description, over, "description", whole, r.Notes)
		case len(r.Pattern) > 1024:
			r.Pattern, r.Notes = shorten(r.Pattern, over, "pattern", whole, r.Notes)
		case len(r.ExternalRefs.Items) > 0:
			r.ExternalRefs.Items = r.ExternalRefs.Items[:len(r.ExternalRefs.Items)-1]
			r.Notes = upsertDropped(r.Notes, "external references omitted for size"+whole+": ", "1")
		default:
			return v, false
		}
		return r, true
	}
	return v, false
}

// shorten cuts s by at least over bytes (plus room for the note), on a rune
// boundary, and records the cut once with the original length.
func shorten(s string, over int, field, whole string, notes []string) (string, []string) {
	keep := len(s) - over - 512
	if keep < 0 {
		keep = 0
	}
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	prefix := field + " shortened to fit this server's 128 KB ceiling" + whole + "; original length "
	for _, n := range notes {
		if strings.HasPrefix(n, prefix) {
			return s[:keep] + "…", notes
		}
	}
	return s[:keep] + "…", append(notes, fmt.Sprintf("%s%d bytes", prefix, len(s)))
}

// upsertDropped keeps one note per kind of omission and grows it.
func upsertDropped(notes []string, prefix, item string) []string {
	for i, n := range notes {
		if strings.HasPrefix(n, prefix) {
			rest := strings.TrimPrefix(n, prefix)
			if item == "1" {
				var count int
				if _, err := fmt.Sscanf(rest, "%d", &count); err == nil {
					notes[i] = fmt.Sprintf("%s%d", prefix, count+1)
					return notes
				}
			}
			notes[i] = n + ", " + item
			return notes
		}
	}
	return append(notes, prefix+item)
}

func toolRawText(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
}

func toolError(err error) map[string]any {
	b, mErr := json.Marshal(structuredError(err))
	text := string(b)
	if mErr != nil {
		text = `{"code":"internal_error","message":"could not encode the error"}`
	}
	return map[string]any{
		"isError": true,
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}
