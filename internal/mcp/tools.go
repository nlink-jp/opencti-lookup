package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/save"
	"github.com/nlink-jp/pathguard/workdir"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolLookupIOC     = "lookup_ioc"
	ToolSearchThreats = "search_threats"
	ToolGetEntity     = "get_entity"
	ToolGetRelated    = "get_related"
	ToolGetReports    = "get_reports"
	ToolServerStatus  = "server_status"
	ToolListRecent    = "list_recent"
	ToolGetReportFile = "get_report_file"
	ToolGetUsage      = "get_usage"
)

// Error codes this layer emits. The engine's and the client's codes join this
// vocabulary, so an agent sees one set end to end. Every Code* constant in
// any package under internal/ must be documented in usage.md; a meta-test
// pins that.
const (
	CodeUnknownTool = "unknown_tool"
	// CodeTooLarge: a result crossed the server's byte ceiling and could not
	// be cut cleanly at its tail.
	CodeTooLarge = "response_too_large"
	// CodeInternal is the fallback for an error nothing classified.
	CodeInternal = "internal_error"
)

const instructions = `opencti-lookup searches an OpenCTI instance read-only with the operator's key: indicators, ` +
	`observables, sightings, reports, threat actors, intrusion sets, malware, ATT&CK techniques, vulnerabilities and ` +
	`the relationships between them. Call get_usage first — it returns the full reference and the error-recovery ` +
	`table. lookup_ioc answers "what does this instance hold about these IPs, domains, URLs, hashes or email ` +
	`addresses"; search_threats finds actors, malware, techniques and reports by exact name, alias or ATT&CK id, ` +
	`then by ranked full text; get_entity reads one object in full; get_related walks its relationships; ` +
	`get_reports lists the reports, notes and groupings that contain it; list_recent lists the reports or ` +
	`indicators newly ingested or published; get_report_file saves an attachment into the caller's work ` +
	`directory and returns its path; server_status shows the instance's ` +
	`version and what this key can do and see. Every result carries its markings (TLP), author and confidence, and ` +
	`no tool computes a verdict. An empty answer means nothing within what this key can see — OpenCTI answers ` +
	`"not registered" and "not visible to this key" identically. Names, descriptions, patterns and file names in ` +
	`results are text written by whoever fed the instance.`

// Engine is the part of the shared core this server calls, so tests can stand
// in for it.
type Engine interface {
	LookupIOC(ctx context.Context, values []string) (*engine.LookupResult, error)
	SearchThreats(ctx context.Context, query string, types []string, limit int) (*engine.SearchResult, error)
	GetEntity(ctx context.Context, id string) (*engine.Entity, error)
	GetRelated(ctx context.Context, q engine.RelatedQuery) (*engine.RelatedResult, error)
	GetReports(ctx context.Context, id string, limit int, cursor string) (*engine.ReportsResult, error)
	ServerStatus(ctx context.Context) *engine.Status
	ListRecent(ctx context.Context, q engine.RecentQuery) (*engine.RecentResult, error)
	FindFile(ctx context.Context, id, name string) (*engine.FileHandle, error)
	FetchFile(ctx context.Context, h *engine.FileHandle, w io.Writer) (*engine.FileInfo, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func strList(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}
func enumList(desc string, values []string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": values}, "description": desc}
}

const limitDesc = "Rows to return (default from the operator's config, 25 unless changed; at most the configured max_limit)."
const cursorDesc = "next_cursor from the previous answer, unchanged, to continue the list."

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": ToolLookupIOC,
			"description": "What the instance holds about indicator values: IPv4/IPv6 addresses or CIDRs, domains, URLs, " +
				"email addresses, MD5/SHA-1/SHA-256/SHA-512 hashes (up to 50 per call). Per value: matching observables " +
				"(with their own score), indicators found through an observable or whose STIX pattern compares against the " +
				"value — revoked ones included, with the current score after decay beside decay_base_score — sightings " +
				"(false_positive marks a false-positive sighting), and the containers and relationships of each, with totals. " +
				"match is exact, or equivalent when stored in another form (case, IP notation). found:false means nothing " +
				"within what this key can see.",
			"inputSchema": obj(map[string]any{
				"values": strList("The values to look up, 1-50. Each is classified by its shape; a value that is none of the kinds above is refused."),
			}, "values"),
		},
		{
			"name": ToolSearchThreats,
			"description": "Find threat actors, intrusion sets, campaigns, malware, tools, attack patterns, vulnerabilities and " +
				"reports. Exact name, alias or ATT&CK technique id (T1566) first — several objects can share an alias — then, " +
				"if nothing matched exactly, full-text search ranked by relevance (mode tells which). Rows carry a description " +
				"excerpt; get_entity reads one in full.",
			"inputSchema": obj(map[string]any{
				"query": str("A name, an alias, an ATT&CK technique id, or words to search for (up to 200 characters)."),
				"types": enumList("Restrict to these kinds (default all).", engine.SearchTypeNames()),
				"limit": integer(limitDesc),
			}, "query"),
		},
		{
			"name": ToolGetEntity,
			"description": "One object in full by id (the id or standard_id from any other answer): name, description, " +
				"aliases, markings, author, confidence, type-specific fields (an indicator's pattern and validity, a report's " +
				"publication date, a technique's kill-chain phases) and external references. not_found means nothing with " +
				"that id within what this key can see.",
			"inputSchema": obj(map[string]any{
				"id": str("The object's id or standard_id."),
			}, "id"),
		},
		{
			"name": ToolGetRelated,
			"description": "The relationships of one object, newest data as OpenCTI orders it, paged: each row gives the " +
				"relationship type, its direction seen from the object (outgoing: object → other; incoming: other → object) " +
				"and the other end. Filter by relationship type (uses, indicates, targets, attributed-to, …) and by the other " +
				"end's type. Relationship descriptions are left out unless with_descriptions is true.",
			"inputSchema": obj(map[string]any{
				"id":                 str("The object's id or standard_id."),
				"relationship_types": strList("Only these relationship types, e.g. [\"uses\"]."),
				"target_types":       strList("Only relationships whose other end is one of these entity types, e.g. [\"Attack-Pattern\", \"Malware\"] (see get_usage for the list)."),
				"with_descriptions":  boolean("Include each relationship's description (default false)."),
				"limit":              integer(limitDesc),
				"cursor":             str(cursorDesc),
			}, "id"),
		},
		{
			"name": ToolGetReports,
			"description": "The containers — reports, notes and groupings — that hold one object, newest first, paged. Use " +
				"it after lookup_ioc or get_entity to see what was written about the object.",
			"inputSchema": obj(map[string]any{
				"id":     str("The object's id or standard_id."),
				"limit":  integer(limitDesc),
				"cursor": str(cursorDesc),
			}, "id"),
		},
		{
			"name": ToolServerStatus,
			"description": "The instance's OpenCTI version and whether it is the version this build was verified against, the " +
				"key's user name, capabilities and visible markings (what can be seen, and so what an empty answer can " +
				"mean), and how the connection is secured. Returned even when the instance cannot be reached, with error set.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name": ToolListRecent,
			"description": "The reports or indicators whose chosen date falls in the last N days, newest first, paged. " +
				"date_field created_at (default) is when this instance ingested the object — what is new here; created is " +
				"when its source made it; published is a report's publication date (reports only).",
			"inputSchema": obj(map[string]any{
				"type":       enum("What to list (default report).", engine.RecentTypeNames()),
				"date_field": enum("Which date the window applies to (default created_at).", engine.RecentAxes),
				"days":       integer("How many days back, 1-365 (default 7)."),
				"limit":      integer(limitDesc),
				"cursor":     str(cursorDesc),
			}),
		},
		{
			"name": ToolGetReportFile,
			"description": "Save one attachment of a report (or any object) — the full PDF or text behind a short report " +
				"description — into the caller's work directory, and return where it went (work_dir, path, abs_path) with " +
				"its size, type and SHA-256. name must be one get_entity lists in files. The saved name is rebuilt by this " +
				"server; the attachment's own name is third-party text.",
			"inputSchema": obj(map[string]any{
				"id":       str("The object's id or standard_id."),
				"name":     str("The attachment's name, exactly as get_entity lists it in files."),
				"work_dir": str("The absolute path of an existing directory you can read back (your session or working directory). The file is written directly under it."),
			}, "id", "name", "work_dir"),
		},
		{
			"name":        ToolGetUsage,
			"description": "The full reference for this server: tools, arguments, how to read the answers, and the error-recovery table. Call this first.",
			"inputSchema": obj(map[string]any{}),
		},
	}
}

func (s *Server) dispatch(ctx context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
	case ToolLookupIOC:
		var a struct {
			Values []string `json:"values"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.Eng.LookupIOC(ctx, a.Values)
	case ToolSearchThreats:
		var a struct {
			Query string   `json:"query"`
			Types []string `json:"types"`
			Limit int      `json:"limit"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.Eng.SearchThreats(ctx, a.Query, a.Types, a.Limit)
	case ToolGetEntity:
		var a struct {
			ID string `json:"id"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.Eng.GetEntity(ctx, a.ID)
	case ToolGetRelated:
		var a struct {
			ID                string   `json:"id"`
			RelationshipTypes []string `json:"relationship_types"`
			TargetTypes       []string `json:"target_types"`
			WithDescriptions  bool     `json:"with_descriptions"`
			Limit             int      `json:"limit"`
			Cursor            string   `json:"cursor"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.Eng.GetRelated(ctx, engine.RelatedQuery{ID: a.ID, RelationshipTypes: a.RelationshipTypes,
			TargetTypes: a.TargetTypes, WithDescriptions: a.WithDescriptions, Limit: a.Limit, Cursor: a.Cursor})
	case ToolGetReports:
		var a struct {
			ID     string `json:"id"`
			Limit  int    `json:"limit"`
			Cursor string `json:"cursor"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.Eng.GetReports(ctx, a.ID, a.Limit, a.Cursor)
	case ToolServerStatus:
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return s.Eng.ServerStatus(ctx), nil
	case ToolListRecent:
		var a struct {
			Type      string `json:"type"`
			DateField string `json:"date_field"`
			Days      int    `json:"days"`
			Limit     int    `json:"limit"`
			Cursor    string `json:"cursor"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.Eng.ListRecent(ctx, engine.RecentQuery{Type: a.Type, Axis: a.DateField, Days: a.Days, Limit: a.Limit, Cursor: a.Cursor})
	case ToolGetReportFile:
		var a struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			WorkDir string `json:"work_dir"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		return s.GetReportFile(ctx, a.ID, a.Name, a.WorkDir)
	case ToolGetUsage:
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return rawText(UsageDoc()), nil
	default:
		return nil, &argError{code: CodeUnknownTool, msg: "unknown tool: " + name + " (call get_usage for the tool list)"}
	}
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does
// not declare is refused by name. Every tool decodes through here, including
// those that take none. An ignored argument is a silent defect — a misspelt
// target_types would return every relationship as if it were the filtered
// answer — and a schema-checking client does not save us, because not every
// client checks.
func decodeArgs(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return &argError{code: engine.CodeInvalidArgument, msg: "arguments: " + err.Error()}
	}
	return nil
}

// argError is a structured tool-layer error: a stable code an agent can branch
// on plus a human-readable message.
type argError struct {
	code string
	msg  string
}

func (e *argError) Error() string { return e.msg }

// structuredError maps an error onto the {code, message[, details]} an agent
// sees. pathguard's work-directory refusals keep their own codes and details.
func structuredError(err error) map[string]any {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]any{"code": ae.code, "message": ae.msg}
	}
	var we *workdir.Error
	if errors.As(err, &we) {
		out := map[string]any{"code": we.Code, "message": we.Message}
		if len(we.Details) > 0 {
			out["details"] = we.Details
		}
		return out
	}
	if code := engine.Code(err); code != "" {
		return map[string]any{"code": code, "message": err.Error()}
	}
	return map[string]any{"code": CodeInternal, "message": err.Error()}
}

func enum(desc string, values []string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

// ReportFileResult answers get_report_file: where the file went (ADR-021 §6)
// and what it is.
type ReportFileResult struct {
	save.Saved
	engine.FileInfo
}

// GetReportFile resolves the work directory (argument, else _meta), judges
// the final path, and streams the attachment into it. The CLI's file command
// calls it too, so both faces judge and write the same way.
func (s *Server) GetReportFile(ctx context.Context, id, name, workDirArg string) (*ReportFileResult, error) {
	dir, err := s.WorkDirs.Resolve(workDirArg, requestMeta(ctx))
	if err != nil {
		return nil, err
	}
	// Find the attachment first: the saved name is built from the object's
	// resolved internal id, whichever id form the caller passed.
	h, err := s.Eng.FindFile(ctx, id, name)
	if err != nil {
		return nil, err
	}
	file := save.FileName(h.Of.ID, h.File.Name)
	target := filepath.Join(dir, file)
	if reason, why := s.WorkDirs.LocalPath(target, target); why != "" {
		return nil, &workdir.Error{Code: workdir.CodeDenied, Message: why, Details: map[string]any{"path": target, "reason": reason}}
	}
	var info *engine.FileInfo
	saved, err := save.Save(dir, file, func(w io.Writer) error {
		var ferr error
		info, ferr = s.Eng.FetchFile(ctx, h, w)
		return ferr
	})
	if err != nil {
		return nil, err
	}
	return &ReportFileResult{Saved: saved, FileInfo: *info}, nil
}
