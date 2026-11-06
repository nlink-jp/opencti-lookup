package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/nlink-jp/opencti-lookup/internal/engine"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolLookupIOC     = "lookup_ioc"
	ToolSearchThreats = "search_threats"
	ToolGetEntity     = "get_entity"
	ToolGetRelated    = "get_related"
	ToolGetReports    = "get_reports"
	ToolServerStatus  = "server_status"
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
	`get_reports lists the reports, notes and groupings that contain it; server_status shows the instance's ` +
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

// structuredError maps an error onto the {code, message} pair an agent sees.
func structuredError(err error) map[string]string {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]string{"code": ae.code, "message": ae.msg}
	}
	if code := engine.Code(err); code != "" {
		return map[string]string{"code": code, "message": err.Error()}
	}
	return map[string]string{"code": CodeInternal, "message": err.Error()}
}
