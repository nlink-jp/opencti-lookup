// Package engine is the core shared by the CLI and the MCP server, so that the
// two faces cannot give different answers for the same input. It turns a
// question into OpenCTI GraphQL queries and the replies into complete views;
// what one MCP result may cost in a client's context is decided later, at the
// MCP boundary.
//
// Every rule here comes from the Phase 0 measurements against OpenCTI 6.7.4
// (docs/ja/opencti-lookup-phase0.ja.md): IOC lookups go through observables
// and indicators both; stored values are asked for in every form; a short
// answer is detected by comparing the total with what was received, never by
// hasNextPage; inputs OpenCTI would answer with a silent zero are refused
// before sending; a missing object is not_found, not an empty list.
package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// VerifiedVersion is the OpenCTI version this build was measured against.
const VerifiedVersion = "6.7.4"

// Error codes the engine emits; the client's (opencti.Code*) pass through.
const (
	// CodeInvalidArgument: an input was refused before anything was sent.
	CodeInvalidArgument = "invalid_argument"
	// CodeNotFound: the id names nothing this key can see.
	CodeNotFound = "not_found"
	// CodeNotConfigured: the URL or the token is missing.
	CodeNotConfigured = "not_configured"
)

// Querier is the part of the OpenCTI client the engine uses.
type Querier interface {
	Query(ctx context.Context, query string, vars map[string]any, out any) error
}

// Engine answers questions against one instance.
type Engine struct {
	Client Querier
	Cfg    *config.Config
}

// Error is an engine-level failure with a stable code.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func invalid(format string, a ...any) error {
	return &Error{Code: CodeInvalidArgument, Message: fmt.Sprintf(format, a...)}
}

// Code returns the stable code of err: the engine's, the client's, or "".
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	var nc *config.NotConfiguredError
	if errors.As(err, &nc) {
		return CodeNotConfigured
	}
	return opencti.Code(err)
}

// ready refuses to query an instance that is not configured.
func (e *Engine) ready() error {
	if err := e.Cfg.Ready(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) query(ctx context.Context, q string, vars map[string]any, out any) error {
	if err := e.ready(); err != nil {
		return err
	}
	return e.Client.Query(ctx, q, vars, out)
}

// limit resolves a requested row count against the configured default and
// ceiling. 0 means "the default"; anything else must be 1..MaxLimit.
func (e *Engine) limit(n int) (int, error) {
	if n == 0 {
		return e.Cfg.DefaultLimit, nil
	}
	if n < 1 || n > e.Cfg.MaxLimit {
		return 0, invalid("limit must be 1-%d (got %d)", e.Cfg.MaxLimit, n)
	}
	return n, nil
}

// --- paging ---------------------------------------------------------------

// cursor is this tool's own continuation token: OpenCTI's cursor plus how many
// rows were already handed out. hasNextPage is not trusted (Phase 0 §6: it is
// false when OpenCTI truncated a page, and true for a two-item list of two),
// so whether more remains is computed from the total.
type cursor struct {
	After string `json:"a"`
	Seen  int    `json:"s"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	if s == "" {
		return cursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	var c cursor
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.Seen < 0 || c.After == "" {
		return cursor{}, invalid("cursor is not one this tool issued (pass next_cursor from a previous answer unchanged)")
	}
	return c, nil
}

// Page says how much of a list was returned and how to get the rest.
type Page struct {
	Total      int    `json:"total"`
	Returned   int    `json:"returned"`
	Remaining  int    `json:"remaining"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func pageOf(total, returned int, prev cursor, endCursor string) Page {
	seen := prev.Seen + returned
	p := Page{Total: total, Returned: returned}
	if total > seen {
		p.Remaining = total - seen
		if returned > 0 && endCursor != "" {
			p.NextCursor = encodeCursor(cursor{After: endCursor, Seen: seen})
		}
	}
	return p
}

// --- shared wire shapes ---------------------------------------------------

type pageInfo struct {
	GlobalCount int    `json:"globalCount"`
	EndCursor   string `json:"endCursor"`
}

type marking struct {
	Definition string `json:"definition"`
}

type named struct {
	Name string `json:"name"`
}

type label struct {
	Value string `json:"value"`
}

type representative struct {
	Main string `json:"main"`
}

// wireRef is one end of a relationship or sighting.
type wireRef struct {
	ID             string         `json:"id"`
	EntityType     string         `json:"entity_type"`
	Representative representative `json:"representative"`
	XMitreID       string         `json:"x_mitre_id"`
}

func markings(ms []marking) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Definition)
	}
	return out
}

func labels(ls []label) []string {
	if len(ls) == 0 {
		return nil
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Value)
	}
	return out
}

func author(n *named) string {
	if n == nil {
		return ""
	}
	return n.Name
}

// Ref is a compact pointer to another object.
type Ref struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	MitreID  string   `json:"mitre_id,omitempty"`
	Markings []string `json:"markings,omitempty"`
}

func ref(w wireRef) Ref {
	return Ref{ID: w.ID, Type: w.EntityType, Name: w.Representative.Main, MitreID: w.XMitreID}
}

// refFields selects what Ref reads, for any object or relationship end.
const refFields = `... on BasicObject { id entity_type } ... on StixCoreObject { representative { main } } ... on AttackPattern { x_mitre_id }`

// filterEq builds a one-filter group.
func filterEq(key string, values ...string) map[string]any {
	return map[string]any{"mode": "and", "filterGroups": []any{}, "filters": []any{
		map[string]any{"key": []string{key}, "values": values, "operator": "eq", "mode": "or"},
	}}
}

// exists resolves an id to the object it names, or not_found. Every tool that
// takes an id asks this first: OpenCTI answers a relationship or container
// query about a nonexistent id with zero rows and no error (Phase 0 §2).
func (e *Engine) exists(ctx context.Context, id string) (Ref, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Ref{}, invalid("id is required")
	}
	var out struct {
		Obj *struct {
			wireRef
			ObjectMarking []marking `json:"objectMarking"`
		} `json:"stixCoreObject"`
	}
	q := `query Exists($id: String!) { stixCoreObject(id: $id) { ` + refFields + ` objectMarking { definition } } }`
	if err := e.query(ctx, q, map[string]any{"id": id}, &out); err != nil {
		return Ref{}, err
	}
	if out.Obj == nil {
		return Ref{}, &Error{Code: CodeNotFound, Message: fmt.Sprintf("no object %q within what this key can see (it may not exist, or this key may not be allowed to see it)", id)}
	}
	r := ref(out.Obj.wireRef)
	r.Markings = markings(out.Obj.ObjectMarking)
	return r, nil
}
