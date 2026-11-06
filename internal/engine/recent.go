package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RecentTypes are the kinds list_recent lists, and the date axes each one
// has. OpenCTI answers a filter on an axis a type lacks (an indicator's
// published) with zero rows and no error (Phase 0 §8), so the pairs are
// checked here.
var RecentTypes = map[string][]string{
	"report":    {"created_at", "created", "published"},
	"indicator": {"created_at", "created"},
}

// RecentAxes are every axis list_recent accepts, for schemas and messages.
var RecentAxes = []string{"created_at", "created", "published"}

// MaxRecentDays bounds how far back list_recent looks.
const MaxRecentDays = 365

// DefaultRecentDays is the window when the caller gives none.
const DefaultRecentDays = 7

// recentTimeLayout is how list_recent writes the window's bounds.
const recentTimeLayout = "2006-01-02T15:04:05.000Z"

// now is replaced in tests.
var now = time.Now

// RecentQuery is list_recent's input.
type RecentQuery struct {
	Type   string // report (default) | indicator
	Axis   string // created_at (default) | created | published
	Days   int    // 1-365, default 7
	Limit  int
	Cursor string
}

// RecentResult answers list_recent.
type RecentResult struct {
	Type  string      `json:"type"`
	Axis  string      `json:"axis"`
	Days  int         `json:"days"`
	Since string      `json:"since"`
	Until string      `json:"until"`
	Rows  []RecentRow `json:"items"`
	Page
}

// RecentRow is one recent object.
type RecentRow struct {
	Ref
	CreatedAt   string   `json:"created_at,omitempty"`
	Created     string   `json:"created,omitempty"`
	Published   string   `json:"published,omitempty"`
	CreatedBy   string   `json:"created_by,omitempty"`
	ReportTypes []string `json:"report_types,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Score       *int     `json:"score,omitempty"`
	Revoked     bool     `json:"revoked,omitempty"`
}

// RecentTypeNames lists RecentTypes' keys, sorted.
func RecentTypeNames() []string {
	names := make([]string, 0, len(RecentTypes))
	for k := range RecentTypes {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ListRecent lists the reports or indicators whose chosen date falls in the
// last N days, newest first.
func (e *Engine) ListRecent(ctx context.Context, q RecentQuery) (*RecentResult, error) {
	if q.Type == "" {
		q.Type = "report"
	}
	if q.Axis == "" {
		q.Axis = "created_at"
	}
	if q.Days == 0 {
		q.Days = DefaultRecentDays
	}
	axes, ok := RecentTypes[q.Type]
	if !ok {
		return nil, invalid("type must be one of %s (got %q)", strings.Join(RecentTypeNames(), ", "), q.Type)
	}
	if !contains(axes, q.Axis) {
		return nil, invalid("a %s has no %q date; use one of %s (OpenCTI would answer an absent date with no rows, not an error)", q.Type, q.Axis, strings.Join(axes, ", "))
	}
	if q.Days < 1 || q.Days > MaxRecentDays {
		return nil, invalid("days must be 1-%d (got %d)", MaxRecentDays, q.Days)
	}
	n, err := e.limit(q.Limit)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(q.Cursor, fingerprint("recent", q.Type, q.Axis, fmt.Sprint(q.Days)))
	if err != nil {
		return nil, err
	}
	// The window is [until - days, until], with until the first page's time:
	// a continuation keeps it, so later arrivals neither enter the count nor
	// the pages. A cursor's until is checked: it must be a time this tool
	// wrote and not in the future (a forged one would yield a silent zero or a
	// DATABASE_ERROR, or step outside the 1-365-day bound).
	until := now().UTC()
	if cur.Until != "" {
		t, err := time.Parse(recentTimeLayout, cur.Until)
		if err != nil || t.After(now().UTC().Add(5*time.Minute)) {
			return nil, invalid("cursor is not one this tool issued (pass next_cursor from a previous answer unchanged)")
		}
		until = t
	}
	cur.Until = until.Format(recentTimeLayout)
	since := until.Add(-time.Duration(q.Days) * 24 * time.Hour).Format(recentTimeLayout)

	root, fields := "reports", `published report_types`
	if q.Type == "indicator" {
		root, fields = "indicators", `pattern x_opencti_score revoked`
	}
	// The axis is one of a closed list, so placing it in the document is safe;
	// GraphQL enums cannot be passed as strings in variables of this shape.
	query := fmt.Sprintf(`query Recent($filters: FilterGroup, $first: Int, $after: ID) {
  %s(filters: $filters, first: $first, after: $after, orderBy: %s, orderMode: desc) {
    pageInfo { globalCount endCursor }
    edges { node { id entity_type representative { main } created created_at objectMarking { definition } createdBy { name } %s } }
  }
}`, root, q.Axis, fields)
	vars := map[string]any{
		"filters": map[string]any{"mode": "and", "filterGroups": []any{}, "filters": []any{
			map[string]any{"key": []string{q.Axis}, "values": []string{since}, "operator": "gte"},
			map[string]any{"key": []string{q.Axis}, "values": []string{cur.Until}, "operator": "lte"},
		}},
		"first": n,
	}
	if cur.After != "" {
		vars["after"] = cur.After
	}
	var out map[string]struct {
		PageInfo pageInfo `json:"pageInfo"`
		Edges    []struct {
			Node struct {
				wireRef
				Created       string    `json:"created"`
				CreatedAt     string    `json:"created_at"`
				Published     string    `json:"published"`
				ReportTypes   []string  `json:"report_types"`
				Pattern       string    `json:"pattern"`
				Score         *int      `json:"x_opencti_score"`
				Revoked       bool      `json:"revoked"`
				ObjectMarking []marking `json:"objectMarking"`
				CreatedBy     *named    `json:"createdBy"`
			} `json:"node"`
		} `json:"edges"`
	}
	if err := e.query(ctx, query, vars, &out); err != nil {
		return nil, err
	}
	conn := out[root]
	res := &RecentResult{Type: q.Type, Axis: q.Axis, Days: q.Days, Since: since, Until: cur.Until, Rows: []RecentRow{}}
	for _, edge := range conn.Edges {
		w := edge.Node
		r := RecentRow{Ref: ref(w.wireRef), CreatedAt: w.CreatedAt, Created: w.Created, Published: w.Published,
			CreatedBy: author(w.CreatedBy), ReportTypes: w.ReportTypes, Pattern: w.Pattern, Score: w.Score, Revoked: w.Revoked}
		r.Markings = markings(w.ObjectMarking)
		res.Rows = append(res.Rows, r)
	}
	res.Page = pageOf(conn.PageInfo.GlobalCount, len(res.Rows), n, cur, conn.PageInfo.EndCursor)
	return res, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
