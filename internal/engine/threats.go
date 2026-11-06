package engine

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SearchTypes maps search_threats' type enum to OpenCTI entity types.
var SearchTypes = map[string][]string{
	"intrusion-set":  {"Intrusion-Set"},
	"threat-actor":   {"Threat-Actor-Group", "Threat-Actor-Individual"},
	"campaign":       {"Campaign"},
	"malware":        {"Malware"},
	"tool":           {"Tool"},
	"attack-pattern": {"Attack-Pattern"},
	"vulnerability":  {"Vulnerability"},
	"report":         {"Report"},
}

// SearchTypeNames is SearchTypes' keys, sorted (for schemas and messages).
func SearchTypeNames() []string {
	names := make([]string, 0, len(SearchTypes))
	for k := range SearchTypes {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// excerptRunes is how much of a description a search row carries; get_entity
// returns it whole.
const excerptRunes = 280

// SearchResult answers search_threats.
type SearchResult struct {
	Query string      `json:"query"`
	Mode  string      `json:"mode"` // exact | fulltext
	Rows  []ThreatRow `json:"results"`
	// MoreRanked: full-text search has further, weaker matches. OpenCTI's
	// total for a full-text search counts any word's hit and is not a match
	// count (Phase 0 §5), so it is not reported as one.
	MoreRanked bool     `json:"more_ranked,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// ThreatRow is one search hit.
type ThreatRow struct {
	Ref
	Aliases   []string `json:"aliases,omitempty"`
	Excerpt   string   `json:"description_excerpt,omitempty"`
	CreatedBy string   `json:"created_by,omitempty"`
	MatchedOn string   `json:"matched_on,omitempty"` // exact mode: name | alias | mitre_id
}

// description is per type, not on the StixDomainObject interface (6.7.4
// rejects it there with GRAPHQL_VALIDATION_FAILED), so each fragment asks.
const threatRowFields = `id entity_type representative { main } objectMarking { definition } createdBy { name }
  ... on IntrusionSet { name aliases description } ... on ThreatActor { name aliases description }
  ... on Campaign { name aliases description } ... on Malware { name aliases description }
  ... on Tool { name aliases description } ... on AttackPattern { name x_mitre_id description }
  ... on Vulnerability { name description } ... on Report { name description }`

type wireThreat struct {
	wireRef
	Name          string    `json:"name"`
	Aliases       []string  `json:"aliases"`
	Description   string    `json:"description"`
	ObjectMarking []marking `json:"objectMarking"`
	CreatedBy     *named    `json:"createdBy"`
}

var mitreID = regexp.MustCompile(`(?i)^(T\d{4}(\.\d{3})?|TA\d{4}|[GSMC]\d{4})$`)

// SearchThreats finds threat entities by exact name, alias or ATT&CK id
// first, and falls back to ranked full-text search.
func (e *Engine) SearchThreats(ctx context.Context, query string, types []string, limit int) (*SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, invalid("query is required")
	}
	if len([]rune(query)) > 200 {
		return nil, invalid("query is longer than 200 characters")
	}
	n, err := e.limit(limit)
	if err != nil {
		return nil, err
	}
	var octTypes []string
	if len(types) == 0 {
		types = SearchTypeNames()
	}
	for _, t := range types {
		mapped, ok := SearchTypes[t]
		if !ok {
			return nil, invalid("unknown type %q (one of %s)", t, strings.Join(SearchTypeNames(), ", "))
		}
		octTypes = append(octTypes, mapped...)
	}

	q := `query Search($types: [String], $filters: FilterGroup, $search: String, $first: Int) {
  stixDomainObjects(types: $types, filters: $filters, search: $search, first: $first) {
    pageInfo { globalCount }
    edges { node { ` + threatRowFields + ` } }
  }
}`
	var out struct {
		Conn struct {
			PageInfo pageInfo `json:"pageInfo"`
			Edges    []struct {
				Node wireThreat `json:"node"`
			} `json:"edges"`
		} `json:"stixDomainObjects"`
	}

	exact := []any{}
	for _, k := range []string{"name", "aliases", "x_opencti_aliases"} {
		exact = append(exact, map[string]any{"key": []string{k}, "values": []string{query}, "operator": "eq"})
	}
	notes := []string{}
	if mitreID.MatchString(query) {
		exact = append(exact, map[string]any{"key": []string{"x_mitre_id"}, "values": []string{query}, "operator": "eq"})
		if !strings.HasPrefix(strings.ToUpper(query), "T") {
			notes = append(notes, "ATT&CK ids are matched on attack patterns only; a group or software id (G…, S…) is found by name or alias instead")
		}
	}
	filters := map[string]any{"mode": "or", "filterGroups": []any{}, "filters": exact}
	if err := e.query(ctx, q, map[string]any{"types": octTypes, "filters": filters, "first": n}, &out); err != nil {
		return nil, err
	}
	res := &SearchResult{Query: query, Mode: "exact", Rows: []ThreatRow{}, Notes: notes}
	if len(out.Conn.Edges) == 0 {
		res.Mode = "fulltext"
		out.Conn.Edges = nil
		if err := e.query(ctx, q, map[string]any{"types": octTypes, "search": query, "first": n}, &out); err != nil {
			return nil, err
		}
		res.MoreRanked = out.Conn.PageInfo.GlobalCount > len(out.Conn.Edges)
		res.Notes = append(res.Notes, "no exact name, alias or ATT&CK id matched; these are full-text matches ranked by relevance, weakest last")
	} else if out.Conn.PageInfo.GlobalCount > len(out.Conn.Edges) {
		res.Notes = append(res.Notes, fmt.Sprintf("%d exact matches, %d listed; raise limit", out.Conn.PageInfo.GlobalCount, len(out.Conn.Edges)))
	}
	for _, edge := range out.Conn.Edges {
		w := edge.Node
		row := ThreatRow{Ref: ref(w.wireRef), Aliases: w.Aliases, Excerpt: excerpt(w.Description), CreatedBy: author(w.CreatedBy)}
		row.Markings = markings(w.ObjectMarking)
		if res.Mode == "exact" {
			row.MatchedOn = matchedOn(query, w)
		}
		res.Rows = append(res.Rows, row)
	}
	return res, nil
}

func matchedOn(q string, w wireThreat) string {
	switch {
	case strings.EqualFold(w.Name, q) || strings.EqualFold(w.Representative.Main, q):
		return "name"
	case strings.EqualFold(w.XMitreID, q):
		return "mitre_id"
	}
	for _, a := range w.Aliases {
		if strings.EqualFold(a, q) {
			return "alias"
		}
	}
	return "alias"
}

func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > excerptRunes {
		return string(r[:excerptRunes]) + "…"
	}
	return s
}

// --- get_entity -----------------------------------------------------------

// Entity is one object in detail.
type Entity struct {
	Ref
	StandardID      string       `json:"standard_id"`
	Name            string       `json:"name,omitempty"`
	Description     string       `json:"description,omitempty"`
	Aliases         []string     `json:"aliases,omitempty"`
	Labels          []string     `json:"labels,omitempty"`
	CreatedBy       string       `json:"created_by,omitempty"`
	Confidence      *int         `json:"confidence,omitempty"`
	Revoked         bool         `json:"revoked,omitempty"`
	Created         string       `json:"created,omitempty"`
	Modified        string       `json:"modified,omitempty"`
	CreatedAt       string       `json:"created_at,omitempty"`
	FirstSeen       string       `json:"first_seen,omitempty"`
	LastSeen        string       `json:"last_seen,omitempty"`
	Published       string       `json:"published,omitempty"`
	ReportTypes     []string     `json:"report_types,omitempty"`
	IsFamily        *bool        `json:"is_family,omitempty"`
	MalwareTypes    []string     `json:"malware_types,omitempty"`
	Platforms       []string     `json:"platforms,omitempty"`
	KillChain       []string     `json:"kill_chain_phases,omitempty"`
	Pattern         string       `json:"pattern,omitempty"`
	PatternType     string       `json:"pattern_type,omitempty"`
	ValidFrom       string       `json:"valid_from,omitempty"`
	ValidUntil      string       `json:"valid_until,omitempty"`
	Score           *int         `json:"score,omitempty"`
	DecayBase       *int         `json:"decay_base_score,omitempty"`
	ObservableValue string       `json:"observable_value,omitempty"`
	ExternalRefs    ExternalRefs `json:"external_references"`
	Files           []FileRef    `json:"files"` // attachments; get_report_file saves one
	Notes           []string     `json:"notes,omitempty"`
}

// ExternalRefs lists external references with their total.
type ExternalRefs struct {
	Total int           `json:"total"`
	Items []ExternalRef `json:"items"`
}

// ExternalRef is a citation.
type ExternalRef struct {
	Source      string `json:"source"`
	URL         string `json:"url,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
	Description string `json:"description,omitempty"`
}

const entityQuery = `query Entity($id: String!) {
  stixCoreObject(id: $id) {
    ` + refFields + ` standard_id created_at
    objectMarking { definition } objectLabel { value } createdBy { name }
    externalReferences(first: 100) { pageInfo { globalCount } edges { node { source_name url external_id description } } }
    importFiles(first: 100) { edges { node { id name size lastModified metaData { mimetype } } } }
    ... on StixDomainObject { confidence revoked created modified }
    ... on StixCyberObservable { observable_value x_opencti_score x_opencti_description }
    ... on IntrusionSet { name aliases description first_seen last_seen }
    ... on ThreatActor { name aliases description first_seen last_seen }
    ... on Campaign { name aliases description first_seen last_seen }
    ... on Malware { name aliases description is_family malware_types first_seen last_seen }
    ... on Tool { name aliases description }
    ... on AttackPattern { name description x_mitre_platforms killChainPhases { kill_chain_name phase_name } }
    ... on Vulnerability { name description }
    ... on Report { name description published report_types }
    ... on Grouping { name description }
    ... on CourseOfAction { name description }
    ... on Identity { name description }
    ... on Location { name description }
    ... on Incident { name description }
    ... on Infrastructure { name description }
    ... on Note { attribute_abstract content }
    ... on Indicator { name description pattern pattern_type valid_from valid_until x_opencti_score decay_base_score }
  }
}`

type wireEntity struct {
	wireRef
	StandardID    string    `json:"standard_id"`
	CreatedAt     string    `json:"created_at"`
	ObjectMarking []marking `json:"objectMarking"`
	ObjectLabel   []label   `json:"objectLabel"`
	CreatedBy     *named    `json:"createdBy"`
	ImportFiles   wireFiles `json:"importFiles"`
	ExternalRefs  struct {
		PageInfo pageInfo `json:"pageInfo"`
		Edges    []struct {
			Node struct {
				SourceName  string `json:"source_name"`
				URL         string `json:"url"`
				ExternalID  string `json:"external_id"`
				Description string `json:"description"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"externalReferences"`
	Confidence      *int     `json:"confidence"`
	Revoked         bool     `json:"revoked"`
	Created         string   `json:"created"`
	Modified        string   `json:"modified"`
	Description     string   `json:"description"`
	ObservableValue string   `json:"observable_value"`
	ObservableDesc  string   `json:"x_opencti_description"`
	Name            string   `json:"name"`
	Aliases         []string `json:"aliases"`
	FirstSeen       string   `json:"first_seen"`
	LastSeen        string   `json:"last_seen"`
	IsFamily        *bool    `json:"is_family"`
	MalwareTypes    []string `json:"malware_types"`
	Platforms       []string `json:"x_mitre_platforms"`
	KillChain       []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"killChainPhases"`
	Published   string   `json:"published"`
	ReportTypes []string `json:"report_types"`
	Abstract    string   `json:"attribute_abstract"`
	Content     string   `json:"content"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	ValidFrom   string   `json:"valid_from"`
	ValidUntil  string   `json:"valid_until"`
	Score       *int     `json:"x_opencti_score"`
	DecayBase   *int     `json:"decay_base_score"`
}

// GetEntity returns one object in detail.
func (e *Engine) GetEntity(ctx context.Context, id string) (*Entity, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, invalid("id is required")
	}
	var out struct {
		Obj *wireEntity `json:"stixCoreObject"`
	}
	if err := e.query(ctx, entityQuery, map[string]any{"id": id}, &out); err != nil {
		return nil, err
	}
	if out.Obj == nil {
		return nil, &Error{Code: CodeNotFound, Message: fmt.Sprintf("no object %q within what this key can see (it may not exist, or this key may not be allowed to see it)", id)}
	}
	w := out.Obj
	ent := &Entity{
		Ref: ref(w.wireRef), StandardID: w.StandardID, Name: w.Name, Aliases: w.Aliases,
		Labels: labels(w.ObjectLabel), CreatedBy: author(w.CreatedBy), Confidence: w.Confidence, Revoked: w.Revoked,
		Created: w.Created, Modified: w.Modified, CreatedAt: w.CreatedAt, FirstSeen: bounded(w.FirstSeen), LastSeen: bounded(w.LastSeen),
		Published: w.Published, ReportTypes: w.ReportTypes, IsFamily: w.IsFamily, MalwareTypes: w.MalwareTypes,
		Platforms: w.Platforms, Pattern: w.Pattern, PatternType: w.PatternType, ValidFrom: w.ValidFrom,
		ValidUntil: w.ValidUntil, Score: w.Score, DecayBase: w.DecayBase, ObservableValue: w.ObservableValue,
		Description:  w.Description,
		ExternalRefs: ExternalRefs{Total: w.ExternalRefs.PageInfo.GlobalCount, Items: []ExternalRef{}},
		Files:        w.ImportFiles.refs(),
	}
	ent.Markings = markings(w.ObjectMarking)
	switch {
	case ent.Description != "":
	case w.Abstract != "" || w.Content != "":
		ent.Description = strings.TrimSpace(w.Abstract + "\n\n" + w.Content)
	case w.ObservableDesc != "":
		ent.Description = w.ObservableDesc
	}
	for _, k := range w.KillChain {
		ent.KillChain = append(ent.KillChain, k.KillChainName+":"+k.PhaseName)
	}
	for _, edge := range w.ExternalRefs.Edges {
		n := edge.Node
		ent.ExternalRefs.Items = append(ent.ExternalRefs.Items, ExternalRef{Source: n.SourceName, URL: n.URL, ExternalID: n.ExternalID, Description: n.Description})
	}
	return ent, nil
}
