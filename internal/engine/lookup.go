package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nlink-jp/opencti-lookup/internal/ioc"
)

// MaxLookupValues bounds one lookup call.
const MaxLookupValues = 50

// candidateRows is how many observables, indicators and sightings one lookup
// asks for in each query. A lookup of up to 50 values that matches more than
// this is reported as truncated, never silently cut.
const candidateRows = 500

// Up to 10 containers and relationships are listed under each observable and
// indicator (the "first: 10" in the queries below); their totals are always
// reported, and get_reports / get_related read the rest.

// NotFoundNote is what a value with no match carries.
const NotFoundNote = "nothing within what this key can see: OpenCTI answers \"not registered\" and \"not visible to this key\" identically"

// LookupResult answers lookup_ioc.
type LookupResult struct {
	Results []IOCResult `json:"results"`
	Notes   []string    `json:"notes,omitempty"`
}

// IOCResult is everything found for one input value.
type IOCResult struct {
	Input string   `json:"input"`
	Kind  ioc.Kind `json:"kind"`
	Found bool     `json:"found"`
	// Inconclusive: nothing was found, but a candidate list was cut, so the
	// value may be among what was not read. Never presented as "not found".
	Inconclusive    bool         `json:"inconclusive,omitempty"`
	Note            string       `json:"note,omitempty"`
	Observables     []Observable `json:"observables"`
	Indicators      []Indicator  `json:"indicators"`
	Sightings       []Sighting   `json:"sightings"`
	PatternMentions []Ref        `json:"pattern_mentions,omitempty"`
}

// Observable is a stored cyber-observable matching the input.
type Observable struct {
	ID         string    `json:"id"`
	StandardID string    `json:"standard_id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Match      ioc.Match `json:"match"`
	Score      *int      `json:"score"` // the observable's own score, separate from any indicator's
	Labels     []string  `json:"labels,omitempty"`
	Markings   []string  `json:"markings"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  string    `json:"created_at,omitempty"`
	Containers Listed    `json:"containers"`
	Related    Listed    `json:"relationships"`
}

// Listed is a short list with its true total.
type Listed struct {
	Total int        `json:"total"`
	Items []RelOrRef `json:"items"`
}

// RelOrRef is a container (Rel empty) or a relationship to another object.
type RelOrRef struct {
	Relationship string `json:"relationship,omitempty"`
	Direction    string `json:"direction,omitempty"` // outgoing | incoming, seen from the subject
	Ref
	Created string `json:"created,omitempty"`
}

// Indicator is a stored indicator matching the input.
type Indicator struct {
	ID                string    `json:"id"`
	StandardID        string    `json:"standard_id"`
	Name              string    `json:"name"`
	Pattern           string    `json:"pattern"`
	PatternType       string    `json:"pattern_type"`
	FoundVia          []string  `json:"found_via"` // observable (based-on) and/or pattern
	PatternLiteral    string    `json:"pattern_literal,omitempty"`
	Match             ioc.Match `json:"match,omitempty"`
	Score             *int      `json:"score"` // current, after decay
	DecayBaseScore    *int      `json:"decay_base_score,omitempty"`
	DecayLifetimeDays *int      `json:"decay_lifetime_days,omitempty"`
	ValidFrom         string    `json:"valid_from,omitempty"`
	ValidUntil        string    `json:"valid_until,omitempty"`
	Revoked           bool      `json:"revoked"`
	Confidence        *int      `json:"confidence"`
	Labels            []string  `json:"labels,omitempty"`
	Markings          []string  `json:"markings"`
	CreatedBy         string    `json:"created_by,omitempty"`
	Related           Listed    `json:"relationships"`
}

// Sighting is an observation of a matching indicator or observable.
type Sighting struct {
	ID         string   `json:"id"`
	Of         Ref      `json:"of"`
	Where      Ref      `json:"where"`
	Count      int      `json:"count"`
	FirstSeen  string   `json:"first_seen,omitempty"`
	LastSeen   string   `json:"last_seen,omitempty"`
	Negative   bool     `json:"false_positive"`
	Confidence *int     `json:"confidence"`
	Markings   []string `json:"markings"`
	CreatedBy  string   `json:"created_by,omitempty"`
}

// --- wire -----------------------------------------------------------------

const relFields = `id relationship_type created from { ` + refFields + ` } to { ` + refFields + ` }`

const indicatorFields = `id standard_id name pattern pattern_type valid_from valid_until x_opencti_score confidence revoked
  decay_base_score decay_applied_rule { decay_lifetime }
  createdBy { name } objectMarking { definition } objectLabel { value }
  stixCoreRelationships(first: ` + "10" + `) { pageInfo { globalCount } edges { node { ` + relFields + ` } } }`

const lookupObservablesQuery = `query LookupObservables($filters: FilterGroup, $first: Int) {
  stixCyberObservables(first: $first, filters: $filters) {
    pageInfo { globalCount }
    edges { node {
      id standard_id entity_type observable_value x_opencti_score created_at
      ... on StixFile { hashes { algorithm hash } }
      createdBy { name } objectMarking { definition } objectLabel { value }
      containers(first: 10) { pageInfo { globalCount } edges { node { id entity_type representative { main } created objectMarking { definition } } } }
      stixCoreRelationships(first: 10) { pageInfo { globalCount } edges { node { ` + relFields + ` } } }
      indicators(first: 20) { pageInfo { globalCount } edges { node { ` + indicatorFields + ` } } }
    } }
  }
}`

const lookupIndicatorsQuery = `query LookupIndicators($filters: FilterGroup, $first: Int) {
  indicators(first: $first, filters: $filters) {
    pageInfo { globalCount }
    edges { node { ` + indicatorFields + ` } }
  }
}`

const sightingsQuery = `query Sightings($filters: FilterGroup, $first: Int) {
  stixSightingRelationships(first: $first, filters: $filters) {
    pageInfo { globalCount }
    edges { node {
      id first_seen last_seen attribute_count x_opencti_negative confidence
      createdBy { name } objectMarking { definition }
      from { ` + refFields + ` } to { ` + refFields + ` }
    } }
  }
}`

type wireRel struct {
	ID               string    `json:"id"`
	RelationshipType string    `json:"relationship_type"`
	Created          string    `json:"created"`
	Description      string    `json:"description"`
	StartTime        string    `json:"start_time"`
	StopTime         string    `json:"stop_time"`
	Confidence       *int      `json:"confidence"`
	CreatedBy        *named    `json:"createdBy"`
	ObjectMarking    []marking `json:"objectMarking"`
	From             wireRef   `json:"from"`
	To               wireRef   `json:"to"`
}

type relConn struct {
	PageInfo pageInfo `json:"pageInfo"`
	Edges    []struct {
		Node wireRel `json:"node"`
	} `json:"edges"`
}

type wireContainer struct {
	wireRef
	Created       string    `json:"created"`
	ObjectMarking []marking `json:"objectMarking"`
}

type wireIndicator struct {
	ID               string `json:"id"`
	StandardID       string `json:"standard_id"`
	Name             string `json:"name"`
	Pattern          string `json:"pattern"`
	PatternType      string `json:"pattern_type"`
	ValidFrom        string `json:"valid_from"`
	ValidUntil       string `json:"valid_until"`
	Score            *int   `json:"x_opencti_score"`
	Confidence       *int   `json:"confidence"`
	Revoked          bool   `json:"revoked"`
	DecayBaseScore   *int   `json:"decay_base_score"`
	DecayAppliedRule *struct {
		DecayLifetime *int `json:"decay_lifetime"`
	} `json:"decay_applied_rule"`
	CreatedBy     *named    `json:"createdBy"`
	ObjectMarking []marking `json:"objectMarking"`
	ObjectLabel   []label   `json:"objectLabel"`
	Rels          relConn   `json:"stixCoreRelationships"`
}

type wireObservable struct {
	ID              string `json:"id"`
	StandardID      string `json:"standard_id"`
	EntityType      string `json:"entity_type"`
	ObservableValue string `json:"observable_value"`
	Score           *int   `json:"x_opencti_score"`
	CreatedAt       string `json:"created_at"`
	Hashes          []struct {
		Algorithm string `json:"algorithm"`
		Hash      string `json:"hash"`
	} `json:"hashes"`
	CreatedBy     *named    `json:"createdBy"`
	ObjectMarking []marking `json:"objectMarking"`
	ObjectLabel   []label   `json:"objectLabel"`
	Containers    struct {
		PageInfo pageInfo `json:"pageInfo"`
		Edges    []struct {
			Node wireContainer `json:"node"`
		} `json:"edges"`
	} `json:"containers"`
	Rels       relConn `json:"stixCoreRelationships"`
	Indicators struct {
		PageInfo pageInfo `json:"pageInfo"`
		Edges    []struct {
			Node wireIndicator `json:"node"`
		} `json:"edges"`
	} `json:"indicators"`
}

type wireSighting struct {
	ID             string    `json:"id"`
	FirstSeen      string    `json:"first_seen"`
	LastSeen       string    `json:"last_seen"`
	AttributeCount int       `json:"attribute_count"`
	Negative       bool      `json:"x_opencti_negative"`
	Confidence     *int      `json:"confidence"`
	CreatedBy      *named    `json:"createdBy"`
	ObjectMarking  []marking `json:"objectMarking"`
	From           wireRef   `json:"from"`
	To             wireRef   `json:"to"`
}

// --- LookupIOC ------------------------------------------------------------

// LookupIOC looks up one or more indicator values.
func (e *Engine) LookupIOC(ctx context.Context, inputs []string) (*LookupResult, error) {
	values, err := classifyAll(inputs)
	if err != nil {
		return nil, err
	}
	if err := e.ready(); err != nil {
		return nil, err
	}
	res := &LookupResult{Results: make([]IOCResult, len(values))}
	for i, v := range values {
		res.Results[i] = IOCResult{Input: v.Input, Kind: v.Kind, Observables: []Observable{}, Indicators: []Indicator{}, Sightings: []Sighting{}}
	}

	// Path 1: observables, exact value (or hash) in every stored form.
	var obsOut struct {
		Conn struct {
			PageInfo pageInfo `json:"pageInfo"`
			Edges    []struct {
				Node wireObservable `json:"node"`
			} `json:"edges"`
		} `json:"stixCyberObservables"`
	}
	if err := e.query(ctx, lookupObservablesQuery, map[string]any{"filters": observableFilter(values), "first": candidateRows}, &obsOut); err != nil {
		return nil, err
	}
	cut := false // a candidate list was truncated: a miss is inconclusive
	if n := obsOut.Conn.PageInfo.GlobalCount; n > len(obsOut.Conn.Edges) {
		cut = true
		res.Notes = append(res.Notes, fmt.Sprintf("observables: %d matched, %d read; look up fewer values at once", n, len(obsOut.Conn.Edges)))
	}

	// Path 2: indicators whose pattern contains any form; kept only when a
	// STIX literal in the pattern is the value (contains matches substrings).
	var indOut struct {
		Conn struct {
			PageInfo pageInfo `json:"pageInfo"`
			Edges    []struct {
				Node wireIndicator `json:"node"`
			} `json:"edges"`
		} `json:"indicators"`
	}
	if err := e.query(ctx, lookupIndicatorsQuery, map[string]any{"filters": patternFilter(values), "first": candidateRows}, &indOut); err != nil {
		return nil, err
	}
	if n := indOut.Conn.PageInfo.GlobalCount; n > len(indOut.Conn.Edges) {
		cut = true
		res.Notes = append(res.Notes, fmt.Sprintf("indicators: %d candidate patterns, %d read; some pattern-only indicators may be missing — look up fewer values at once", n, len(indOut.Conn.Edges)))
	}

	sightingOf := map[string][]int{} // object id -> result indexes
	for i, v := range values {
		r := &res.Results[i]
		indByID := map[string]*Indicator{}
		for _, edge := range obsOut.Conn.Edges {
			o := edge.Node
			stored, ok := observableMatch(v, o)
			if !ok {
				continue
			}
			r.Observables = append(r.Observables, shapeObservable(o, v, stored))
			sightingOf[o.ID] = append(sightingOf[o.ID], i)
			for _, ie := range o.Indicators.Edges {
				ind := ie.Node
				if prev := indByID[ind.ID]; prev != nil {
					continue
				}
				shaped := shapeIndicator(ind)
				shaped.FoundVia = []string{"observable"}
				indByID[ind.ID] = &shaped
			}
			if o.Indicators.PageInfo.GlobalCount > len(o.Indicators.Edges) {
				r.Note = joinNote(r.Note, fmt.Sprintf("observable %s has %d indicators; %d listed", o.ObservableValue, o.Indicators.PageInfo.GlobalCount, len(o.Indicators.Edges)))
			}
		}
		for _, edge := range indOut.Conn.Edges {
			ind := edge.Node
			if !strings.EqualFold(ind.PatternType, "stix") {
				if mentions(v, ind.Pattern) {
					r.PatternMentions = append(r.PatternMentions, Ref{ID: ind.ID, Type: "Indicator (" + ind.PatternType + ")", Name: ind.Name})
				}
				continue
			}
			lit, ok := v.PatternMatch(ind.Pattern)
			if !ok {
				continue
			}
			shaped := indByID[ind.ID]
			if shaped == nil {
				s := shapeIndicator(ind)
				shaped = &s
				indByID[ind.ID] = shaped
			}
			shaped.FoundVia = appendOnce(shaped.FoundVia, "pattern")
			shaped.PatternLiteral = lit
			shaped.Match = v.MatchOf(lit)
		}
		ids := make([]string, 0, len(indByID))
		for id := range indByID {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			r.Indicators = append(r.Indicators, *indByID[id])
			sightingOf[id] = append(sightingOf[id], i)
		}
		r.Found = len(r.Observables) > 0 || len(r.Indicators) > 0
		switch {
		case !r.Found && cut:
			r.Inconclusive = true
			r.Note = joinNote("not found among what was read, but more candidates matched than one call reads (see notes): look this value up on its own", r.Note)
		case !r.Found:
			r.Note = joinNote(NotFoundNote, r.Note)
		}
	}

	// Sightings of every matched observable and indicator, in one query.
	if len(sightingOf) > 0 {
		ids := make([]string, 0, len(sightingOf))
		for id := range sightingOf {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var sOut struct {
			Conn struct {
				PageInfo pageInfo `json:"pageInfo"`
				Edges    []struct {
					Node wireSighting `json:"node"`
				} `json:"edges"`
			} `json:"stixSightingRelationships"`
		}
		if err := e.query(ctx, sightingsQuery, map[string]any{"filters": filterEq("fromId", ids...), "first": candidateRows}, &sOut); err != nil {
			return nil, err
		}
		if n := sOut.Conn.PageInfo.GlobalCount; n > len(sOut.Conn.Edges) {
			res.Notes = append(res.Notes, fmt.Sprintf("sightings: %d exist, %d read", n, len(sOut.Conn.Edges)))
		}
		for _, edge := range sOut.Conn.Edges {
			s := edge.Node
			for _, i := range sightingOf[s.From.ID] {
				res.Results[i].Sightings = append(res.Results[i].Sightings, Sighting{
					ID: s.ID, Of: ref(s.From), Where: ref(s.To), Count: s.AttributeCount,
					FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Negative: s.Negative, Confidence: s.Confidence,
					Markings: markings(s.ObjectMarking), CreatedBy: author(s.CreatedBy),
				})
			}
		}
	}
	return res, nil
}

func classifyAll(inputs []string) ([]ioc.Value, error) {
	if len(inputs) == 0 {
		return nil, invalid("at least one value is required")
	}
	if len(inputs) > MaxLookupValues {
		return nil, invalid("at most %d values per lookup (got %d)", MaxLookupValues, len(inputs))
	}
	var bad []string
	seen := map[string]bool{}
	values := make([]ioc.Value, 0, len(inputs))
	for _, in := range inputs {
		v, err := ioc.Classify(in)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		if seen[v.Input] {
			continue
		}
		seen[v.Input] = true
		values = append(values, v)
	}
	if len(bad) > 0 {
		return nil, invalid("%s", strings.Join(bad, "; "))
	}
	return values, nil
}

// observableFilter asks for every form of every value under its key, OR'ed.
func observableFilter(values []ioc.Value) map[string]any {
	byKey := map[string][]string{}
	var keys []string
	for _, v := range values {
		if _, ok := byKey[v.Key]; !ok {
			keys = append(keys, v.Key)
		}
		byKey[v.Key] = append(byKey[v.Key], v.Forms...)
	}
	filters := make([]any, 0, len(keys))
	for _, k := range keys {
		filters = append(filters, map[string]any{"key": []string{k}, "values": byKey[k], "operator": "eq", "mode": "or"})
	}
	return map[string]any{"mode": "or", "filterGroups": []any{}, "filters": filters}
}

// patternFilter asks for indicators whose pattern contains any form.
func patternFilter(values []ioc.Value) map[string]any {
	var forms []string
	for _, v := range values {
		forms = append(forms, v.Forms...)
	}
	return map[string]any{"mode": "and", "filterGroups": []any{}, "filters": []any{
		map[string]any{"key": []string{"pattern"}, "values": forms, "operator": "contains", "mode": "or"},
	}}
}

// observableMatch reports whether an observable is this value, and the stored
// form that matched.
func observableMatch(v ioc.Value, o wireObservable) (string, bool) {
	if strings.HasPrefix(v.Key, "hashes.") {
		alg := strings.TrimPrefix(v.Key, "hashes.")
		for _, h := range o.Hashes {
			if strings.EqualFold(h.Algorithm, alg) && strings.EqualFold(h.Hash, v.Input) {
				return h.Hash, true
			}
		}
		return "", false
	}
	if v.Equivalent(o.ObservableValue) {
		return o.ObservableValue, true
	}
	return "", false
}

// mentions is the weak check for a non-STIX pattern (YARA, Sigma, Snort…):
// the value appears in it. Such indicators are listed apart, as mentions.
func mentions(v ioc.Value, pattern string) bool {
	p := strings.ToLower(pattern)
	for _, f := range v.Forms {
		if strings.Contains(p, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

func shapeObservable(o wireObservable, v ioc.Value, stored string) Observable {
	out := Observable{
		ID: o.ID, StandardID: o.StandardID, Type: o.EntityType, Value: o.ObservableValue,
		Match: v.MatchOf(stored), Score: o.Score, Labels: labels(o.ObjectLabel),
		Markings: markings(o.ObjectMarking), CreatedBy: author(o.CreatedBy), CreatedAt: o.CreatedAt,
		Containers: Listed{Total: o.Containers.PageInfo.GlobalCount, Items: []RelOrRef{}},
		Related:    rels(o.ID, o.Rels),
	}
	for _, c := range o.Containers.Edges {
		r := ref(c.Node.wireRef)
		r.Markings = markings(c.Node.ObjectMarking)
		out.Containers.Items = append(out.Containers.Items, RelOrRef{Ref: r, Created: c.Node.Created})
	}
	return out
}

func shapeIndicator(w wireIndicator) Indicator {
	ind := Indicator{
		ID: w.ID, StandardID: w.StandardID, Name: w.Name, Pattern: w.Pattern, PatternType: w.PatternType,
		Score: w.Score, DecayBaseScore: w.DecayBaseScore, ValidFrom: w.ValidFrom, ValidUntil: w.ValidUntil,
		Revoked: w.Revoked, Confidence: w.Confidence, Labels: labels(w.ObjectLabel),
		Markings: markings(w.ObjectMarking), CreatedBy: author(w.CreatedBy), Related: rels(w.ID, w.Rels),
	}
	if w.DecayAppliedRule != nil {
		ind.DecayLifetimeDays = w.DecayAppliedRule.DecayLifetime
	}
	return ind
}

// rels lists relationships seen from subject: each row names the other end.
func rels(subject string, c relConn) Listed {
	out := Listed{Total: c.PageInfo.GlobalCount, Items: []RelOrRef{}}
	for _, edge := range c.Edges {
		n := edge.Node
		dir, other := "outgoing", n.To
		if n.To.ID == subject {
			dir, other = "incoming", n.From
		}
		out.Items = append(out.Items, RelOrRef{Relationship: n.RelationshipType, Direction: dir, Ref: ref(other), Created: n.Created})
	}
	return out
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}
