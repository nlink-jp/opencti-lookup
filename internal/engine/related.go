package engine

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// TargetTypes are the entity types get_related accepts as the other end.
// OpenCTI answers a type it does not know with zero rows and no error
// (Phase 0 §2), so the list is checked here, before sending.
var TargetTypes = []string{
	"Administrative-Area", "Artifact", "Attack-Pattern", "Autonomous-System", "Campaign", "Channel", "City",
	"Country", "Course-Of-Action", "Data-Component", "Data-Source", "Directory", "Domain-Name", "Email-Addr",
	"Event", "Grouping", "Hostname", "Identity", "IPv4-Addr", "IPv6-Addr", "Incident", "Indicator",
	"Individual", "Infrastructure", "Intrusion-Set", "Language", "Location", "Mac-Addr", "Malware",
	"Malware-Analysis", "Narrative", "Network-Traffic", "Note", "Observed-Data", "Opinion", "Organization",
	"Position", "Process", "Region", "Report", "Sector", "Software", "Stix-Cyber-Observable",
	"Stix-Domain-Object", "StixFile", "System", "Text", "Threat-Actor", "Threat-Actor-Group",
	"Threat-Actor-Individual", "Tool", "Url", "User-Account", "User-Agent", "Vulnerability",
	"Windows-Registry-Key", "X509-Certificate",
}

var targetTypeSet = func() map[string]string {
	m := map[string]string{}
	for _, t := range TargetTypes {
		m[strings.ToLower(t)] = t
	}
	return m
}()

// relationshipName is the shape of an OpenCTI relationship type. The instance
// rejects an unknown one (UNSUPPORTED_ERROR), so only the shape is checked.
var relationshipName = regexp.MustCompile(`^[a-z][a-z-]{1,40}$`)

// RelatedQuery is get_related's input.
type RelatedQuery struct {
	ID                string
	RelationshipTypes []string
	TargetTypes       []string
	Limit             int
	Cursor            string
	WithDescriptions  bool
}

// RelatedResult answers get_related. The starting object is given once, and
// the filters are echoed so that a continuation can repeat them.
type RelatedResult struct {
	Of                Ref          `json:"of"`
	RelationshipTypes []string     `json:"relationship_types,omitempty"`
	TargetTypes       []string     `json:"target_types,omitempty"`
	Rows              []RelatedRow `json:"relationships"`
	Page
}

// RelatedRow is one relationship, seen from Of.
type RelatedRow struct {
	Relationship string   `json:"relationship"`
	Direction    string   `json:"direction"` // outgoing: Of → other; incoming: other → Of
	Other        Ref      `json:"other"`
	StartTime    string   `json:"start_time,omitempty"`
	StopTime     string   `json:"stop_time,omitempty"`
	Confidence   *int     `json:"confidence,omitempty"`
	Markings     []string `json:"markings"`
	CreatedBy    string   `json:"created_by,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// openTimes are OpenCTI's sentinels for "unbounded" (start_time, stop_time,
// first_seen, last_seen); reporting them as dates would read as data.
var openTimes = map[string]bool{"1970-01-01T00:00:00.000Z": true, "5138-11-16T09:46:40.000Z": true}

// bounded returns ts, or "" when it is an unbounded sentinel.
func bounded(ts string) string {
	if openTimes[ts] {
		return ""
	}
	return ts
}

// GetRelated walks relationships from one object.
func (e *Engine) GetRelated(ctx context.Context, q RelatedQuery) (*RelatedResult, error) {
	n, err := e.limit(q.Limit)
	if err != nil {
		return nil, err
	}
	if _, err := decodeCursor(q.Cursor, ""); err != nil {
		return nil, err
	}
	for _, r := range q.RelationshipTypes {
		if !relationshipName.MatchString(r) {
			return nil, invalid("relationship type %q is not a relationship name (lower-case words joined by hyphens, e.g. uses, indicates, targets)", r)
		}
	}
	var targets []string
	for _, t := range q.TargetTypes {
		canon, ok := targetTypeSet[strings.ToLower(t)]
		if !ok {
			return nil, invalid("unknown target type %q (OpenCTI answers an unknown type with no rows rather than an error; the accepted types are listed in the README and by get_usage)", t)
		}
		targets = append(targets, canon)
	}
	of, err := e.exists(ctx, q.ID)
	if err != nil {
		return nil, err
	}
	rels := append([]string(nil), q.RelationshipTypes...)
	sort.Strings(rels)
	sortedTargets := append([]string(nil), targets...)
	sort.Strings(sortedTargets)
	cur, err := decodeCursor(q.Cursor, fingerprint("related", of.ID, strings.Join(rels, ","), strings.Join(sortedTargets, ",")))
	if err != nil {
		return nil, err
	}

	desc := ""
	if q.WithDescriptions {
		desc = " description"
	}
	query := `query Related($id: [String], $types: [String], $targets: [String], $first: Int, $after: ID) {
  stixCoreRelationships(fromOrToId: $id, relationship_type: $types, elementWithTargetTypes: $targets, first: $first, after: $after) {
    pageInfo { globalCount endCursor }
    edges { node { id relationship_type start_time stop_time confidence createdBy { name } objectMarking { definition }` + desc + `
      from { ` + refFields + ` } to { ` + refFields + ` } } }
  }
}`
	vars := map[string]any{"id": []string{of.ID}, "first": n}
	if len(q.RelationshipTypes) > 0 {
		vars["types"] = q.RelationshipTypes
	}
	if len(targets) > 0 {
		vars["targets"] = targets
	}
	if cur.After != "" {
		vars["after"] = cur.After
	}
	var out struct {
		Conn relConn `json:"stixCoreRelationships"`
	}
	if err := e.query(ctx, query, vars, &out); err != nil {
		// An unknown relationship type is rejected as UNSUPPORTED_ERROR
		// ("This API only support Stix core relationships", measured). That
		// is the caller's argument, not a version mismatch.
		var oe *opencti.Error
		if len(q.RelationshipTypes) > 0 && errors.As(err, &oe) && oe.UpstreamCode == "UNSUPPORTED_ERROR" {
			return nil, invalid("OpenCTI does not know relationship type(s) %s as core relationships (%s)", strings.Join(q.RelationshipTypes, ", "), oe.Message)
		}
		return nil, err
	}
	res := &RelatedResult{Of: of, Rows: []RelatedRow{}, RelationshipTypes: q.RelationshipTypes, TargetTypes: targets}
	for _, edge := range out.Conn.Edges {
		w := edge.Node
		dir, other := "outgoing", w.To
		if w.To.ID == of.ID {
			dir, other = "incoming", w.From
		}
		row := RelatedRow{Relationship: w.RelationshipType, Direction: dir, Other: ref(other),
			Confidence: w.Confidence, Markings: markings(w.ObjectMarking), CreatedBy: author(w.CreatedBy),
			Description: w.Description}
		row.StartTime, row.StopTime = bounded(w.StartTime), bounded(w.StopTime)
		res.Rows = append(res.Rows, row)
	}
	res.Page = pageOf(out.Conn.PageInfo.GlobalCount, len(res.Rows), n, cur, out.Conn.PageInfo.EndCursor)
	return res, nil
}

// --- get_reports ----------------------------------------------------------

// ReportsResult answers get_reports.
type ReportsResult struct {
	Of         Ref            `json:"of"`
	Containers []ContainerRow `json:"containers"`
	Page
}

// ContainerRow is one report, note or grouping holding the object.
type ContainerRow struct {
	Ref
	Created   string `json:"created,omitempty"`
	Published string `json:"published,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
}

// GetReports lists the containers (report, note, grouping) holding an object,
// newest first. The root containers query is used because the one nested
// under an object cannot page (Phase 0 §3).
func (e *Engine) GetReports(ctx context.Context, id string, limit int, cursorToken string) (*ReportsResult, error) {
	n, err := e.limit(limit)
	if err != nil {
		return nil, err
	}
	if _, err := decodeCursor(cursorToken, ""); err != nil {
		return nil, err
	}
	of, err := e.exists(ctx, id)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(cursorToken, fingerprint("reports", of.ID))
	if err != nil {
		return nil, err
	}
	q := `query Containers($filters: FilterGroup, $first: Int, $after: ID) {
  containers(filters: $filters, first: $first, after: $after, orderBy: created, orderMode: desc) {
    pageInfo { globalCount endCursor }
    edges { node { id entity_type representative { main } created objectMarking { definition } createdBy { name } ... on Report { published } } }
  }
}`
	vars := map[string]any{"filters": filterEq("objects", of.ID), "first": n}
	if cur.After != "" {
		vars["after"] = cur.After
	}
	var out struct {
		Conn struct {
			PageInfo pageInfo `json:"pageInfo"`
			Edges    []struct {
				Node struct {
					wireRef
					Created       string    `json:"created"`
					Published     string    `json:"published"`
					ObjectMarking []marking `json:"objectMarking"`
					CreatedBy     *named    `json:"createdBy"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"containers"`
	}
	if err := e.query(ctx, q, vars, &out); err != nil {
		return nil, err
	}
	res := &ReportsResult{Of: of, Containers: []ContainerRow{}}
	for _, edge := range out.Conn.Edges {
		w := edge.Node
		r := ref(w.wireRef)
		r.Markings = markings(w.ObjectMarking)
		res.Containers = append(res.Containers, ContainerRow{Ref: r, Created: w.Created, Published: w.Published, CreatedBy: author(w.CreatedBy)})
	}
	res.Page = pageOf(out.Conn.PageInfo.GlobalCount, len(res.Containers), n, cur, out.Conn.PageInfo.EndCursor)
	return res, nil
}

// --- server_status --------------------------------------------------------

// Status answers server_status. It is returned even when the instance could
// not be asked, with Error set, so that the configuration facts are still
// there to diagnose with.
type Status struct {
	URL             string       `json:"url,omitempty"`
	ConfigFile      string       `json:"config_file"`
	ConfigSearched  []string     `json:"config_searched,omitempty"`
	Version         string       `json:"version,omitempty"`
	VerifiedVersion string       `json:"verified_version"`
	VersionMatches  bool         `json:"version_matches"`
	User            string       `json:"user,omitempty"`
	Capabilities    []string     `json:"capabilities,omitempty"`
	VisibleMarkings []string     `json:"visible_markings,omitempty"`
	TLSVerification string       `json:"tls_verification"` // on | off | "n/a (http)"
	CAFile          string       `json:"ca_file,omitempty"`
	PlainHTTP       bool         `json:"plain_http"`
	Warnings        []string     `json:"warnings,omitempty"`
	Error           *StatusError `json:"error,omitempty"`
}

// StatusError is a failure to reach or authenticate to the instance.
type StatusError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ServerStatus reports the instance's version, what the key can do and see,
// and how the connection is secured.
func (e *Engine) ServerStatus(ctx context.Context) *Status {
	c := e.Cfg
	st := &Status{URL: c.URL, ConfigFile: c.Path, VerifiedVersion: VerifiedVersion, CAFile: c.CAFile,
		PlainHTTP: c.PlainHTTP(), Warnings: c.Warnings}
	if c.Path == "" {
		st.ConfigFile = "(none)"
		st.ConfigSearched = c.Searched
	}
	switch {
	case strings.HasPrefix(c.URL, "http://"):
		st.TLSVerification = "n/a (http)"
	case c.InsecureSkipVerify:
		st.TLSVerification = "off"
	default:
		st.TLSVerification = "on"
	}

	var out struct {
		About struct {
			Version string `json:"version"`
		} `json:"about"`
		Me struct {
			Name         string `json:"name"`
			Capabilities []struct {
				Name string `json:"name"`
			} `json:"capabilities"`
			AllowedMarking []marking `json:"allowed_marking"`
		} `json:"me"`
	}
	q := `query Status { about { version } me { name capabilities { name } allowed_marking { definition } } }`
	if err := e.query(ctx, q, nil, &out); err != nil {
		code := Code(err)
		if code == "" {
			code = "internal_error"
		}
		st.Error = &StatusError{Code: code, Message: err.Error()}
		return st
	}
	st.Version = out.About.Version
	st.VersionMatches = st.Version == VerifiedVersion
	if !st.VersionMatches {
		st.Warnings = append(st.Warnings, "the instance runs OpenCTI "+st.Version+"; this build was verified against "+VerifiedVersion+" — queries may be rejected (query_rejected) or shaped differently")
	}
	st.User = out.Me.Name
	for _, cp := range out.Me.Capabilities {
		st.Capabilities = append(st.Capabilities, cp.Name)
	}
	st.VisibleMarkings = markings(out.Me.AllowedMarking)
	sort.Strings(st.VisibleMarkings)
	return st
}
