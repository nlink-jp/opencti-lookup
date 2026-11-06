package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/termsafe"
)

// The renderers receive results that forText has already made inert, and
// still route third-party multi-line text through block().

// visible rewrites the characters a terminal obeys rather than shows.
// Vendored from shodan-lookup.
func visible(s string, multiline bool) string {
	if multiline {
		// A CRLF line end is a line end; only a lone CR — which would return
		// the cursor and let the text overwrite its own line — is shown.
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case multiline && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		case termsafe.Obeyed(r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// block prints third-party multi-line text with every line behind a gutter,
// so it cannot pass for this tool's own output.
func block(w io.Writer, text string) {
	for _, line := range strings.Split(visible(strings.TrimRight(text, "\n"), true), "\n") {
		fmt.Fprintf(w, "      | %s\n", strings.TrimRight(line, " \t"))
	}
}

func tags(markings []string) string {
	if len(markings) == 0 {
		return "[no marking]"
	}
	return "[" + strings.Join(markings, ", ") + "]"
}

func by(author string) string {
	if author == "" {
		return ""
	}
	return "  by " + author
}

func num(p *int) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprint(*p)
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func renderLookup(w io.Writer, res *engine.LookupResult) {
	for _, r := range res.Results {
		switch {
		case r.Found:
			fmt.Fprintf(w, "%s  (%s)  FOUND\n", r.Input, r.Kind)
		case r.Inconclusive:
			fmt.Fprintf(w, "%s  (%s)  INCONCLUSIVE — %s\n", r.Input, r.Kind, r.Note)
		default:
			fmt.Fprintf(w, "%s  (%s)  not found — %s\n", r.Input, r.Kind, r.Note)
		}
		for _, o := range r.Observables {
			match := ""
			if o.Match == "equivalent" {
				match = "  (stored as " + o.Value + ")"
			}
			fmt.Fprintf(w, "  observable %s %s%s  score %s  %s%s\n", o.Type, o.Value, match, num(o.Score), tags(o.Markings), by(o.CreatedBy))
			listed(w, "containers", o.Containers, "opencti-lookup reports "+o.ID)
			listed(w, "relationships", o.Related, "opencti-lookup related "+o.ID)
		}
		for _, ind := range r.Indicators {
			state := ""
			if ind.Revoked {
				state = "  REVOKED"
			}
			decay := ""
			if ind.DecayBaseScore != nil {
				decay = fmt.Sprintf(" (base %s", num(ind.DecayBaseScore))
				if ind.DecayLifetimeDays != nil {
					decay += fmt.Sprintf(", lifetime %dd", *ind.DecayLifetimeDays)
				}
				decay += ")"
			}
			fmt.Fprintf(w, "  indicator %s%s  score %s%s  valid %s → %s  confidence %s  via %s  %s%s\n",
				ind.Name, state, num(ind.Score), decay, day(ind.ValidFrom), day(ind.ValidUntil), num(ind.Confidence),
				strings.Join(ind.FoundVia, ","), tags(ind.Markings), by(ind.CreatedBy))
			fmt.Fprintf(w, "    pattern (%s):\n", ind.PatternType)
			block(w, ind.Pattern)
			listed(w, "relationships", ind.Related, "opencti-lookup related "+ind.ID)
		}
		for _, s := range r.Sightings {
			fp := ""
			if s.Negative {
				fp = "  FALSE POSITIVE"
			}
			fmt.Fprintf(w, "  sighting of %s at %s ×%d  %s → %s%s  confidence %s  %s\n",
				s.Of.Type, s.Where.Name, s.Count, day(s.FirstSeen), day(s.LastSeen), fp, num(s.Confidence), tags(s.Markings))
		}
		for _, m := range r.PatternMentions {
			fmt.Fprintf(w, "  mentioned (not an exact match) in %s %s  id %s\n", m.Type, m.Name, m.ID)
		}
	}
	for _, n := range res.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

func listed(w io.Writer, what string, l engine.Listed, more string) {
	if l.Total == 0 {
		return
	}
	fmt.Fprintf(w, "    %s %d:\n", what, l.Total)
	for _, it := range l.Items {
		arrow := ""
		switch it.Direction {
		case "outgoing":
			arrow = "→ " + it.Relationship + " "
		case "incoming":
			arrow = "← " + it.Relationship + " "
		}
		mark := ""
		if len(it.Markings) > 0 {
			mark = "  " + tags(it.Markings)
		}
		fmt.Fprintf(w, "      %s%s %s%s\n", arrow, it.Type, it.Name, mark)
	}
	if l.Total > len(l.Items) {
		fmt.Fprintf(w, "      … %d more: %s\n", l.Total-len(l.Items), more)
	}
}

func renderSearch(w io.Writer, res *engine.SearchResult) {
	switch {
	case len(res.Rows) == 0:
		fmt.Fprintf(w, "nothing matched %q within what this key can see\n", res.Query)
	case res.Mode == "exact":
		fmt.Fprintf(w, "exact matches for %q:\n", res.Query)
	default:
		fmt.Fprintf(w, "full-text matches for %q, by relevance (weakest last):\n", res.Query)
	}
	for _, r := range res.Rows {
		on := ""
		if r.MatchedOn != "" {
			on = "  (" + r.MatchedOn + ")"
		}
		mitre := ""
		if r.MitreID != "" {
			mitre = " " + r.MitreID
		}
		fmt.Fprintf(w, "  %s%s  %s%s  %s%s\n    id %s\n", r.Type, mitre, r.Name, on, tags(r.Markings), by(r.CreatedBy), r.ID)
		if len(r.Aliases) > 0 {
			fmt.Fprintf(w, "    aliases: %s\n", strings.Join(r.Aliases, ", "))
		}
		if r.Excerpt != "" {
			block(w, r.Excerpt)
		}
	}
	if res.MoreRanked {
		fmt.Fprintln(w, "… further, weaker full-text matches exist (raise --limit)")
	}
	for _, n := range res.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

func renderEntity(w io.Writer, e *engine.Entity) {
	fmt.Fprintf(w, "%s  %s  %s%s\n", e.Type, e.Name, tags(e.Markings), by(e.CreatedBy))
	fmt.Fprintf(w, "  id %s\n  standard_id %s\n", e.ID, e.StandardID)
	field := func(name, value string) {
		if value != "" {
			fmt.Fprintf(w, "  %s: %s\n", name, value)
		}
	}
	field("aliases", strings.Join(e.Aliases, ", "))
	field("labels", strings.Join(e.Labels, ", "))
	field("mitre_id", e.MitreID)
	field("kill_chain_phases", strings.Join(e.KillChain, ", "))
	field("platforms", strings.Join(e.Platforms, ", "))
	field("malware_types", strings.Join(e.MalwareTypes, ", "))
	field("report_types", strings.Join(e.ReportTypes, ", "))
	field("published", e.Published)
	field("first_seen", e.FirstSeen)
	field("last_seen", e.LastSeen)
	field("valid", strings.Trim(day(e.ValidFrom)+" → "+day(e.ValidUntil), " →"))
	field("observable_value", e.ObservableValue)
	if e.Score != nil {
		field("score", num(e.Score)+map[bool]string{true: " (base " + num(e.DecayBase) + ")", false: ""}[e.DecayBase != nil])
	}
	if e.Confidence != nil {
		field("confidence", num(e.Confidence))
	}
	if e.Revoked {
		field("revoked", "true")
	}
	field("created", e.Created)
	field("modified", e.Modified)
	if e.Pattern != "" {
		fmt.Fprintf(w, "  pattern (%s):\n", e.PatternType)
		block(w, e.Pattern)
	}
	if e.Description != "" {
		fmt.Fprintln(w, "  description:")
		block(w, e.Description)
	}
	if e.ExternalRefs.Total > 0 {
		fmt.Fprintf(w, "  external references %d:\n", e.ExternalRefs.Total)
		for _, r := range e.ExternalRefs.Items {
			fmt.Fprintf(w, "    %s %s %s\n", r.Source, r.ExternalID, r.URL)
		}
		if e.ExternalRefs.Total > len(e.ExternalRefs.Items) {
			fmt.Fprintf(w, "    … %d more (--json lists the same first %d)\n", e.ExternalRefs.Total-len(e.ExternalRefs.Items), len(e.ExternalRefs.Items))
		}
	}
}

// page prints how to continue a list: the same command, every filter, the
// same page size, and the cursor (which only that query accepts).
func page(w io.Writer, p engine.Page, cmd string) {
	if p.Remaining > 0 {
		if p.NextCursor != "" {
			fmt.Fprintf(w, "… %d more: %s --limit %d --cursor %s\n", p.Remaining, cmd, p.Limit, p.NextCursor)
		} else {
			fmt.Fprintf(w, "… %d more, not reachable from this page\n", p.Remaining)
		}
	}
}

func renderRelated(w io.Writer, r *engine.RelatedResult) {
	fmt.Fprintf(w, "%s %s — %d relationships, %d shown  %s\n", r.Of.Type, r.Of.Name, r.Total, r.Returned, tags(r.Of.Markings))
	for _, row := range r.Rows {
		arrow := "→"
		if row.Direction == "incoming" {
			arrow = "←"
		}
		mitre := ""
		if row.Other.MitreID != "" {
			mitre = " " + row.Other.MitreID
		}
		when := ""
		if row.StartTime != "" || row.StopTime != "" {
			when = fmt.Sprintf("  %s → %s", day(row.StartTime), day(row.StopTime))
		}
		fmt.Fprintf(w, "  %s %s %s%s %s%s  %s%s\n", arrow, row.Relationship, row.Other.Type, mitre, row.Other.Name, when, tags(row.Markings), by(row.CreatedBy))
		fmt.Fprintf(w, "      id %s\n", row.Other.ID)
		if row.Description != "" {
			block(w, row.Description)
		}
	}
	cmd := "opencti-lookup related " + r.Of.ID
	for _, rel := range r.RelationshipTypes {
		cmd += " --relationship " + rel
	}
	for _, tt := range r.TargetTypes {
		cmd += " --target-type " + tt
	}
	page(w, r.Page, cmd)
}

func renderReports(w io.Writer, r *engine.ReportsResult) {
	fmt.Fprintf(w, "%s %s — contained in %d, %d shown\n", r.Of.Type, r.Of.Name, r.Total, r.Returned)
	for _, c := range r.Containers {
		pub := ""
		if c.Published != "" {
			pub = "  published " + day(c.Published)
		}
		fmt.Fprintf(w, "  %s  %s  created %s%s  %s%s\n      id %s\n", c.Type, c.Name, day(c.Created), pub, tags(c.Markings), by(c.CreatedBy), c.ID)
	}
	page(w, r.Page, "opencti-lookup reports "+r.Of.ID)
}

func renderStatus(w io.Writer, s *engine.Status) {
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-18s %s\n", k+":", v)
		}
	}
	line("url", s.URL)
	line("config file", s.ConfigFile)
	if len(s.ConfigSearched) > 0 {
		line("searched", strings.Join(s.ConfigSearched, ", "))
	}
	if s.Error != nil {
		line("ERROR", s.Error.Code+": "+s.Error.Message)
	} else {
		match := "matches the verified version"
		if !s.VersionMatches {
			match = "DIFFERS from the verified " + s.VerifiedVersion
		}
		line("OpenCTI version", s.Version+" ("+match+")")
		line("user", s.User)
		line("capabilities", strings.Join(s.Capabilities, ", "))
		line("visible markings", strings.Join(s.VisibleMarkings, ", "))
	}
	line("TLS verification", s.TLSVerification)
	line("ca_file", s.CAFile)
	if s.PlainHTTP {
		line("plain http", "yes — the token travels unencrypted")
	}
	for _, warn := range s.Warnings {
		line("warning", warn)
	}
}

func renderRecent(w io.Writer, r *engine.RecentResult) {
	fmt.Fprintf(w, "%s by %s since %s — %d, %d shown\n", r.Type, r.Axis, day(r.Since), r.Total, r.Returned)
	for _, row := range r.Rows {
		when := row.CreatedAt
		switch r.Axis {
		case "created":
			when = row.Created
		case "published":
			when = row.Published
		}
		extra := ""
		if row.Revoked {
			extra = "  REVOKED"
		}
		if row.Score != nil {
			extra += "  score " + num(row.Score)
		}
		fmt.Fprintf(w, "  %s  %s %s%s  %s%s\n      id %s\n", day(when), row.Type, row.Name, extra, tags(row.Markings), by(row.CreatedBy), row.ID)
		if row.Pattern != "" {
			block(w, row.Pattern)
		}
	}
	page(w, r.Page, fmt.Sprintf("opencti-lookup recent --type %s --by %s --days %d", r.Type, r.Axis, r.Days))
}
