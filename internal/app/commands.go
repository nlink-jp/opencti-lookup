package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/mcp"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
	"github.com/nlink-jp/pathguard"
	"github.com/nlink-jp/pathguard/workdir"
)

// common holds the flags every query command takes.
type common struct {
	jsonOut    bool
	configPath string
	timeout    float64
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.BoolVar(&c.jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(&c.configPath, "config", "", "config file path")
	fs.StringVar(&c.configPath, "c", "", "config file path (shorthand)")
	fs.Float64Var(&c.timeout, "timeout", 0, "request timeout in seconds")
}

// load resolves the config, prints its warnings once, and builds the engine.
func (c *common) load(stderr io.Writer) (mcp.Engine, *config.Config, int) {
	var override time.Duration
	if c.timeout != 0 {
		if c.timeout < 1 || c.timeout != float64(int(c.timeout)) {
			fmt.Fprintln(stderr, "opencti-lookup: --timeout must be a whole number of seconds, 1 or more")
			return nil, nil, exitError
		}
		override = time.Duration(c.timeout) * time.Second
	}
	cfg, err := config.Load(c.configPath, override)
	if err != nil {
		fmt.Fprintf(stderr, "opencti-lookup: %v\n", err)
		return nil, nil, exitError
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(stderr, "Warning: %s\n", w)
	}
	return newEngine(cfg), cfg, exitOK
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	return fs
}

// exitFor maps a failure to an exit code and prints it.
func exitFor(err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "opencti-lookup: %s\n", visible(err.Error(), false))
	switch engine.Code(err) {
	case engine.CodeInvalidArgument, engine.CodeNotConfigured, opencti.CodeAuthFailed, opencti.CodeForbidden:
		return exitError
	}
	return exitUpstream
}

func ctx(cfg *config.Config) (context.Context, context.CancelFunc) {
	// Up to four requests per command (an existence check, lookups, sightings).
	return context.WithTimeout(context.Background(), 4*cfg.Timeout+5*time.Second)
}

// writeJSON prints v as indented JSON made inert for a terminal.
func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(jsonForTerminal(b), '\n'))
	return err
}

func runIOC(args []string, stdout, stderr io.Writer) int {
	var c common
	fs := newFlags("ioc", stderr)
	c.register(fs)
	values, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(values) == 0 {
		fmt.Fprintln(stderr, "opencti-lookup: ioc needs at least one value")
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	res, err := eng.LookupIOC(cx, values)
	if err != nil {
		return exitFor(err, stderr)
	}
	exit := exitOK
	for _, r := range res.Results {
		if r.Inconclusive {
			exit = exitUpstream
		}
	}
	if c.jsonOut {
		if err := writeJSON(stdout, res); err != nil {
			return exitFor(err, stderr)
		}
		return exit
	}
	renderLookup(stdout, forText(res))
	return exit
}

func runSearch(args []string, stdout, stderr io.Writer) int {
	var c common
	var types stringList
	var limit int
	fs := newFlags("search", stderr)
	c.register(fs)
	fs.Var(&types, "type", "restrict to a kind (repeatable)")
	fs.IntVar(&limit, "limit", 0, "rows")
	words, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(words) == 0 {
		fmt.Fprintln(stderr, "opencti-lookup: search needs a query")
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	res, err := eng.SearchThreats(cx, strings.Join(words, " "), types, limit)
	if err != nil {
		return exitFor(err, stderr)
	}
	if c.jsonOut {
		if err := writeJSON(stdout, res); err != nil {
			return exitFor(err, stderr)
		}
		return exitOK
	}
	renderSearch(stdout, forText(res))
	return exitOK
}

func oneID(fs *flag.FlagSet, args []string, stderr io.Writer, name string) (string, bool) {
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return "", false
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "opencti-lookup: %s takes exactly one id\n", name)
		return "", false
	}
	return pos[0], true
}

// answerNotFound prints a not_found as the answer it is (exit 0).
func answerNotFound(err error, stdout, stderr io.Writer) (int, bool) {
	if engine.Code(err) != engine.CodeNotFound {
		return 0, false
	}
	fmt.Fprintln(stdout, visible(err.Error(), false))
	return exitOK, true
}

func runEntity(args []string, stdout, stderr io.Writer) int {
	var c common
	fs := newFlags("entity", stderr)
	c.register(fs)
	id, ok := oneID(fs, args, stderr, "entity")
	if !ok {
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	ent, err := eng.GetEntity(cx, id)
	if err != nil {
		if code, ok := answerNotFound(err, stdout, stderr); ok {
			return code
		}
		return exitFor(err, stderr)
	}
	if c.jsonOut {
		if err := writeJSON(stdout, ent); err != nil {
			return exitFor(err, stderr)
		}
		return exitOK
	}
	renderEntity(stdout, forText(ent))
	return exitOK
}

func runRelated(args []string, stdout, stderr io.Writer) int {
	var c common
	var rels, targets stringList
	var q engine.RelatedQuery
	fs := newFlags("related", stderr)
	c.register(fs)
	fs.Var(&rels, "relationship", "relationship type (repeatable)")
	fs.Var(&targets, "target-type", "other end's entity type (repeatable)")
	fs.BoolVar(&q.WithDescriptions, "descriptions", false, "include relationship descriptions")
	fs.IntVar(&q.Limit, "limit", 0, "rows")
	fs.StringVar(&q.Cursor, "cursor", "", "next_cursor from a previous answer")
	id, ok := oneID(fs, args, stderr, "related")
	if !ok {
		return exitError
	}
	q.ID, q.RelationshipTypes, q.TargetTypes = id, rels, targets
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	res, err := eng.GetRelated(cx, q)
	if err != nil {
		if code, ok := answerNotFound(err, stdout, stderr); ok {
			return code
		}
		return exitFor(err, stderr)
	}
	if c.jsonOut {
		if err := writeJSON(stdout, res); err != nil {
			return exitFor(err, stderr)
		}
		return exitOK
	}
	renderRelated(stdout, forText(res))
	return exitOK
}

func runReports(args []string, stdout, stderr io.Writer) int {
	var c common
	var limit int
	var cursor string
	fs := newFlags("reports", stderr)
	c.register(fs)
	fs.IntVar(&limit, "limit", 0, "rows")
	fs.StringVar(&cursor, "cursor", "", "next_cursor from a previous answer")
	id, ok := oneID(fs, args, stderr, "reports")
	if !ok {
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	res, err := eng.GetReports(cx, id, limit, cursor)
	if err != nil {
		if code, ok := answerNotFound(err, stdout, stderr); ok {
			return code
		}
		return exitFor(err, stderr)
	}
	if c.jsonOut {
		if err := writeJSON(stdout, res); err != nil {
			return exitFor(err, stderr)
		}
		return exitOK
	}
	renderReports(stdout, forText(res))
	return exitOK
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	var c common
	fs := newFlags("status", stderr)
	c.register(fs)
	extra, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(extra) > 0 {
		fmt.Fprintf(stderr, "opencti-lookup: status takes no arguments (got %q)\n", extra[0])
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	st := eng.ServerStatus(cx)
	if c.jsonOut {
		if err := writeJSON(stdout, st); err != nil {
			return exitFor(err, stderr)
		}
	} else {
		renderStatus(stdout, forText(st))
	}
	if st.Error == nil {
		return exitOK
	}
	switch st.Error.Code {
	case engine.CodeNotConfigured, opencti.CodeAuthFailed, opencti.CodeForbidden:
		return exitError
	}
	return exitUpstream
}

// runMCP serves the stdio MCP server until stdin closes. A closing stdin is
// the shutdown signal. Config warnings go to stderr, which an MCP client
// keeps apart from the protocol on stdout.
func runMCP(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	var configPath string
	fs := newFlags("mcp", stderr)
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&configPath, "c", "", "config file path (shorthand)")
	extra, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(extra) > 0 {
		fmt.Fprintf(stderr, "opencti-lookup: mcp takes no arguments (got %q)\n", extra[0])
		return exitError
	}
	cfg, err := config.Load(configPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "opencti-lookup: %v\n", err)
		return exitError
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(stderr, "Warning: %s\n", w)
	}
	srv := &mcp.Server{Eng: newEngine(cfg), Version: version, WorkDirs: workDirs(cfg)}
	if err := srv.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "opencti-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}

// workDirs builds the work-directory judge (organization ADR-021 / ADR-022)
// with this tool's own configuration directories protected: every directory a
// config file is searched in, and the one actually read, since they hold the
// token.
func workDirs(cfg *config.Config) workdir.Resolver {
	seen := map[string]bool{}
	var places []pathguard.Place
	add := func(file string) {
		dir := filepath.Dir(file)
		if file == "" || !filepath.IsAbs(dir) || seen[dir] {
			return
		}
		seen[dir] = true
		places = append(places, pathguard.ServerDir(dir, "which holds the OpenCTI token"))
	}
	for _, p := range config.SearchPaths() {
		add(p)
	}
	add(cfg.Path)
	return workdir.NewResolver(workdir.Options{
		Protected:    places,
		RequiredHint: "The attachment is written there and returned as a path, and a path you cannot open is worth nothing.",
	})
}

func runRecent(args []string, stdout, stderr io.Writer) int {
	var c common
	var q engine.RecentQuery
	fs := newFlags("recent", stderr)
	c.register(fs)
	fs.StringVar(&q.Type, "type", "", "report (default) or indicator")
	fs.StringVar(&q.Axis, "by", "", "created_at (default), created or published")
	fs.IntVar(&q.Days, "days", 0, "days back, 1-365 (default 7)")
	fs.IntVar(&q.Limit, "limit", 0, "rows")
	fs.StringVar(&q.Cursor, "cursor", "", "next_cursor from a previous answer")
	extra, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(extra) > 0 {
		fmt.Fprintf(stderr, "opencti-lookup: recent takes no arguments (got %q)\n", extra[0])
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	res, err := eng.ListRecent(cx, q)
	if err != nil {
		return exitFor(err, stderr)
	}
	if c.jsonOut {
		if err := writeJSON(stdout, res); err != nil {
			return exitFor(err, stderr)
		}
		return exitOK
	}
	renderRecent(stdout, forText(res))
	return exitOK
}

func runFile(args []string, stdout, stderr io.Writer) int {
	var c common
	out := "."
	fs := newFlags("file", stderr)
	c.register(fs)
	fs.StringVar(&out, "out", ".", "directory to save into (default the current directory)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) != 2 {
		fmt.Fprintln(stderr, "opencti-lookup: file takes an id and an attachment name (as entity lists it)")
		return exitError
	}
	dir, err := filepath.Abs(out)
	if err != nil {
		fmt.Fprintf(stderr, "opencti-lookup: --out: %v\n", err)
		return exitError
	}
	eng, cfg, code := c.load(stderr)
	if code != exitOK {
		return code
	}
	cx, cancel := ctx(cfg)
	defer cancel()
	srv := &mcp.Server{Eng: eng, WorkDirs: workDirs(cfg)}
	res, err := srv.GetReportFile(cx, pos[0], pos[1], dir)
	if err != nil {
		var we *workdir.Error
		if errors.As(err, &we) {
			fmt.Fprintf(stderr, "opencti-lookup: --out %s: %s\n", out, visible(we.Message, false))
			return exitError
		}
		// Unlike a lookup, file is an action: when nothing was saved — the
		// object or the attachment is not there for this key — it fails, so
		// that "file … && next-step" does not run on a file that is absent.
		// Too large to save is the same outcome: nothing was written.
		switch engine.Code(err) {
		case engine.CodeNotFound, opencti.CodeFileTooLarge: // opencti.CodeNotFound is the same "not_found"
			fmt.Fprintf(stderr, "opencti-lookup: nothing saved: %s\n", visible(err.Error(), false))
			return exitError
		}
		return exitFor(err, stderr)
	}
	if c.jsonOut {
		if err := writeJSON(stdout, res); err != nil {
			return exitFor(err, stderr)
		}
		return exitOK
	}
	// Every string in the result is the instance's — the attachment's name,
	// its type, the object's name — and is made inert before printing.
	forText(res)
	fmt.Fprintf(stdout, "saved %s (%d bytes, %s, sha256 %s)\n  from %s %s, attachment %q\n",
		res.AbsPath, res.Bytes, res.MimeType, res.SHA256, res.Of.Type, res.Of.Name, res.Name)
	return exitOK
}
