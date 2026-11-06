package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/mcp"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
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
	srv := &mcp.Server{Eng: newEngine(cfg), Version: version}
	if err := srv.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "opencti-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
