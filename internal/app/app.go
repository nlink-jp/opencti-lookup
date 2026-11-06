// Package app implements the opencti-lookup command-line interface: subcommand
// dispatch plus the ioc / search / entity / related / reports / status / mcp
// commands. Core logic lives in the config, opencti, ioc and engine packages;
// this package is the thin I/O shell around them.
package app

import (
	"fmt"
	"io"
	"os"

	"github.com/nlink-jp/opencti-lookup/internal/config"
	"github.com/nlink-jp/opencti-lookup/internal/engine"
	"github.com/nlink-jp/opencti-lookup/internal/mcp"
	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// Exit codes. "Not found" and an empty list are answers, so they are distinct
// from an operational failure.
const (
	exitOK       = 0 // answered (empty answers included)
	exitUpstream = 1 // the instance could not be asked, or not fully (INCONCLUSIVE)
	exitError    = 2 // invalid input, configuration, authentication or permission
)

// newEngine builds the engine for a configuration; tests replace it.
var newEngine = func(cfg *config.Config) mcp.Engine {
	return &engine.Engine{Client: opencti.New(cfg), Cfg: cfg}
}

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, version string) int {
	return run(args, version, os.Stdin, os.Stdout, os.Stderr)
}

// run is Run with injected streams.
func run(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "ioc":
		return runIOC(rest, stdout, stderr)
	case "search":
		return runSearch(rest, stdout, stderr)
	case "entity":
		return runEntity(rest, stdout, stderr)
	case "related":
		return runRelated(rest, stdout, stderr)
	case "reports":
		return runReports(rest, stdout, stderr)
	case "status":
		return runStatus(rest, stdout, stderr)
	case "recent":
		return runRecent(rest, stdout, stderr)
	case "file":
		return runFile(rest, stdout, stderr)
	case "mcp":
		return runMCP(rest, version, stdin, stdout, stderr)
	case "version", "--version", "-v":
		printVersion(stdout, version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return exitError
	}
}

// printVersion is the single source of the version banner. `--version` and the
// `version` subcommand must print byte-identical output: a Homebrew formula's
// `brew test` calls `--version`, while humans type `version`.
func printVersion(w io.Writer, version string) {
	fmt.Fprintln(w, "opencti-lookup "+version)
	fmt.Fprintln(w, "Reads an OpenCTI instance read-only with your key; verified against OpenCTI "+engine.VerifiedVersion+".")
	fmt.Fprintln(w, "Not affiliated with or endorsed by Filigran.")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `opencti-lookup — read-only threat-intelligence lookups against your OpenCTI instance

Usage:
  opencti-lookup <command> [flags] [arguments]

Commands:
  ioc <VALUE>...           What the instance holds about IPs, CIDRs, domains, URLs,
                           email addresses and MD5/SHA-1/SHA-256/SHA-512 hashes (up to 50)
  search <QUERY>           Threat actors, malware, techniques, vulnerabilities, reports:
                           exact name, alias or ATT&CK id first, then ranked full text
  entity <ID>              One object in full
  related <ID>             The relationships of one object, paged
  reports <ID>             The reports, notes and groupings that contain one object
  recent                   Reports or indicators newly ingested or published (last N days)
  file <ID> <NAME>         Save one attachment of an object (NAME as entity lists it)
  status                   Version, what the key can do and see, the config file read
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

Flags (before or after the arguments):
  --json, -j               JSON on stdout
  --config, -c <path>      config file (an explicit path that does not exist is an error)
  --timeout <seconds>      per-request timeout
  search:   --type T (repeatable: intrusion-set, threat-actor, campaign, malware,
            tool, attack-pattern, vulnerability, report)  --limit N
  related:  --relationship R (repeatable)  --target-type T (repeatable)
            --descriptions  --limit N  --cursor C
  reports:  --limit N  --cursor C
  recent:   --type report|indicator  --by created_at|created|published
            --days N (1-365, default 7)  --limit N  --cursor C
  file:     --out DIR (default the current directory; the saved name is
            rebuilt as opencti-lookup-<id>-<hash>-<safe name>)

An empty answer means nothing within what this key can see: OpenCTI answers
"not registered" and "not visible to this key" identically. "status" shows
what the key can see. No verdict is computed; scores, confidence and markings
are the instance's own.

Exit codes:
  0  answered — "not found" and an empty list are answers
  1  the instance could not be asked, or not fully (INCONCLUSIVE in the output)
  2  error: invalid input, configuration, a refused key, a missing permission

The tool never writes to the instance.
`)
}
