// Command opencti-lookup searches an OpenCTI instance read-only — indicators,
// observables, reports, threat actors, malware, ATT&CK techniques and the
// relationships between them — as a CLI and a local MCP server, so that an
// agent doing threat analysis can consult the instance alongside the external
// lookups.
//
// The instance queried is one the operator is entitled to read, with a key
// issued to them; no packet reaches the target under investigation. What the
// key can see is decided by the instance, not by this tool.
//
// The tool is read-only by design: every write path is out of scope
// permanently.
package main

import (
	"os"

	"github.com/nlink-jp/opencti-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
