# CLAUDE.md — opencti-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that searches **one OpenCTI instance read-only** with a
key issued to the operator, for threat-analysis agents. Verified against
**OpenCTI 6.7.4**, the production version. Production runs on a machine the
development machine cannot reach: the Podman dev stack is the only test bed.

Design authority: [docs/ja/opencti-lookup-rfp.ja.md](docs/ja/opencti-lookup-rfp.ja.md).
Measured behaviour: [docs/ja/opencti-lookup-phase0.ja.md](docs/ja/opencti-lookup-phase0.ja.md).
Contributor summary and gotchas: [AGENTS.md](AGENTS.md).

## Build & test

```bash
make build   # never `go build` directly
make test    # offline
make lint
make e2e     # live, against the dev stack (make dev-up, then seed — see README)
```

## Key conventions

- **Read-only, permanently.** No mutation, no enrichment trigger, no upload.
- **Measure before you code a query.** Run it against the dev stack first
  (`dev/gql.sh`, `dev/capture.py`); introspection is refused, so the schema is
  read from the OpenCTI repository at tag 6.7.4.
- **Input that is not understood is refused**: unknown config keys, a missing
  `--config` file, undeclared MCP arguments, unknown target types, ids that
  name nothing (`not_found`), anything OpenCTI would answer with a silent zero.
- **A negative answer is never manufactured.** Empty means "nothing within
  what this key can see"; a miss after a cut list is `inconclusive`; partial
  GraphQL success is a failure.
- **The token never appears on any output surface** and travels only in the
  Authorization header. `Config.Redacted` for anything that prints settings.
- **The documents are pinned to the code**: `internal/mcp/usage_test.go`
  requires every `Tool*` and `Code*` constant, every argument and enum value in
  `usage.md`. README.md and README.ja.md change together.
- **No raw control or bidi character in any source file** (`source_test.go`).
- **Fixtures are fictional**: RFC 5737 / RFC 2606 values only (`dev/seed/`).

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
