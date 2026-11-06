# AGENTS.md — opencti-lookup

## Summary

A CLI and local MCP server that searches one OpenCTI instance read-only with a
key issued to the operator: IOC lookups (observables, indicators, sightings),
threat search (exact name / alias / ATT&CK id, then full text), one object in
full, its relationships, its containers, and the instance's status. Built so
that threat-analysis agents (gem-agent, lagent, Claude Code) can consult the
instance next to the cybersecurity-series lookups.

Production use is from a machine that the development machine cannot reach;
the development OpenCTI 6.7.4 stack on Podman is the only way to test, and it
is pinned to the production version.

Module path: `github.com/nlink-jp/opencti-lookup`. Design authority:
[docs/ja/opencti-lookup-rfp.ja.md](docs/ja/opencti-lookup-rfp.ja.md); measured
upstream behaviour: [docs/ja/opencti-lookup-phase0.ja.md](docs/ja/opencti-lookup-phase0.ja.md).

## Build / test

```bash
make build   # → dist/opencti-lookup (NEVER `go build` directly)
make test    # go test -race -cover ./... then go vet -tags e2e ./...  (offline)
make lint    # golangci-lint
make check   # lint + test + build-all
make e2e     # live tests against the dev stack (make dev-up and seed first)
```

Go 1.25+. Two dependencies, both organization libraries: `github.com/nlink-jp/toml`
(ADR-026) and `github.com/nlink-jp/pathguard` (ADR-021/022).

The dev stack: `make dev-up` / `dev-down` / `dev-reset` (deletes data);
seed with `dev/seed/push.sh`, `python3 -I dev/seed/readonly_user.py`,
`python3 -I dev/seed/attach.py`; recapture the Phase 0 replies with
`python3 -I dev/capture.py`. Secrets live in `dev/.env` (generated, mode 600,
gitignored); `make e2e` passes the tokens without printing them.

## Structure

```
main.go                   Entry point → internal/app
source_test.go            No raw control or bidi character in any source file
internal/config/          Strict TOML config (nlink-jp/toml), env, search order, warnings
internal/opencti/         GraphQL client: one POST per query, error classification
internal/ioc/             Value classification, stored forms, STIX pattern literals
internal/engine/          Shared core: lookup, search, entity, related, reports, recent, files, status
internal/save/            Writes a download into the work directory through os.Root
internal/app/             CLI shell: dispatch, flags, text and JSON rendering
internal/mcp/             stdio JSON-RPC MCP server, response budget, embedded usage.md
internal/termsafe/        The one list of characters a terminal obeys
e2e/                      Live tests (build tag e2e): engine and built binary
dev/                      Development OpenCTI 6.7.4 stack, fixtures, queries, captures
docs/{ja,en}/             RFP and Phase 0 measurement record
scripts/                  Byte-identical copies of .github/templates (signing, brew)
```

## Where the scaffold came from

Transplanted per package from the newest sibling, shodan-lookup (checked with
`git log -1 -- internal/<pkg>` across the lookups): the MCP server, its budget
backstop and the usage meta-tests, the terminal-safety code, the interleaved
flag parser, the Makefile and `source_test.go`. The config loader was
rewritten on nlink-jp/toml instead of the siblings' hand-written TOML subset.

## Key design decisions

- **Read-only, permanently.** No mutation is ever sent. The key's own
  permissions decide what is visible; the tool does not filter markings.
- **Two lookup paths.** Observables by exact value (every stored form) and
  indicators whose pattern `contains` a form, kept only when a STIX literal is
  equivalent to the value. Observable-less indicators exist in real feeds.
- **Stored values are not canonical.** IPs are asked for as given, canonical
  and (IPv6) expanded; results are mapped back by equivalence and marked
  `exact` or `equivalent`.
- **Short answers are detected by count, never by `hasNextPage`.** The cursor
  this tool issues carries how many rows were handed out.
- **Silent zero-row inputs are refused before sending**: nonexistent ids
  (existence checked first → `not_found`), unknown target types (checked
  against a list), unknown relationship types (OpenCTI's `UNSUPPORTED_ERROR`
  mapped to `invalid_argument`).
- **Partial success is failure.** Any `errors` entry fails the call;
  `extensions.cause` is never passed on.
- **The response budget lives at the MCP boundary.** Descriptions and patterns
  are exempt from the 1000-character cut; other strings over it are cut and
  named. Over 128 KB a result is cut where the cut is clean and says so: a
  lookup loses its last values (for one value, its last items), a search its
  last rows, an object the largest of description / pattern / external
  references first. A paged list is refused (`response_too_large`) because
  dropping rows would make its cursor skip them. Cursors carry a fingerprint
  of their query (and list_recent's closing time), so they continue only the
  list they came from.
- **Attachments are named by the listing, saved by the tool.** The storage id
  is taken from the object's `importFiles`, never built from the caller's
  string; the saved name is rebuilt as `opencti-lookup-<8 of the resolved
  internal id>-<8 hex of a hash of id and name>-<safe stem><ext>`, so two
  attachments never share a name; the
  work directory is judged by pathguard with this tool's config directories
  protected, and the write is confined with `os.Root` and renamed into place.
- **TLS verification can be turned off** — an accepted risk the operator chose
  for a self-hosted instance, documented in the RFP; on by default, warned
  every start, reported by `server_status`. Plain http likewise.

## Gotchas

Measured on OpenCTI 6.7.4 (2026-11-06). Re-measure before trusting them on
another version.

- **Errors mostly arrive as HTTP 200** with the kind in `extensions.code`;
  `__schema` is HTTP 500; storage answers 403 (auth) and 503 with
  `File not found or restricted` (absent or invisible).
- **`first` above 5000 is silently cut to 5000 and `hasNextPage` turns false.**
- **Introspection is refused**; read the schema from the OpenCTI repository
  at tag 6.7.4 (`config/schema/opencti.graphql` plus `src/modules/*/*.graphql`).
  `description` is per type, not on the `StixDomainObject` interface; a
  `Container` selection must not spread `... on AttackPattern`.
- **Decay rewrites indicators**: `x_opencti_score` falls, `valid_until` moves,
  `revoked` turns true (IPv4 lifetime 47 days, domains 300 days in the dev
  stack). The observable keeps its own score.
- **Confidence is filled** with the ingesting user's default when the source
  gave none.
- **The worker retries a rejected element without logging it**:
  `x_opencti_main_observable_type` takes OpenCTI type names (`IPv4-Addr`),
  and STIX spelling stalled every dependent object. When fixture ingestion
  crawls, suspect a rejection first.
- **MinIO's images are gone** (repository archived 2026-04-24); the dev stack
  builds `RELEASE.2024-05-28T17-19-04Z` from source. podman-compose hangs
  silently on an unpullable image.
- **A typed backslash-u can become the raw character** on its way into a file
  (it happened in `app_test.go`); `source_test.go` refuses it.
- **OpenCTI's unbounded-time sentinels** (1970-01-01, 5138-11-16) are not
  dates; they are dropped from relationship and entity times.
