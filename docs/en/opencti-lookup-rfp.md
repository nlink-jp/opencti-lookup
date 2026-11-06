# RFP: opencti-lookup

> Generated: 2026-11-06
> Status: Draft (Phase 0 measurements applied — [opencti-lookup-phase0.md](opencti-lookup-phase0.md))
> Translation of [docs/ja/opencti-lookup-rfp.ja.md](../ja/opencti-lookup-rfp.ja.md) (the Japanese version is primary)

## 1. Problem Statement

To widen the sources an agent can consult while doing threat analysis, expose the
threat intelligence held in a continuously running OpenCTI instance — indicators,
observables, reports, threat actors, intrusion sets, malware, ATT&CK techniques
and the relationships between them — for **read-only** search over MCP. It sits
next to the external indexes such as otx-lookup and gti-lookup, and because the
instance queried is one we are entitled to read, no packet reaches the target
under investigation.

- **Target users**: agents doing threat analysis (gem-agent, lagent, Claude Code)
  and their operators
- **What the user prepares**: only the OpenCTI URL and a read-only API key issued
  by the instance's provider, written into a config file. Building and running
  OpenCTI itself is not the user's burden (the production instance runs
  continuously in another environment)
- **Where it runs**: production use happens on a Mac in an **entirely separate
  environment** from the development machine, which cannot reach the production
  instance

## 2. Functional Specification

### Commands / API Surface

A CLI and an MCP server sharing one engine, as the sibling lookups do. When
something goes wrong on the production Mac, the same query can be run from the
CLI to isolate it.

**Phase 1 MCP tools**

| Tool | Question it answers |
|---|---|
| `lookup_ioc` | For IP, domain, URL, hash or email values (several at once, capped): the matching observables and indicators, **looked up both through observables and through indicators** and grouped per value (some indicators have no observable), with score, confidence, labels, markings (TLP etc.), author, validity window, sightings (when, where, how often observed, and false-positive sightings via `x_opencti_negative`), the reports containing them and a summary of `indicates` and similar relationships. **Not found is a normal result**, worded as "nothing within what this key can see" (not registered and not visible are indistinguishable) |
| `search_threats` | Search threat actors, intrusion sets, campaigns, malware, tools, attack patterns, vulnerabilities and reports. **Exact match on name, alias or ATT&CK id is tried first** (several exact matches are possible; ATT&CK ids work for attack patterns only), then full-text search (relevance-ordered, capped, its total never shown as a match count); the type is an enum |
| `get_entity` | One object in detail (description, aliases, external references, markings, author, and for an indicator its pattern) |
| `get_related` | Walk relationships from one object, filtered by relationship type and target type (validated against an enum), with a limit and cursor paging. The starting object is returned once, not repeated on every row. Per-relationship descriptions are omitted by default and added on request (of APT28's 93 techniques, ~78 KB: descriptions 32%, repeated ends 34%). A nonexistent id answers not_found rather than zero rows |
| `get_reports` | The containers (report, note, grouping) holding an object. In OpenCTI this is containment (`objects`), not a relationship, hence separate from `get_related`. Nested `containers` cannot page, so the root `containers(filters: objects)` is used |
| `server_status` | Connection check: OpenCTI version and whether it matches the verified version (6.7.4), the key's user name, capabilities and visible markings, whether TLS is verified, whether the URL is plain http, and the config file actually read |
| `get_usage` | The manual an agent reads first (tools, arguments, error codes, worked query examples) |

**Phase 2 MCP tools**

| Tool | Question it answers |
|---|---|
| `list_recent` | Reports and indicators from the last N days, on a selectable date axis: ingestion time `created_at` (default, "new to this instance"), the source's creation time `created`, or publication date `published`. The axes each type supports are validated (an axis a type lacks returns zero rows, not an error) |
| `get_report_file` | Save a report's attached file (PDF etc.) and return its size, type and destination. Having no workspace concept, it writes directly under `<work_dir>` with the server's name in the file name (ADR-021 §5) and returns `work_dir`, `path` and `abs_path` (§6). File names are third-party strings; the saved name is built by the tool |

ATT&CK technique lists, targeted sectors and the actors exploiting a CVE are all
reachable through `get_related` filters, so they get worked examples in
`get_usage` rather than dedicated tools.

CLI subcommands map onto the tools (names settled in Phase 1 to match the
siblings). Every subcommand, `mcp` included, accepts `--config <path>`.

### Input / Output

- Results are JSON; the CLI also renders text and has `--json`
- **Responses carry the full result under an explicit cap** (ADR-021 §3). The cap
  comes from the call argument and a configured default and ceiling; when hit,
  `truncated: true` and the total count are reported. Nothing is dropped silently.
  Spilling a large response to disk is the calling runtime's job (gem-agent
  ADR-0058, lagent ADR-0039, Claude Code's MCP output limit)
- The cap applies to the **whole response**, aggregates and reference lists
  included (the otx-lookup 162 KB lesson), in three tiers:
  1. list length (call argument, configured default and ceiling; below OpenCTI's 5,000-row page ceiling)
  2. over-long strings (descriptions and the like) are shortened, marked, and their original length given
  3. a whole-response ceiling (128 KB). `lookup_ioc` and `search_threats` drop
     values or rows from the tail and name them in notes; a paged list
     (`get_related`, `get_reports`) is not cut — dropping rows would make its
     cursor skip them — and answers `response_too_large`, asking for a smaller
     `limit` (decided while implementing Phase 1)
- **A short answer is detected by comparing the total with the rows received.**
  OpenCTI silently cuts `first` above 5,000 to 5,000 and reports `hasNextPage: false`
  (`hasNextPage` is not trusted)
- Every result carries markings, author and confidence. **No verdict
  (malicious/benign) is computed**; OpenCTI's score is passed through
- Errors are structured (`{code, message}`) and distinguish missing permission
  (`forbidden`), authentication failure, not found, connection failure and version mismatch
- **Most OpenCTI errors arrive with HTTP 200**, their kind in the body's
  `errors[].extensions.code` (`AUTH_REQUIRED`, `FORBIDDEN_ACCESS`, `FUNCTIONAL_ERROR`,
  `UNSUPPORTED_ERROR`, `DATABASE_ERROR`, `GRAPHQL_PARSE_FAILED`, `GRAPHQL_VALIDATION_FAILED`, …).
  Classification uses both HTTP status and `extensions.code`. Storage answers `HTTP 503` with
  `File not found or restricted` for "absent or not visible" and `HTTP 403` for an
  authentication failure; both are kept apart from a connection failure
- Internal detail such as `extensions.cause` (which carries Elasticsearch query bodies and internal ids) is never passed on
- **Partial success is never a complete answer.** Any entry in `errors` yields a
  structured error (a field the key may not read comes back `null` while the others return)
- **Bad inputs that OpenCTI answers with zero rows are stopped beforehand.** A nonexistent
  id, a nonexistent type name or a date axis a type lacks returns zero rows, not an error.
  Values are validated against enums and ranges, and tools that take an id check the
  object exists first and answer not_found
- A failed query is never reported as "nothing found"

**CLI exit codes** (as in the sibling lookups)

| Code | Meaning |
|---|---|
| 0 | Answered (an empty answer is a valid answer) |
| 1 | An upstream failure prevented some queries (`INCONCLUSIVE` in the output; what succeeded is printed) |
| 2 | Invalid input or configuration |

An empty result is reported as "nothing found" only when every query succeeded.

**`lookup_ioc` query rules** (from the Phase 0 measurements)

- **Two paths, grouped per value**
  - observables: exact `eq` on `stixCyberObservables` `value` (hashes under `hashes.<algorithm>`)
  - indicators: candidates whose `pattern` `contains` the value, then the returned patterns are
    parsed in the tool and only exact value matches kept (`contains` matches substrings).
    Indicators with no observable are found only this way
- Full-text search matches prefix-like and is not used
- **OpenCTI does not canonicalize stored values.** For IPv4 / IPv6 the input as given and the
  `net/netip` canonical form (and the expanded form for IPv6) are all queried under `or`.
  OpenCTI matches case-insensitively (URL paths included)
- When the match was in a different form than the input (case, IP notation), the stored form is returned with a note saying so
- A hash is classified by length — MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128) — (`value` does not match)
- In multi-value lookups, results are mapped back to inputs by normalized value
- Sightings come from one `stixSightingRelationships(filters: fromId)` query over the array of indicator and observable ids
- **Decay is passed through uninterpreted.** OpenCTI rewrites an indicator's `valid_until`,
  `x_opencti_score` and `revoked` under its decay rules. Revoked indicators are not hidden;
  `revoked`, the current score, `decay_base_score` and `valid_until` are reported side by side,
  and observable and indicator scores are reported separately
- `get_usage` states that confidence is not necessarily the source's (it may be the ingesting user's default)
- MCP tool schemas are closed (`additionalProperties: false`)

### Configuration

- Default locations are searched in order and the first that exists is used (knowledge
  config-and-io): `$XDG_CONFIG_HOME/opencti-lookup/config.toml` → `~/.config/opencti-lookup/config.toml`
  → `~/Library/Application Support/opencti-lookup/config.toml`. `server_status` and the CLI
  diagnostics show the path actually read, or the list of paths searched
- A config file whose permissions are not 0600 draws a warning on stderr (CONVENTIONS)
- `--config <path>` selects another file. **An explicitly named file that does not
  exist stops with an error naming the path** (the siblings silently continue as
  if no file were given; that makes isolation on the production machine harder,
  so this tool differs). A missing file at the default location is not an error
- Precedence: flag > environment (`OPENCTI_LOOKUP_*`) > config file > default
- Settings
  - `url` (required). `https://` is recommended, but **`http://` is accepted** (the user's
    decision). Over plain http the CLI warns once at start-up that the token travels
    unencrypted, and `server_status` reports it (CONVENTIONS: tools that send credentials
    over unencrypted HTTP must warn)
  - `token` (required; also `OPENCTI_LOOKUP_TOKEN`; never printed, logged or put in a URL)
  - `ca_file` (trust a self-signed or internal-CA certificate)
  - `insecure_skip_verify` (default false; also `--insecure`)
  - timeout, default and maximum result counts
- The config file holds a credential and is gitignored; `config.example.toml` ships
- No cache (the instance has no usage quota, and connectors update it
  continuously, so a stale answer does more harm than a repeated query)

### External Dependencies

- The OpenCTI 6.7.4 GraphQL API (`/graphql`, `Authorization: Bearer <token>`) only
- For development: an OpenCTI 6.7.4 stack on Podman (platform, worker,
  Elasticsearch, Redis, RabbitMQ, MinIO, STIX import connector, MITRE connector).
  MinIO's official images are gone, so the release the 6.7.4 compose pinned is
  built from official source

## 3. Design Decisions

- **Go, standard library only**, matching the sibling lookups. pycti (Filigran's
  official client) is Python; from Go the GraphQL API is called directly over net/http
- **Organization building blocks**
  - Config parsing: `nlink-jp/toml` (ADR-026)
  - Release and signing wiring: copies of the CONVENTIONS templates (ADR-028's shared kit
    was withdrawn; copying is the current way)
  - Path judgement for `get_report_file`: `nlink-jp/pathguard` (ADR-022, amending ADR-021 §4, §7, §10)
  - MCP skeleton transplanted from the newest sibling (chosen per package by `git log`)
- **No existing OpenCTI MCP server is adopted.** No official Filigran MCP server
  was found, only a community one (DarkAngel-agents/opencti-mcp, MIT); per the
  organization's supply-chain policy this one is written in-house
- **Complements**: otx-lookup and gti-lookup (external threat intelligence),
  cve-lookup (vulnerability severity and exploitation; not duplicated here)
- **Where control lives**: what is visible is decided by the key (the OpenCTI user
  and group). The tool does not filter by marking
- **Disabling TLS verification is an accepted risk, with its reason.** The
  production instance is self-hosted and its certificate is not properly set up.
  With verification off, someone on the path could steal the token; the path is
  inside the user's own environment and the user accepts that risk. Verification
  is on by default, and the README points to `ca_file` first. When disabled,
  `server_status` reports it and the CLI warns once at start-up (not on every result)
- **Permanently out of scope**
  - Every write (creating entities or relationships, triggering enrichment, creating cases)
  - The live stream (SSE)
  - Reading the organization's own incident-response cases and RFIs
  - Bulk STIX bundle export

## 4. Development Plan

### Phase 0: Development environment and measurement (before code) — done 2026-11-06

Results are in [opencti-lookup-phase0.md](opencti-lookup-phase0.md). What follows is the plan as written.

- Bring an OpenCTI 6.7.4 development stack up and down with a compose file in the
  repository and `make dev-up` / `make dev-down`, based on the official docker setup
- Start-up checks: whether the whole stack starts on the 16 GB Podman machine, and
  whether the MITRE connector (amd64-only at 6.7.4) runs and ingests under qemu emulation
- Measure and record (ADR-023)
  - The GraphQL queries each tool will use and the actual response shapes
  - How to match an IOC value exactly (a filter, not full-text search)
  - The maximum page size per query
  - How an attached file is fetched and which capability it needs
  - The capabilities and markings `me` returns
- Create a read-only user in the development stack shaped like the production one
- **Review point**: review the measurements before Phase 1. The design is
  finalized here, with an independent sub-agent verification pass

### Phase 1: Core functionality and tests — implemented 2026-11-06

The six tools and the CLI, with offline tests (`make test`) and live tests
against the development stack (`make e2e`). What was measured while
implementing is recorded in AGENTS.md (Gotchas). What follows is the plan as written.

- Config (`--config`, `ca_file`, `insecure_skip_verify`), GraphQL client, engine,
  the seven Phase 1 tools, CLI
- Offline tests (`make test`): responses captured from the development stack as
  fixtures, served by an `httptest` server. TLS is tested against a self-signed
  `httptest.NewTLSServer`: verified fails, `ca_file` succeeds, `insecure` succeeds.
  Meta-tests pin `usage.md` to the code
- Live tests (`make e2e`, `e2e` build tag) against the development containers

### Phase 2: Additional features — implemented 2026-11-06

`get_entity` lists attachments (`files`), and `get_report_file` accepts only
a name from that listing (the storage id is taken from the listing, never
built from the caller's string). What follows is the plan as written.

- `list_recent`
- `get_report_file` (ADR-021 `work_dir` contract, pathguard)

### Phase 3: Documentation and release

- README.md / README.ja.md, AGENTS.md, CHANGELOG.md
- Release (signing, notarization, zips, Homebrew tap), integration into
  cybersecurity-series, org profile, knowledge feedback, check-org
- Independent sub-agent verification before release
- **Production check**: on the production Mac the user runs `server_status` and a
  few lookups and records the result (capabilities and markings especially). The
  development machine cannot reach production, so this step is the user's

### Independently reviewable units

The Phase 0 measurement record, Phase 1, Phase 2 and Phase 3 can each be
reviewed on their own.

### Not part of this plan

- Adding the server to the mcp-tactics skill (work in skills-series). An issue is
  raised there at release, and decided there

## 5. Required API Scopes / Permissions

- **One read-only API key issued by the instance's provider.** The user cannot
  create users or groups; what the key can see is the provider's decision
- Sending results to an LLM (cloud or local) is accepted by the user
- The tool assumes nothing about the key's permissions
  - Missing permission is the structured error `forbidden`, distinct from "not found"
  - `server_status` returns the key's user name, capabilities and visible markings
- In development, a read-only user is created with the capabilities that
  `server_status` reports in production, and tests run as that user
- With the development read-only user (role `KNOWLEDGE` only), `about`, `me`,
  knowledge queries and attachment listing and download (`/storage/get/`) all
  succeed; administrative queries and writes answer `FORBIDDEN_ACCESS`
- **Residual risk**: the issued production key need not match the development
  shape. Whether `get_report_file` works is checked in the production check
  (Phase 3); if not, that tool answers `forbidden`

## 6. Series Placement

Series: cybersecurity-series
Reason: it is the same kind of tool as the read-only threat-intelligence lookups
(otx-lookup, gti-lookup, cve-lookup and others), and is named to match them.

## 7. External Platform Constraints

- **Version dependence**: the GraphQL schema changes between OpenCTI versions.
  Only 6.7.4, the production version, is verified; `server_status` warns on a mismatch
- **Measured in Phase 0** (details in the measurement record)
  - The page ceiling is 5,000 rows. Asking for more is silently cut to 5,000 with
    `hasNextPage: false`. A negative `first` is a `DATABASE_ERROR`
  - Whole-schema introspection (`__schema`) is refused with HTTP 500 (`__type` works).
    The schema is read from the OpenCTI repository at tag 6.7.4 (some types, such as
    Indicator, exist only under `src/modules/`)
  - Errors mostly arrive as HTTP 200 with `extensions.code`; storage answers "absent or
    not visible" with 503 and an authentication failure with 403
  - A nonexistent id, type name or filter axis returns zero rows, not an error
  - OpenCTI does not canonicalize stored values (an IPv6 stored expanded does not match its canonical form)
  - "Not registered" and "not visible to this key" are indistinguishable
  - Full-text search is relevance-ordered and its total is not a match count
- **Rate limits**: OpenCTI's own default limit is unconfirmed, and a reverse proxy
  in front may impose one, so 429 and similar are returned as structured errors
- **Connector images**: platform and worker 6.7.4 ship amd64 and arm64, but the
  MITRE connector 6.7.4 is amd64-only (checked on Docker Hub, 2026-11-06). It runs
  under qemu in development (the Podman machine has Rosetta off and qemu-x86_64 registered)
- **Network path**: the path from the production Mac to the instance cannot be
  checked from the development machine. `ca_file` and `insecure_skip_verify` exist
  for the self-signed, incomplete certificate
- **Data contains third-party text**: OpenCTI's content is prose ingested from
  external feeds and reports, written by anyone. `get_usage` states that text which
  looks like instructions is data
- **Development machine**: the Podman machine is shared with data-toolbox-mcp and
  pcap-analyzer-mcp. 16 GB (about 14 GB usable inside the VM), 6 CPUs,
  `vm.max_map_count = 1048576` (sufficient by default). The running stack uses about 5 GB
- **Development stack parts**: minio/minio was archived on 2026-04-24 and its public
  images cannot be pulled. OpenCTI's compose moved to a community fork (pgsty/silo);
  this project builds from official source instead. podman-compose hangs without an
  error on an unpullable image
- **The worker retries rejected elements without logging them.** When fixture ingestion
  is slow, suspect a rejection first (the real case: `x_opencti_main_observable_type`
  takes OpenCTI type names such as `IPv4-Addr`; STIX spelling is rejected)

---

## Discussion Log

1. **Feasibility**: the official documentation states Podman support for an OpenCTI
   development environment. The early concerns were arm64 images and memory;
   `podman manifest inspect` showed arm64 for platform, worker and MITRE connector at `latest`
2. **Direction**: "search OpenCTI" versus "ingest into OpenCTI" was put to the user;
   search (read-only) was chosen
3. **Where the instance lives**: production is an instance running continuously in
   another environment; the development containers are for testing only. Running
   OpenCTI is not the user's burden, so setup weight (the reason gdrive-collector
   was cancelled) was judged not to be an issue
4. **Version**: production is 6.7.4 (confirmed by the user) and the development stack
   matches it. Platform and worker 6.7.4 have arm64, but the MITRE connector is
   amd64-only. Pairing a newer connector with the older platform was rejected as
   defeating the point of matching versions; qemu emulation was chosen
5. **Where it runs**: production use is from a Mac in an entirely separate environment.
   Distribution is release zips and the Homebrew tap; the production check is the user's
6. **Name**: `opencti-lookup`, matching the sibling lookups (`opencti-mcp` was the alternative)
7. **More features**: at the user's question "what else could it offer", the options
   were listed. Sightings and multi-value lookup went into Phase 1's `lookup_ioc`,
   `list_recent` into Phase 2. ATT&CK, targets and CVE exploitation are served by `get_related`
8. **Large responses**: attached files were first ruled out as "too large"; the user
   pointed out that server-side spilling is withdrawn and the runtime does it
   (ADR-021 §3). All three clients — gem-agent, lagent, Claude Code — were confirmed
   to spill (Claude Code files successful results over 25,000 tokens or 50,000
   characters). Attached files are a file product, so they entered Phase 2 under the `work_dir` contract
9. **Is ADR-021 current**: checked at the user's question. It is Accepted; ADR-022
   amends only §4, §7 and §10. §3 stands
10. **Cache and CLI**: no cache; both CLI and MCP
11. **Permissions**: the key is issued by the provider and the user cannot create one;
    sending to an LLM is accepted. The tool assumes no permission and `server_status` shows what it can do
12. **`--config`**: adopted at the user's suggestion, matching gti-lookup and
    shodan-lookup, except that a missing explicit path is an error rather than
    silently ignored. The siblings' behaviour is out of scope here
13. **Disabling TLS verification**: requested because the self-hosted instance's
    certificate is not properly set up. The token-exposure risk is accepted with its
    reason; verification stays on by default and `ca_file` is recommended first
14. **Replacing MinIO** (Phase 0): with the official images gone, the community fork
    OpenCTI adopted (pinned by digest) was weighed against building from official
    source; the user chose the source build
15. **Applying Phase 0**: the seven proposed RFP changes from the measurement record
    were applied with the user's approval (error classification, `lookup_ioc` query
    rules and decay, exact match first in `search_threats`, descriptions omitted in
    `get_related`, the date axis of `list_recent`, the permission results, constraints)
16. **Independent verification** (design finalization): a sub-agent recounted the
    measurements from the captures and the live stack and checked the design against the
    recorded lessons. Every finding, including the heavy ones (the 5,000-row page ceiling
    that truncates silently with `hasNextPage` false; citing the withdrawn ADR-028), was
    confirmed by recapturing before being adopted. The measurement record was corrected as
    its second edition (§11 there), and the RFP gained: two lookup paths and stored-form
    handling, the three-tier cap and short-answer detection, the extended error
    classification with internal detail withheld, pre-validation of inputs, CLI exit codes,
    the config search order and 0600 warning, and `get_report_file` following ADR-021 §5–§6
17. **Plain http**: the verifier proposed refusing non-loopback http as shodan-lookup does;
    by the user's decision it is accepted with a warning (CONVENTIONS requires a warning)
