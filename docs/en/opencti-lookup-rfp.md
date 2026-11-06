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
| `lookup_ioc` | For IP, domain, URL, hash or email values (several at once, capped): the matching observables and indicators with score, confidence, labels, markings (TLP etc.), author, validity window, sightings (when, where, how often observed, and false-positive sightings via `x_opencti_negative`), the reports containing them and a summary of `indicates` and similar relationships. **Not found is a normal result**, worded as "nothing within what this key can see" (not registered and not visible are indistinguishable) |
| `search_threats` | Search threat actors, intrusion sets, campaigns, malware, tools, attack patterns, vulnerabilities and reports. **Exact match on name, alias or ATT&CK id is tried first**, then full-text search (relevance-ordered, capped); the type is an enum |
| `get_entity` | One object in detail (description, aliases, external references, markings, author, and for an indicator its pattern) |
| `get_related` | Walk relationships from one object, filtered by relationship type and target type, with a limit and cursor paging. Per-relationship descriptions are omitted by default and added on request (most of the ~75 KB for APT28's 93 techniques was descriptions) |
| `get_reports` | The containers (report, note, grouping) holding an object. In OpenCTI this is containment (`objects`), not a relationship, hence separate from `get_related` |
| `server_status` | Connection check: OpenCTI version and whether it matches the verified version (6.7.4), the key's user name, capabilities and visible markings, and whether TLS is verified |
| `get_usage` | The manual an agent reads first (tools, arguments, error codes, worked query examples) |

**Phase 2 MCP tools**

| Tool | Question it answers |
|---|---|
| `list_recent` | Reports and indicators from the last N days, on a selectable date axis: ingestion time `created_at` (default, "new to this instance"), the source's creation time `created`, or publication date `published` |
| `get_report_file` | Save a report's attached file (PDF etc.) under `<work_dir>/<workspace_id>/` and return its path, size and type |

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
  included (the otx-lookup 162 KB lesson)
- Every result carries markings, author and confidence. **No verdict
  (malicious/benign) is computed**; OpenCTI's score is passed through
- Errors are structured (`{code, message}`) and distinguish missing permission
  (`forbidden`), authentication failure, not found, connection failure and version mismatch
- **OpenCTI always answers HTTP 200.** Errors are classified by the body's
  `errors[].extensions.code` (`AUTH_REQUIRED`, `FORBIDDEN_ACCESS`, `FUNCTIONAL_ERROR`,
  `BAD_USER_INPUT`, …). Storage's `HTTP 503` with `File not found or restricted` means
  "absent or not visible" and is kept apart from a connection failure
- **Partial success is never a complete answer.** Any entry in `errors` yields a
  structured error (a field the key may not read comes back `null` while the others return)
- A failed query is never reported as "nothing found"

**`lookup_ioc` query rules** (from the Phase 0 measurements)

- Lookup is an exact `eq` on `value`. Full-text search matches prefix-like and is not used
- IPv4 / IPv6 are canonicalized with `net/netip` before querying (non-canonical IPv6 does not match)
- A hash is classified as MD5 / SHA-1 / SHA-256 by length and queried under `hashes.<algorithm>` (`value` does not match)
- OpenCTI matches case-insensitively
- Sightings come from one `stixSightingRelationships(filters: fromId)` query over the array of indicator ids
- **Decay is passed through uninterpreted.** OpenCTI rewrites an indicator's `valid_until`,
  `x_opencti_score` and `revoked` under its decay rules. Revoked indicators are not hidden;
  `revoked`, the current score, `decay_base_score` and `valid_until` are reported side by side,
  and observable and indicator scores are reported separately
- `get_usage` states that confidence is not necessarily the source's (it may be the ingesting user's default)
- MCP tool schemas are closed (`additionalProperties: false`)

### Configuration

- Default location: `~/.config/opencti-lookup/config.toml` (honours XDG_CONFIG_HOME)
- `--config <path>` selects another file. **An explicitly named file that does not
  exist stops with an error naming the path** (the siblings silently continue as
  if no file were given; that makes isolation on the production machine harder,
  so this tool differs). A missing file at the default location is not an error
- Precedence: flag > environment (`OPENCTI_LOOKUP_*`) > config file > default
- Settings
  - `url` (required)
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
  - Release: the shared release kit (ADR-028)
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

### Phase 1: Core functionality and tests

- Config (`--config`, `ca_file`, `insecure_skip_verify`), GraphQL client, engine,
  the seven Phase 1 tools, CLI
- Offline tests (`make test`): responses captured from the development stack as
  fixtures, served by an `httptest` server. TLS is tested against a self-signed
  `httptest.NewTLSServer`: verified fails, `ca_file` succeeds, `insecure` succeeds.
  Meta-tests pin `usage.md` to the code
- Live tests (`make e2e`, `e2e` build tag) against the development containers

### Phase 2: Additional features

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
  - `first: 5000` returned 1,379 rows at once; any higher ceiling is unmeasured
    for lack of data. A negative `first` is an error
  - GraphQL introspection is refused; the schema is read from the OpenCTI
    repository at tag 6.7.4 (some types, such as Indicator, exist only under `src/modules/`)
  - HTTP is always 200 (errors in `extensions.code`); storage answers "absent or not visible" with 503
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
