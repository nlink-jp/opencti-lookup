# Phase 0 measurements: opencti-lookup

> Measured: 2026-11-06
> Target: development OpenCTI 6.7.4 (`dev/compose.yaml`), fictional fixtures (`dev/seed/bundle.json`) and MITRE ATT&CK
> Design authority: [opencti-lookup-rfp.md](opencti-lookup-rfp.md)
> Translation of [docs/ja/opencti-lookup-phase0.ja.md](../ja/opencti-lookup-phase0.ja.md) (the Japanese version is primary)

What the RFP's Phase 0 said must be measured rather than guessed, measured on the
development stack. Queries are in `dev/queries/`, replies in `dev/captures/` (both
committed). Everything here was observed on 6.7.4; re-measure when the version moves.

## 1. Development stack

| Item | Result |
|---|---|
| Start-up | `make dev-up` brings up all eight containers; the platform turns healthy within minutes |
| Version | `{ about { version } }` → `6.7.4` |
| Memory | of the 16 GB VM, about 5 GB used and 9.8 GB available (Elasticsearch largest at 4.5 GB) |
| MITRE connector | the amd64 image runs under qemu and finished ingesting (1,532 attack patterns, ~180 intrusion sets) |
| Fixtures | 128 indicators, 128 observables, 4 reports, 1 sighting |

### What bit during bring-up

- **The MinIO image is gone.** minio/minio was archived on 2026-04-24 and its images on
  Docker Hub and quay.io can no longer be pulled (access denied). OpenCTI's current compose
  moved to the community fork `pgsty/silo:latest`. By the user's decision this project
  builds `RELEASE.2024-05-28T17-19-04Z`, the release the 6.7.4 compose pinned, from
  official source (`dev/minio/Containerfile`, digest-pinned bases, tag commit verified)
- **podman-compose hangs silently on an unpullable image** — 23 minutes with no error.
  Start-up is now watched for state changes and health, with a deadline
- **The refs API returns the tag object's id for an annotated tag.** Verify against the
  sha from `repos/<r>/commits/<tag>` (f79a4ef4…, not f92beb79…)
- **GraphQL introspection is refused** (`GraphQL introspection not authorized!`). The
  schema is read from the OpenCTI repository at tag 6.7.4: `config/schema/opencti.graphql`
  plus `src/modules/*/*.graphql`; some types, such as Indicator, exist only in the modules
- **The worker retries a rejected element without logging it.** With
  `x_opencti_main_observable_type` in STIX spelling (`ipv4-addr`) the platform rejected the
  indicator (`Observable type ipv4-addr is not supported.`), the worker logged nothing, and
  every dependent relationship, sighting and report crawled at one per tens of seconds.
  The value takes OpenCTI type names (`IPv4-Addr`, `StixFile`, …)

## 2. Error shape

**HTTP is always 200.** The kind of error appears only in the body's `errors[].extensions.code`.

| Situation | `extensions.code` | `extensions.data.http_status` |
|---|---|---|
| No token or a wrong one (indistinguishable) | `AUTH_REQUIRED` | 401 |
| Missing permission | `FORBIDDEN_ACCESS` | 403 |
| Business rejection | `FUNCTIONAL_ERROR` | 400 |
| Input validation failure | `BAD_USER_INPUT` | — |
| Introspection refused, non-null field null | `INTERNAL_SERVER_ERROR` | — |
| Negative `first` | (message `Fail to execute engine pagination`) | — |

**Partial success exists.** A query that includes a field the user may not read returns
`null` and an error for that field, and data for the others (checked by hand, not captured).

→ **Design**: classify by `extensions.code`, not HTTP status. Any entry in `errors` yields
a structured error; partial data is never returned as a complete answer.

## 3. IOC lookup (`lookup_ioc`)

Queried with `stixCyberObservables(filters: {key: ["value"], operator: eq})`.

| Test | Result | Capture |
|---|---|---|
| `192.0.2.10` | 1 | `eq-ipv4.json` |
| `192.0.2.1` (prefix check) | 0 — no over-matching | `eq-ipv4-prefix.json` |
| `BAD.EXAMPLE.COM` | 1 — **case-insensitive** | `eq-domain-upper.json` |
| `2001:db8::10` | 1 | `eq-ipv6.json` |
| `2001:0db8:0000:…:0010` (non-canonical) | **0** | `eq-ipv6-long.json` |
| SHA-256 under `value` | **0** | `eq-sha256-value.json` |
| SHA-256 under `hashes.SHA-256` | 1, upper case too | `eq-sha256-hashes.json` / `-upper.json` |
| Unknown `192.0.2.200` | 0 | `eq-notfound.json` |
| Full-text `search: "192.0.2.1"` | returns 192.0.2.10 | `search-prefix.json` |

→ **Design**:
- Canonicalize IPv6 (and IPv4) with `net/netip` before querying
- Classify a hash as MD5 / SHA-1 / SHA-256 by length and query `hashes.<algorithm>`
- Never use full-text search for IOC lookup

### What one query returns

`indicators`, `containers` and `stixCoreRelationships` nest under an observable and come
back in one query. Relationship ends resolve to a name for any type with
`... on BasicObject { id entity_type } ... on StixCoreObject { representative { main } }`.

- `indicates` (indicator → malware) is **the indicator's relationship**; under the
  observable only `based-on` appears
- Sightings cannot be reached from the Indicator type. `stixSightingRelationships(filters:
  {key: ["fromId"], values: [indicator ids…]})` fetches them for several indicators at once
  (`sightings-fromId.json`). A sighting carries `x_opencti_negative` (a false-positive
  sighting), `attribute_count` (how many times), `first_seen` / `last_seen`

### Decay rewrites indicators

Values ingested versus values returned (`eq-ipv4.json`):

| Field | Ingested | Returned |
|---|---|---|
| `valid_until` | 2027-12-31 | **2026-10-01** (recomputed) |
| `x_opencti_score` | 85 | **20** (original kept as `decay_base_score: 85`) |
| `revoked` | — | **true** |
| `decay_applied_rule.decay_lifetime` | — | 47 (days) |

The observable's `x_opencti_score` stays 85. **One value carries two scores: 85 on the
observable, 20 on the indicator.**

→ **Design**: return revoked indicators rather than hiding them, alongside `revoked`, the
current score, `decay_base_score` and `valid_until`. Observable and indicator scores are
reported separately. Whether production enables decay is unknown, so the tool passes the
values through without interpreting them.

### Confidence may be filled in

A sighting ingested with no confidence came back with `confidence: 100`, apparently the
ingesting user's default. → `get_usage` states that confidence is not necessarily the source's.

## 4. Permissions and markings (read-only user)

Created by `dev/seed/readonly_user.py`: a role with `KNOWLEDGE` only, markings TLP:CLEAR /
GREEN / AMBER (RED withheld).

| Test | Result |
|---|---|
| `{ about { version } }` | allowed |
| `me { capabilities allowed_marking … }` | `['KNOWLEDGE']` and the three TLPs — **enough to build `server_status`** |
| Look up TLP:RED `198.51.100.7` | **0 results, no error** (`readonly-198.51.100.7.json`) |
| Containers of `192.0.2.10` | the RED report is left out of the total too (`readonly-192.0.2.10.json`) |
| Administrative `capabilities` | `FORBIDDEN_ACCESS` |
| A write (`indicatorAdd`) | `FORBIDDEN_ACCESS` |

→ **Design**: **"not registered" and "not visible to this key" are indistinguishable.**
`lookup_ioc` words a miss as "nothing within what this key can see", and `server_status`
shows what the key can see.

## 5. Threat search (`search_threats`)

| Method | Result |
|---|---|
| Full-text `stixDomainObjects(search:)` | relevance-ordered; **the total is meaninglessly large** (300 for `TA-FIXTURE-01`, 849 for `IGNORE ALL PREVIOUS`). Aliases match but ranking wobbles (`Fancy Bear` puts APT28 second; `Sofacy` leaves it out of the top four) |
| Exact `filters` on `name` / `aliases` / `x_opencti_aliases`, `or` | unique hits, case-insensitive (`Sofacy`, `sofacy`, `Fancy Bear`, `apt28` → APT28) |
| ATT&CK id `x_mitre_id` `eq` | `t1566` → `[T1566] Phishing` |

→ **Design**: try exact match (name, alias, ATT&CK id) first, fall back to full-text with a
result cap. The full-text total is never presented as a match count.

## 6. Relationships, detail, page size

| Test | Result |
|---|---|
| APT28 → `uses` → Attack-Pattern | 93 rows, **about 75 KB**, mostly the per-relationship descriptions (up to 679 characters) (`related-apt28-uses-ap.json`) |
| APT28 detail | about 13 KB, of which 28 external references are about 9 KB (`entity-apt28.json`) |
| Page size | `first: 5000` returned 1,379 at once; any higher ceiling is unmeasured for lack of data |
| `first: 0` | no rows, total only (usable for counting) |
| `first: -1` | error |

→ **Design**: `get_related` omits relationship descriptions by default and adds them on
request. Count arguments are validated as non-negative before sending.

## 7. Attached files (`get_report_file`)

| Test | Result |
|---|---|
| Listing | `report(id) { importFiles { … id name size metaData { mimetype } } }`; ids are `import/Report/<report id>/<file name>` |
| Download as the read-only user | `GET /storage/get/<url-encoded id>` → 200; `/storage/view/` the same |
| Naming the attachment of an invisible RED report | **HTTP 503**, `{"status":"error","error":"File not found or restricted"}` |
| A file that does not exist | the same 503 and body |

→ **Design**: `KNOWLEDGE` alone was enough (the RFP's residual risk did not apply to the
development shape; the issued production key still needs checking). This 503 with this
body maps to "absent or not visible", distinct from a connection failure.

## 8. Recent items (`list_recent`)

| Field | Meaning | Filtered to ≥ 2026-11-01 |
|---|---|---|
| `created_at` | when OpenCTI ingested it | 4 (ingested today) |
| `created` | when the source created it | 0 (dated 1 October) |
| `published` | a report's publication date | 0 |

→ **Design**: let the caller choose between "new to this instance" and "newly published";
default to `created_at`.

## 9. Instruction-shaped text

The malware whose description reads `IGNORE ALL PREVIOUS INSTRUCTIONS…` ranks first in
full-text search like any other text; OpenCTI does not alter content. → As the RFP says,
`get_usage` states that such text is data.

## 10. Proposed RFP changes (applied after review)

1. §2 Input/Output: classify errors by `extensions.code`; never return partial data as complete (§2)
2. §2 `lookup_ioc`: IPv4/IPv6 canonicalization, per-algorithm hash keys, decay fields,
   sighting `x_opencti_negative`, the "nothing within what this key can see" wording (§3, §4)
3. §2 `search_threats`: exact match first, full-text second (§5)
4. §2 `get_related`: descriptions omitted by default (§6)
5. §2 `list_recent`: selectable date axis (§8)
6. §5 Permissions: attachments needed only `KNOWLEDGE` in the development shape; keep the production check (§7)
7. §7 Constraints: MinIO source build, no introspection, HTTP always 200, the worker's
   silent retries, the storage 503 (§1, §2, §7)
