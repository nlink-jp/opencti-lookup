# Phase 0 measurements: opencti-lookup

> Measured: 2026-11-06 (second edition: recaptured after the independent verification)
> Target: development OpenCTI 6.7.4 (`dev/compose.yaml`), fictional fixtures (`dev/seed/`) and MITRE ATT&CK
> Design authority: [opencti-lookup-rfp.md](opencti-lookup-rfp.md)
> Translation of [docs/ja/opencti-lookup-phase0.ja.md](../ja/opencti-lookup-phase0.ja.md) (the Japanese version is primary)

What the RFP's Phase 0 said must be measured rather than guessed, measured on the development stack.

- **To reproduce**: `make dev-up` → `dev/seed/push.sh` → `python3 -I dev/seed/readonly_user.py` →
  `python3 -I dev/seed/attach.py` → `python3 -I dev/capture.py`
- **Evidence**: each claim's "evidence" is `dev/captures/<name>.json`. Every file holds the query,
  variables, user, HTTP status, reply and, where something was removed, what (`trimmed`)
- Everything here was observed on 6.7.4; re-measure when the version moves

## 1. Development stack

| Item | Result |
|---|---|
| Start-up | `make dev-up` brings up all eight containers; the platform turns healthy within minutes |
| Version | `about.version` = `6.7.4` (evidence: `me-admin`) |
| Memory | of the 16 GB VM, about 5 GB used and 9.8 GB available (Elasticsearch largest at 4.5 GB) |
| MITRE connector | the amd64 image runs under qemu and finished ingesting (1,532 attack patterns, 190 intrusion sets) |
| Fixtures | 130 indicators, 130 observables, 4 reports, 1 note, 1 grouping, 3 sightings, 1 vulnerability |

### What bit during bring-up

- **The MinIO image is gone.** minio/minio was archived on 2026-04-24 and its images on Docker Hub
  and quay.io can no longer be pulled (access denied). OpenCTI's current compose moved to the community
  fork `pgsty/silo:latest`. By the user's decision this project builds `RELEASE.2024-05-28T17-19-04Z`,
  the release the 6.7.4 compose pinned, from official source (`dev/minio/Containerfile`, digest-pinned
  bases, tag commit verified)
- **podman-compose hangs silently on an unpullable image** — 23 minutes with no error. Start-up is
  now watched for state changes and health, with a deadline
- **The refs API returns the tag object's id for an annotated tag.** Verify against the sha from
  `repos/<r>/commits/<tag>` (f79a4ef4…, not f92beb79…)
- **Whole-schema introspection (`__schema`) is refused with HTTP 500** (the platform log says
  `GraphQL introspection not authorized!`; the reply is `INTERNAL_SERVER_ERROR`; evidence:
  `err-introspection-schema`). Single-type `__type(name:)` works (evidence: `err-introspection-type`).
  The schema is read from the OpenCTI repository at tag 6.7.4: `config/schema/opencti.graphql` plus
  `src/modules/*/*.graphql`; some types, such as Indicator, exist only in the modules
- **The worker retries a rejected element without logging it.** With `x_opencti_main_observable_type`
  in STIX spelling (`ipv4-addr`) the platform rejected the indicator (`Observable type ipv4-addr is not
  supported.`), the worker logged nothing, and every dependent relationship, sighting and report crawled
  at one per tens of seconds. The value takes OpenCTI type names (`IPv4-Addr`, `StixFile`, …)
- **A sighting of an observable is accepted** (outside STIX 2.1, but ingested; evidence: `sightings-of-observable`)

## 2. Error shape

Most errors arrive with **HTTP 200**, their kind in the body's `errors[].extensions.code`. The
exceptions: `__schema` answers HTTP 500, and storage (§7) answers 403 / 503.

| Situation | HTTP | `extensions.code` | Evidence |
|---|---|---|---|
| No token or a wrong one (indistinguishable) | 200 | `AUTH_REQUIRED` | `err-no-token`, `err-bad-token` |
| Missing permission (read or write) | 200 | `FORBIDDEN_ACCESS` | `err-forbidden-read`, `err-forbidden-write` |
| Business rejection | 200 | `FUNCTIONAL_ERROR` | checked by hand while fixing the fixtures (§1) |
| Unknown filter key | 200 | `UNSUPPORTED_ERROR` | `err-unknown-filter-key` |
| Negative `first` | 200 | `DATABASE_ERROR` (its `cause` carries the Elasticsearch query body and internal group ids; removed in the record) | `err-negative-first` |
| Syntax error | 200 | `GRAPHQL_PARSE_FAILED` (no `data`) | `err-parse` |
| Nonexistent field | 200 | `GRAPHQL_VALIDATION_FAILED` (no `data`) | `err-validation` |
| `__schema` | **500** | `INTERNAL_SERVER_ERROR` | `err-introspection-schema` |

**Partial success exists.** A query including a field the user may not read returns `null` and an
error for that field and data for the others (evidence: `err-partial`).

**Some bad inputs return zero rows silently** (no error):
- relationships of a nonexistent id (evidence: `related-nonexistent-id`)
- a nonexistent type name in `toTypes` (evidence: `related-unknown-totype`)

The verifier reports that the same root field three or more times is refused with "Allowed number of
calls … (max: 2)" (not captured here).

→ **Design**:
- Classify by both HTTP status and `extensions.code`
- Any entry in `errors` yields a structured error; partial data is never returned as complete
- Internal detail such as `cause` is never passed on
- Values are validated against enums and ranges before sending, and tools that take an id check the object exists first

## 3. IOC lookup (`lookup_ioc`)

### Through observables

`stixCyberObservables(filters: {key, operator: eq})`.

| Test | Result | Evidence |
|---|---|---|
| `192.0.2.10` | 1 | `ioc-ipv4` |
| `192.0.2.1` (prefix check) | 0 — no over-matching | `ioc-ipv4-prefix` |
| `BAD.EXAMPLE.COM` | 1 — case-insensitive | `ioc-domain-upper` |
| `http://bad.example.com/PAYLOAD.BIN` | **1** — the URL path is case-insensitive too (the stored lower-case value comes back) | `ioc-url-upper-path` |
| `2001:db8::10` (stored canonical) | 1 | `ioc-ipv6` |
| the same value queried expanded | **0** | `ioc-ipv6-query-expanded` |
| an IPv6 stored expanded and upper-case, queried canonical | **0** | `ioc-ipv6-stored-expanded-query-canonical` |
| the same, queried as stored | 1 | `ioc-ipv6-stored-expanded-query-as-stored` |
| SHA-256 under `value` | **0** | `ioc-sha256-by-value` |
| SHA-256 / MD5 / SHA-1 / SHA-512 under `hashes.<algorithm>` | 1 each, upper case too | `ioc-sha256`, `-upper`, `ioc-md5`, `ioc-sha1`, `ioc-sha512` |
| unknown `192.0.2.200` | 0 | `ioc-notfound` |
| `orphan.example.org`, an indicator with no observable | **0** | `ioc-orphan-via-observables` |
| full-text `search: "192.0.2.1"` | returns 192.0.2.10 | `ioc-search-prefix` |

### Through indicators

Indicators with no observable are common in real feeds and invisible to an observable lookup.

| Test | Result | Evidence |
|---|---|---|
| `indicators` with `name` = `orphan.example.org` | 1 | `indicator-by-name` |
| `pattern` `contains` `orphan.example.org` | 1 | `indicator-by-pattern-contains` |
| `pattern` `contains` `orphan.example` | **1** (substring) | `indicator-by-pattern-contains-partial` |

→ **Design**:
- Query both through observables and through indicators, and group results per value
- An indicator's `name` need not be its value: fetch candidates with `pattern` `contains`, parse the
  returned patterns in the tool, and keep only exact value matches
- **OpenCTI does not canonicalize stored values.** For IPs, query the input as given and the canonical
  form (and the expanded form for IPv6) together with `or`; OpenCTI folds case itself
- Classify a hash by length — MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128) — and query `hashes.<algorithm>`
- When the returned value matched in a different form (case, IP notation), say so in the result
- Never use full-text search for IOC lookup
- For multi-value lookups, map results back to inputs in the tool (by the normalized value)

### What one query returns

`indicators`, `containers` and `stixCoreRelationships` nest under an observable and come back in one
query. Relationship ends resolve to a name for any type with
`... on BasicObject { id entity_type } ... on StixCoreObject { representative { main } }` (evidence: `ioc-ipv4`).

- `indicates` (indicator → malware) is **the indicator's relationship**; under the observable only `based-on` appears
- Sightings cannot be reached from the Indicator type. `stixSightingRelationships(filters: {key: ["fromId"],
  values: [ids…]})` fetches them for several indicators and observables at once (evidence:
  `sightings-of-indicator`, `sightings-of-observable`)
- A sighting carries `x_opencti_negative` (a false-positive sighting), `attribute_count` (how many times)
  and `first_seen` / `last_seen`. The 192.0.2.10 indicator returns two: a normal sighting (3 times) and a
  false positive (once) (evidence: `sightings-of-indicator`)
- Nested `containers` has no `after` (no paging). To walk every container, use the root
  `containers(filters: {key: ["objects"]})` (§4)

### Decay rewrites indicators

Evidence: `ioc-ipv4`.

| Field | Ingested | Returned |
|---|---|---|
| `valid_until` | 2027-12-31 | **2026-10-01T04:33:39Z** (recomputed) |
| `x_opencti_score` | 85 | **20** (original kept as `decay_base_score: 85`) |
| `revoked` | — | **true** |
| `decay_applied_rule.decay_lifetime` | — | 47 (days) |

The observable's `x_opencti_score` stays 85. **One value carries two scores: 85 on the observable, 20 on the indicator.**

→ **Design**: return revoked indicators rather than hiding them, alongside `revoked`, the current score,
`decay_base_score` and `valid_until`. Observable and indicator scores are reported separately. Whether
production enables decay is unknown, so the tool passes the values through without interpreting them.

### Confidence may be filled in

Both sightings ingested with no confidence came back with `confidence: 100` (evidence:
`sightings-of-indicator`), apparently the ingesting user's default. → `get_usage` states that
confidence is not necessarily the source's.

## 4. Permissions and markings (read-only user)

Created by `dev/seed/readonly_user.py`: a role with `KNOWLEDGE` only, markings TLP:CLEAR / GREEN / AMBER (RED withheld).

| Test | Result | Evidence |
|---|---|---|
| `about` and `me` | allowed; `capabilities` = `['KNOWLEDGE']`, `allowed_marking` = TLP:AMBER / GREEN / CLEAR. **Enough to build `server_status`** | `me-readonly` |
| TLP:RED `198.51.100.7` | **0, no error** for the read-only user; 1 for admin | `ioc-red-readonly`, `ioc-red-admin` |
| Containers holding FIXTURE-HERON | 5 for admin, 4 for read-only (only the RED report disappears, from the total too) | `containers-of-actor-admin`, `-readonly` |
| Administrative query, write | `FORBIDDEN_ACCESS` | `err-forbidden-read`, `err-forbidden-write` |

→ **Design**: **"not registered" and "not visible to this key" are indistinguishable.** `lookup_ioc`
words a miss as "nothing within what this key can see", and `server_status` shows what the key can see.

## 5. Threat search (`search_threats`)

| Method | Result | Evidence |
|---|---|---|
| Full-text `stixDomainObjects(search:)` | relevance-ordered; **the total is not a match count** (305 for `TA-FIXTURE-01`, 849 for `IGNORE ALL PREVIOUS`). Aliases match but ranking wobbles (`Fancy Bear` puts APT28 second; `Sofacy` leaves it out of the top five) | `search-fulltext-*` |
| Exact (`name`, `aliases`, `x_opencti_aliases` under `or`) | case-insensitive. `apt28` → APT28 alone. **`Sofacy` → APT28 and CORESHELL** (one alias on several objects). `CVE-2099-0001` → the vulnerability | `search-exact-*` |
| ATT&CK id (`x_mitre_id` `eq`) | `t1566` → `[T1566] Phishing`. **A group id (`G0007`) returns 0** — the field serves attack patterns only | `search-mitre-id-*` |

→ **Design**: try exact match first and fall back to capped full-text search. **Expect several exact
matches.** Never present the full-text total as a match count. Document that ATT&CK-id lookup covers attack patterns only.

## 6. Relationships, detail, page size

| Test | Result | Evidence |
|---|---|---|
| APT28 → `uses` → Attack-Pattern | 93 rows, about 78 KB: per-relationship descriptions **32%** (up to 679 characters), the repeated `from` / `to` **34%** | `related-apt28-uses-attack-pattern` |
| APT28 detail | about 13 KB, of which 28 external references are about 9 KB | `entity-apt28` |
| **Page ceiling** | **5,000.** `first: 5000` returns 5,000 with `hasNextPage: true`; **`first: 5001` and above also return 5,000 — truncated — with `hasNextPage: false`** (total 24,918) | `page-first-5000`, `page-first-5001` |
| `first: 0` | no rows, total only | `page-first-0` |

The verifier also reports nested `containers(first: 2)` answering `hasNextPage: true` with a total of 2.
**`hasNextPage` cannot be used to detect a short answer.**

→ **Design**:
- Keep `first` within 1–5000 (the tool's own caps sit below that)
- Detect a short answer by comparing the total with the rows received, not by `hasNextPage`
- `get_related` omits relationship descriptions by default and adds them on request; the starting object is returned once, not repeated on every row

## 7. Attached files (`get_report_file`)

Evidence: `files-green-readonly`, `files-downloads`.

| Test | Result |
|---|---|
| Listing | `report(id) { importFiles { … id name size metaData { mimetype } } }`; ids are `import/Report/<report id>/<file name>` |
| Download as the read-only user | `GET /storage/get/<url-encoded id>`; a PDF (618 bytes, `application/pdf`) and a text file answer 200 |
| Uploaded as `../escape attempt.txt` | stored and returned as `escape attempt.txt` (the path part is dropped, the space kept) |
| Naming the attachment of an invisible RED report | **HTTP 503**, `{"status":"error","error":"File not found or restricted"}` |
| A file that does not exist | the same 503 and body |
| A wrong token | **HTTP 403**, plain-text `Forbidden` |

→ **Design**:
- `KNOWLEDGE` alone was enough (the issued production key still needs checking)
- 503 with that body maps to "absent or not visible", 403 to an authentication failure, both distinct from a connection failure
- File names are third-party strings; the tool builds the saved name itself rather than relying on OpenCTI's handling

## 8. Recent items (`list_recent`)

| Field | Meaning | Filtered to ≥ 2026-11-01 | Evidence |
|---|---|---|---|
| `created_at` | when OpenCTI ingested it | 4 (ingested today) | `recent-created_at` |
| `created` | when the source created it | 0 (dated 1 October) | `recent-created` |
| `published` | a report's publication date | 0 | `recent-published` |

The verifier reports that filtering indicators by `published` (a field they lack) returns zero rows without an error.

→ **Design**: let the caller choose between "new to this instance" and "newly published"; default to
`created_at`. Validate which date axes each type supports.

## 9. Instruction-shaped text

The malware whose description reads `IGNORE ALL PREVIOUS INSTRUCTIONS…` ranks first in full-text search
like any other text (evidence: `search-fulltext-ignore-all-previous`); OpenCTI does not alter content.
→ As the RFP says, `get_usage` states that such text is data. The same holds for other third-party
strings such as file names.

## 10. Not yet measured

- Response sizes at real-data scale (only fixtures and MITRE were measured)
- The issued production key's permissions, visible markings and decay rules (taken in the Phase 3 production check)
- The refusal of a root field repeated three times (verifier's report only)

## 11. Corrections to the first edition

The independent verification (2026-11-06) was confirmed by recapturing, then corrected here.

| First edition | Correction |
|---|---|
| "HTTP is always 200" | `__schema` answers 500; storage answers 403 / 503 |
| "Page ceiling unmeasured for lack of data" (1,379 returned) | The ceiling is 5,000; beyond it rows are cut silently and `hasNextPage` turns false. 1,379 was the total at the time |
| Cited `readonly-192.0.2.10.json` as evidence of RED exclusion | That value is in no RED report, so it proved nothing; replaced by `containers-of-actor-*` |
| "`Sofacy` matches APT28 uniquely" | APT28 and CORESHELL |
| "Relationship replies are mostly descriptions" | descriptions 32%, repeated `from` / `to` 34% |
| intrusion sets "about 180" | 190 |
| Captures carried no query, variables or user, and some predated the query file | All recaptured by `dev/capture.py` with provenance in the same file |
| The error table lacked `DATABASE_ERROR`, `UNSUPPORTED_ERROR`, `GRAPHQL_*` | Added |
