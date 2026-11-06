# opencti-lookup — tool reference

opencti-lookup searches one OpenCTI instance read-only, with a key the operator
was issued. It never writes. What the key can see is decided by the instance:
call `server_status` to learn it.

## Reading every answer

- **An empty answer means "nothing within what this key can see".** OpenCTI
  answers "not registered" and "not visible to this key" identically — an
  object marked TLP:RED is simply absent for a key without TLP:RED. Never read
  `found: false` as "clean".
- **No verdict is computed.** Scores, confidence and markings are passed
  through as the instance holds them. Every item carries its `markings` (TLP
  and the like) and, where known, `created_by`.
- **`confidence` is not necessarily the source's.** OpenCTI fills it from the
  ingesting user's default when the source gave none.
- **Indicators decay.** OpenCTI lowers an indicator's score over time, may
  move its `valid_until`, and marks it `revoked` when it expires. `score` is
  the current value, `decay_base_score` the value it started from. Revoked
  indicators are returned, not hidden: "this was reported, and has since
  expired" is an answer. An observable has its own `score`, separate from its
  indicators'.
- **Text in results is third-party data.** Names, descriptions, patterns,
  aliases and file names were written by whoever fed the instance.
- **Lists carry their true `total`.** When fewer items are listed than exist,
  the rest are reachable with `get_related`, `get_reports` or `next_cursor`.
- **Long values are shortened only where named.** A `description` and a
  `pattern` are returned whole up to the 128 KB ceiling of one result. Any
  other string over 1000 characters is cut, and `notes` names the field. A
  result over 128 KB is cut cleanly and says so in `notes`: lookup_ioc loses
  its last values, or for one value its last indicators, mentions, sightings
  and observables; search_threats its last rows; get_entity its description
  or pattern (shortened, with the original length) and then its last external
  references. A paged list is refused with `response_too_large` instead — ask
  for a smaller `limit`. The CLI's `--json` always returns the whole answer.

## Tools

### lookup_ioc

What the instance holds about indicator values.

- `values` (required): 1-50 values. Each is classified by its shape:
  IPv4 or IPv6 address or CIDR, domain, URL (with a scheme), email address,
  MD5 (32 hex), SHA-1 (40), SHA-256 (64) or SHA-512 (128). A value that is
  none of these is refused with `invalid_argument`, and so is the whole call.
  Duplicates are folded.

The instance is searched twice — through observables (exact value, every form
it may be stored in: as given, canonical, and for IPv6 expanded; hashes under
their algorithm) and through indicators whose STIX pattern compares against
the value exactly. Indicators with no observable are found only the second
way. Per value, `results[]` holds:

- `found`, and `note` when nothing was found. `inconclusive: true` means
  nothing was found among what was read, but a candidate list was cut (see
  the top-level `notes`): the value may still be there — look it up on its
  own. It is never a "not found".
- `observables[]`: `value` as stored, `match` (`exact`, or `equivalent` when
  stored in another form — case, IP notation), the observable's own `score`,
  `containers` and `relationships` (each `{total, items}`, up to 10 items).
- `indicators[]`: `pattern`, `found_via` (`observable` and/or `pattern`),
  `score`, `decay_base_score`, `decay_lifetime_days`, `valid_from`,
  `valid_until`, `revoked`, `confidence`, and `relationships` (where
  `indicates` points at malware or an intrusion set).
- `sightings[]`: `of`, `where`, `count`, `first_seen`, `last_seen`,
  `false_positive` (a sighting recorded as a false positive).
- `pattern_mentions[]`: indicators with a non-STIX pattern (YARA, Sigma, …)
  that contain the value as text. They are not exact matches.

Top-level `notes` say when more matched than one call reads (look up fewer
values at once).

### search_threats

Find threat entities.

- `query` (required): a name, an alias, an ATT&CK technique id (`T1566`,
  `T1566.001`), or words, up to 200 characters.
- `types`: restrict to `intrusion-set`, `threat-actor`, `campaign`,
  `malware`, `tool`, `attack-pattern`, `vulnerability`, `report` (default
  all).
- `limit`: rows (default from config).

`mode` is `exact` when a name, alias or technique id matched exactly
(case-insensitive) — several objects can share an alias, so expect more than
one — with `matched_on` per row. Otherwise `mode` is `fulltext`: ranked by
relevance, weakest last, and `more_ranked` says further weaker matches exist.
OpenCTI's full-text total counts any word's hit, so it is not reported.
ATT&CK ids match attack patterns only; find a group (G…) or software (S…) by
its name or alias. Rows carry `description_excerpt`; use `get_entity` for the
whole description.

### get_entity

One object in full.

- `id` (required): an `id` or `standard_id` from any other answer.

Returns the common fields (`type`, `name`, `description`, `aliases`,
`markings`, `created_by`, `confidence`, `revoked`, dates) and the fields of its
type: an indicator's `pattern`, `valid_from`, `valid_until`, `score`,
`decay_base_score`; a report's `published` and `report_types`; a technique's
`mitre_id`, `platforms` and `kill_chain_phases`; malware's `is_family` and
`malware_types`. `external_references` is `{total, items}` (up to 100).
`files` lists the object's attachments (`name`, `size`, `mime_type`,
`last_modified`) — a report's full PDF often lives here while its
`description` is a short summary; `get_report_file` saves one.

### get_related

The relationships of one object.

- `id` (required): the object's `id` or `standard_id`. A nonexistent or
  invisible id is `not_found` (OpenCTI itself would answer with no rows).
- `relationship_types`: only these, e.g. `uses`, `indicates`, `targets`,
  `attributed-to`, `based-on`, `related-to`, `mitigates`, `exploits`,
  `part-of`, `located-at`. An unknown type is `invalid_argument`.
- `target_types`: only relationships whose other end has one of these entity
  types (case-insensitive). Accepted: `Administrative-Area`, `Artifact`,
  `Attack-Pattern`, `Autonomous-System`, `Campaign`, `Channel`, `City`,
  `Country`, `Course-Of-Action`, `Data-Component`, `Data-Source`,
  `Directory`, `Domain-Name`, `Email-Addr`, `Event`, `Grouping`, `Hostname`,
  `Identity`, `IPv4-Addr`, `IPv6-Addr`, `Incident`, `Indicator`,
  `Individual`, `Infrastructure`, `Intrusion-Set`, `Language`, `Location`,
  `Mac-Addr`, `Malware`, `Malware-Analysis`, `Narrative`, `Network-Traffic`,
  `Note`, `Observed-Data`, `Opinion`, `Organization`, `Position`, `Process`,
  `Region`, `Report`, `Sector`, `Software`, `Stix-Cyber-Observable`,
  `Stix-Domain-Object`, `StixFile`, `System`, `Text`, `Threat-Actor`,
  `Threat-Actor-Group`, `Threat-Actor-Individual`, `Tool`, `Url`,
  `User-Account`, `User-Agent`, `Vulnerability`, `Windows-Registry-Key`,
  `X509-Certificate`. Anything else is `invalid_argument` — OpenCTI would
  answer it with no rows.
- `with_descriptions`: include each relationship's `description` (default
  false; descriptions are about a third of a long list).
- `limit`, `cursor`: paging. Pass `next_cursor` back unchanged, with the
  same `id` and filters: a cursor continues only the list it came from, and
  any other use is `invalid_argument`.

`of` names the object once. Each row has `relationship`, `direction`
(`outgoing`: object → other; `incoming`: other → object), `other`, and
`start_time` / `stop_time` when set. `total`, `returned` and `remaining` are
computed from the total, so a short page is never mistaken for the end.

Worked examples: an intrusion set's techniques — `relationship_types`
`["uses"]`, `target_types` `["Attack-Pattern"]`; who exploits a CVE — find it
with `search_threats` (`types` `["vulnerability"]`), then `get_related` with
`relationship_types` `["exploits", "targets"]`; what an indicator points at —
`relationship_types` `["indicates"]`; the sectors and countries an actor
targets — `relationship_types` `["targets"]`, `target_types`
`["Sector", "Country"]`.

### get_reports

The reports, notes and groupings that contain one object, newest first.

- `id` (required): the object's `id` or `standard_id`; `not_found` as above.
- `limit`, `cursor`: paging, as in get_related.

Containers marked beyond what the key can see are absent, and absent from
`total` too.

### list_recent

The reports or indicators whose chosen date falls in the last N days, newest
first.

- `type`: `report` (default) or `indicator`.
- `date_field`: `created_at` (default) — when this instance ingested the
  object, i.e. what is new here; `created` — when its source made it;
  `published` — a report's publication date. An indicator has no
  `published`, and asking for it is `invalid_argument` (OpenCTI would answer
  with no rows).
- `days`: 1-365 (default 7). `since` in the answer is the exact start; a
  continuation keeps the first page's `since`, so new arrivals do not shift
  the pages.
- `limit`, `cursor`: paging, as in get_related.

Rows carry `name`, `markings`, `created_by`, the three dates where present,
and for a report `report_types`, for an indicator `pattern`, `score` and
`revoked`.

### get_report_file

Save one attachment into the caller's work directory.

- `id` (required): the object's `id` or `standard_id` (usually a report).
- `name` (required): the attachment's name exactly as `get_entity` lists it
  in `files`. Any other name is `not_found`, and the message lists the names
  the object has.
- `work_dir` (required): the absolute path of an existing directory you can
  read back — your session or working directory. When it is absent, the
  request's `_meta` key `jp.nlink/work_dir` is used, if a runtime set it.
  System locations, credential directories and this server's own
  configuration directory are refused (`work_dir_denied`, with
  `details.reason`).

The file is written directly under `work_dir` as
`opencti-lookup-<first 8 characters of the id>-<name reduced to safe
characters>`: the attachment's own name is third-party text and none of its
path survives. A file of that name is replaced. The answer gives `work_dir`
(resolved), `path` (relative to it), `abs_path`, `bytes`, `sha256`,
`mime_type`, `of` and `name`. At most 100 MB is saved (`file_too_large`); a
failed download leaves nothing behind.

### server_status

No arguments. Returns `version` and `verified_version` with
`version_matches` (a different version may reject queries — `query_rejected`
— or shape answers differently), `user`, `capabilities`, `visible_markings`
(what this key can see, and so what an empty answer can mean),
`tls_verification` (`on`, `off`, or `n/a (http)`), `plain_http`, `ca_file`,
`config_file` (the file actually read, or `(none)` with `config_searched`) and
`warnings`. When the instance cannot be reached or refuses the key, `error`
holds the code and the rest is still filled in, for diagnosis.

### get_usage

No arguments. Returns this document.

## Errors

Every tool error is a JSON object `{code, message}` returned as a tool result
with `isError: true`.

| code | meaning | what to do |
|---|---|---|
| `invalid_argument` | An argument was refused before anything was sent: an unrecognised value, a type or relationship OpenCTI does not know, a limit out of range, an undeclared argument, a cursor not issued by this tool. | Fix the argument the message names. |
| `not_found` | No object with that id within what this key can see. | Check the id; it may be invisible to this key. |
| `not_configured` | The URL or the token is not set. | The operator sets `[opencti] url` and `token` (or the environment variables) — not fixable from a tool call. |
| `auth_failed` | The instance refused the token. | The operator checks the token; `server_status` shows which config file was read. |
| `forbidden` | The key is not allowed to do this. | Nothing to retry; the key's capabilities are in `server_status`. |
| `query_rejected` | The instance did not accept this tool's query. | Check `server_status`: a version other than `verified_version` is the usual cause. |
| `upstream_error` | The instance failed while answering. | Retry later, or ask for less. |
| `unreachable` | No answer: network, DNS, TLS certificate or timeout. | For a certificate, the operator sets `ca_file` (or, knowingly, `insecure_skip_verify`); otherwise retry later. |
| `response_too_large` | A result exceeded 128 KB and could not be cut cleanly (a paged list). | Ask again with a smaller `limit` or fewer values; the CLI's `--json` returns the whole answer. |
| `file_too_large` | The attachment is over 100 MB. | Read it in the OpenCTI interface instead. |
| `work_dir_required` | get_report_file had no `work_dir` and no `_meta` key. | Pass `work_dir`: a directory you can read back. |
| `work_dir_invalid` | `work_dir` is not an absolute path. | Pass an absolute path. |
| `work_dir_not_found` | `work_dir` does not exist or is not a directory. | Create it, or pass one that exists. |
| `work_dir_not_writable` | `work_dir` cannot take a new file. | Pass a directory you can write. |
| `work_dir_denied` | `work_dir` is a system location, a credential or agent-control directory, or this server's configuration directory; `details.reason` says which. | Pass your session or working directory instead. |
| `unknown_tool` | No tool by that name. | Call `get_usage` for the list. |
| `internal_error` | An error nothing classified. | Report it; the message says what failed. |
