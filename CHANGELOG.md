# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] — 2026-11-07

### Fixed

- A refused TLS certificate is explained by what is wrong with it. ca_file is
  offered only when the issuer is the whole problem; a certificate that names
  its host only in the legacy Common Name (no subjectAltName), names another
  host, has expired, is not yet valid (check the clock first) or is not issued
  for server use is reported as such, with what to ask the instance's operator
  for — ca_file cannot fix those. The presented certificate is examined before
  the error's type is trusted (on macOS the system verifier calls all of these
  "unknown authority" while no ca_file is set), so the real cause is named on
  the first attempt.

## [0.1.0] — 2026-11-06

### Added

- `ioc` / `lookup_ioc`: what the instance holds about IPv4/IPv6 addresses and
  CIDRs, domains, URLs, email addresses and MD5/SHA-1/SHA-256/SHA-512 hashes,
  up to 50 per call. Looked up through observables (every form a value may be
  stored in) and through indicators whose STIX pattern compares against the
  value exactly, so indicators with no observable are found. Sightings,
  false-positive sightings, containers and relationships with their totals;
  decayed and revoked indicators returned with their current and base scores.
  A miss after a cut candidate list is `inconclusive`, never "not found".
- `search` / `search_threats`: exact name, alias or ATT&CK technique id first,
  then ranked full-text search.
- `entity` / `get_entity`, `related` / `get_related`, `reports` /
  `get_reports`: one object in full, its relationships and its containers,
  paged with a cursor that counts what was handed out.
- `status` / `server_status`: the instance's version against the verified
  OpenCTI 6.7.4, what the key can do and see, how the connection is secured,
  and the config file read.
- Strict configuration (nlink-jp/toml): `--config`, search order including
  `~/Library/Application Support`, `ca_file`, `insecure_skip_verify`, plain
  http accepted with a warning, a warning for a config file that is not 0600.
- `recent` / `list_recent`: reports or indicators by ingestion, source or
  publication date within 1-365 days, refusing a date a type lacks.
- `file` / `get_report_file`: save one attachment into a work directory
  (`work_dir` argument or `_meta` `jp.nlink/work_dir`, judged by
  nlink-jp/pathguard, organization ADR-021/022), under a rebuilt name, through
  `os.Root`; `get_entity` lists an object's attachments.
- A local MCP server (`opencti-lookup mcp`) with the eight tools and `get_usage`.
- A development OpenCTI 6.7.4 stack on Podman (`make dev-up`) with fictional
  fixtures, and live tests against it (`make e2e`).
