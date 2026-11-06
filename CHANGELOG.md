# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- A local MCP server (`opencti-lookup mcp`) with the six tools and `get_usage`.
- A development OpenCTI 6.7.4 stack on Podman (`make dev-up`) with fictional
  fixtures, and live tests against it (`make e2e`).
