# opencti-lookup

Read-only threat-intelligence lookups against your OpenCTI instance, as a CLI
and a local MCP server — so that an agent doing threat analysis can consult
what your instance holds alongside the external lookups (otx-lookup,
gti-lookup, cve-lookup and the rest of the cybersecurity series).

Given an IP, domain, URL, email address or file hash, it tells you which
observables and indicators the instance holds, whether they were sighted (and
whether a sighting was a false positive), which reports mention them, and what
they point at. Given a name, alias or ATT&CK id, it finds the threat actor,
malware, technique or report and walks its relationships.

It queries an instance you are entitled to read, with a key issued to you, so
no packet reaches the target under investigation. It never writes.

[日本語版 README](README.ja.md)

## Status

Phase 1 of the [RFP](docs/en/opencti-lookup-rfp.md) is implemented and tested
against OpenCTI 6.7.4. Not yet released.

## Requirements

- An OpenCTI instance — **verified against 6.7.4**; another version may reject
  queries (`server_status` says which version the instance runs) — its URL,
  and an API key.
- Go 1.25+ to build.

## Installation

```bash
make build   # → dist/opencti-lookup
```

## Configuration

Copy [config.example.toml](config.example.toml) to
`~/.config/opencti-lookup/config.toml`, set `url` and `token`, and
`chmod 600` it. The file is looked for in `$XDG_CONFIG_HOME/opencti-lookup/`,
`~/.config/opencti-lookup/` and, on macOS, `~/Library/Application Support/opencti-lookup/`,
in that order; `--config <path>` names one explicitly.

| Setting | Environment | Meaning |
|---|---|---|
| `[opencti] url` | `OPENCTI_LOOKUP_URL` | Base URL of the instance (required) |
| `[opencti] token` | `OPENCTI_LOOKUP_TOKEN` | Your API key (required) |
| `[opencti] ca_file` | `OPENCTI_LOOKUP_CA_FILE` | PEM certificate to trust (self-signed or internal CA) |
| `[opencti] insecure_skip_verify` | `OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY` | Skip TLS verification (see below) |
| `[opencti] timeout_seconds` | `OPENCTI_LOOKUP_TIMEOUT_SECONDS` | Per-request timeout, 1-600 (default 30) |
| `[query] default_limit` | — | Rows a list returns by default (25) |
| `[query] max_limit` | — | Most rows one call may ask for, 1-5000 (500) |

Unknown keys, empty values and out-of-range numbers are errors. A config file
readable by others draws a warning.

**Certificates.** For a self-signed or internal-CA certificate, point
`ca_file` at it first. Only when that cannot work (a hostname mismatch, an
expired certificate) set `insecure_skip_verify = true` — anyone on the network
path can then read your token. The tool warns on every start, and
`status` reports it.

**Plain http** is accepted, with the same kind of warning: the token travels
unencrypted on every request.

## Commands

```bash
opencti-lookup ioc 192.0.2.10 bad.example.com 491fc027…   # up to 50 values
opencti-lookup search "Fancy Bear"                         # exact name/alias/ATT&CK id, then full text
opencti-lookup search T1566 --type attack-pattern
opencti-lookup entity <id>
opencti-lookup related <id> --relationship uses --target-type Attack-Pattern
opencti-lookup reports <id>
opencti-lookup status
```

`--json` prints JSON; flags may come before or after the arguments. Lists
print a `--cursor` line to continue.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Answered — "not found" and an empty list are answers |
| 1 | The instance could not be asked, or not fully (`INCONCLUSIVE` in the output) |
| 2 | Invalid input, configuration, a refused key, a missing permission |

## Reading the answers

- **Empty means "nothing within what this key can see".** OpenCTI answers
  "not registered" and "not visible to this key" identically: an object
  marked TLP:RED is absent for a key without TLP:RED. `status` lists the
  markings your key can see.
- **No verdict is computed.** Scores, confidence and markings are the
  instance's own. `confidence` may be the ingesting user's default rather than
  the source's.
- **Indicators decay.** OpenCTI lowers an indicator's score over time, may
  move its `valid_until`, and revokes it when it expires. Revoked indicators
  are shown, with the current score beside the score they started from.
- **A value may be stored in another form.** An IPv6 address stored expanded,
  a domain in upper case: these are found and marked `equivalent`.
- **Text is third-party data.** Names, descriptions, patterns and file names
  were written by whoever fed the instance; the CLI makes control characters
  visible before printing them.

## MCP server

```json
{
  "mcpServers": {
    "opencti-lookup": { "command": "/path/to/opencti-lookup", "args": ["mcp"] }
  }
}
```

Add `"--config", "/path/to/config.toml"` to `args` to give one client its own
configuration (for example a key with a narrower view).

Tools: `lookup_ioc`, `search_threats`, `get_entity`, `get_related`,
`get_reports`, `server_status`, `get_usage`. Call `get_usage` first: it is the
full reference and the error-recovery table. Results are returned whole up to
128 KB, with long lists capped by `limit` and totals always reported; spilling
a large result to a file is the client's job (gem-agent, lagent and Claude
Code all do it).

## Development

The [Phase 0 record](docs/en/opencti-lookup-phase0.md) holds what OpenCTI 6.7.4
was measured to do. To run the live tests:

```bash
make dev-up                                  # OpenCTI 6.7.4 on Podman (about 5 GB of the VM)
dev/seed/push.sh                             # fictional fixtures
python3 -I dev/seed/readonly_user.py         # the read-only test user
python3 -I dev/seed/attach.py                # report attachments
make e2e                                     # live tests (tokens read from dev/.env)
make dev-down
```

MinIO's published images are gone; `make dev-minio` builds the release the
6.7.4 stack pinned from its official source.

## Documentation

- [RFP](docs/en/opencti-lookup-rfp.md) — the design record
- [Phase 0 measurements](docs/en/opencti-lookup-phase0.md)
- [AGENTS.md](AGENTS.md) — for contributors and coding agents

## License

MIT. OpenCTI is a product of Filigran; this tool is not affiliated with or
endorsed by Filigran.
