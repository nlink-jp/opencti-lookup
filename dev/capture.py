"""Re-run every Phase 0 measurement and save each reply with its provenance.

Each case writes dev/captures/<name>.json:

  {"query": <query file or inline label>, "variables": {...}, "as": "admin"|"readonly"|...,
   "http_status": 200, "reply": {...}, "trimmed": "<what was removed, if anything>"}

so a capture can be re-derived from the repository alone (the first round of
captures had neither the variables nor the user, and some predated the query
file they sat next to). Ids that differ per stack (report, actor, indicator)
are looked up at run time.

Trimming, always declared in "trimmed":
  - pages of 5,000 rows keep pageInfo and the row count, not the rows
  - errors[].extensions.cause is removed (it carries the Elasticsearch query
    body and internal group ids)

Run against the dev stack after dev/seed/push.sh, readonly_user.py and
attach.py. Usage: python3 -I dev/capture.py [CASE_NAME ...]
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEV = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(DEV, "captures")
BASE = "http://127.0.0.1:8080"


def env():
    values = {}
    with open(os.path.join(DEV, ".env")) as f:
        for line in f:
            key, _, value = line.rstrip("\n").partition("=")
            values[key] = value
    return values


ENV = env()
TOKENS = {
    "admin": ENV["OPENCTI_ADMIN_TOKEN"],
    "readonly": ENV["OPENCTI_READONLY_TOKEN"],
    "bad-token": "00000000-0000-4000-8000-000000000000",
    "no-token": None,
}


def post(query, variables, as_user):
    headers = {"Content-Type": "application/json"}
    if TOKENS[as_user]:
        headers["Authorization"] = f"Bearer {TOKENS[as_user]}"
    req = urllib.request.Request(
        BASE + "/graphql",
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    try:
        return status, json.loads(body)
    except ValueError:
        return status, {"non_json_body": body.decode(errors="replace")[:500]}


def get_file(file_id, as_user):
    headers = {}
    if TOKENS[as_user]:
        headers["Authorization"] = f"Bearer {TOKENS[as_user]}"
    url = f"{BASE}/storage/get/{urllib.parse.quote(file_id, safe='')}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status, body, ctype = resp.status, resp.read(), resp.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        status, body, ctype = e.code, e.read(), e.headers.get("Content-Type")
    return {
        "http_status": status,
        "content_type": ctype,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "head": body[:80].decode(errors="replace"),
    }


def strip_cause(reply):
    removed = False
    for err in reply.get("errors", []) or []:
        ext = err.get("extensions") or {}
        if "cause" in ext:
            del ext["cause"]
            removed = True
    return removed


def query_text(ref):
    return open(os.path.join(DEV, "queries", ref)).read() if ref.endswith(".graphql") else ref


def run_query(name, ref, variables, as_user, trim_rows=False):
    status, reply = post(query_text(ref), variables, as_user)
    trimmed = []
    if strip_cause(reply):
        trimmed.append("errors[].extensions.cause removed")
    if trim_rows:
        for value in (reply.get("data") or {}).values():
            if isinstance(value, dict) and "edges" in value:
                value["edge_count"] = len(value.pop("edges"))
                trimmed.append("edges replaced by edge_count")
    save(name, {"query": ref if ref.endswith(".graphql") else "inline: " + ref, "variables": variables,
                "as": as_user, "http_status": status, "reply": reply, "trimmed": "; ".join(trimmed) or None})
    return reply


def save(name, record):
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump(record, f, indent=1, ensure_ascii=False, sort_keys=True)
        f.write("\n")


def eq(key, *values):
    return {"mode": "and", "filterGroups": [], "filters": [{"key": [key], "values": list(values), "operator": "eq"}]}


def first_id(reply, root):
    edges = reply["data"][root]["edges"]
    return edges[0]["node"]["id"] if edges else None


def ids():
    def one(q, root, filters):
        _, r = post(q, {"filters": filters}, "admin")
        return first_id(r, root)

    return {
        "actor": one("query($filters: FilterGroup) { intrusionSets(first: 1, filters: $filters) { edges { node { id } } } }",
                     "intrusionSets", eq("name", "FIXTURE-HERON")),
        "apt28": one("query($filters: FilterGroup) { intrusionSets(first: 1, filters: $filters) { edges { node { id } } } }",
                     "intrusionSets", eq("name", "APT28")),
        "ip_ind": one("query($filters: FilterGroup) { indicators(first: 1, filters: $filters) { edges { node { id } } } }",
                      "indicators", eq("name", "192.0.2.10")),
        "dom_obs": one("query($filters: FilterGroup) { stixCyberObservables(first: 1, filters: $filters) { edges { node { id } } } }",
                       "stixCyberObservables", eq("value", "bad.example.com")),
        "green_report": one("query($filters: FilterGroup) { reports(first: 1, filters: $filters) { edges { node { id } } } }",
                            "reports", eq("name", "Fixture report: Operation Fixture Tide (GREEN)")),
        "red_report": one("query($filters: FilterGroup) { reports(first: 1, filters: $filters) { edges { node { id } } } }",
                          "reports", eq("name", "Fixture report: restricted (RED)")),
    }


SHA256 = "491fc027d8e22a569e67a40c16b98c93a4586c5421b18894cdd5c40201277d20"
SAMPLE2 = b"opencti-lookup fixture sample 2"


def cases(i):
    obs = "lookup-observable.graphql"
    ind = "lookup-indicator.graphql"
    c = []

    def q(name, ref, variables, as_user="admin", trim_rows=False):
        c.append((name, lambda: run_query(name, ref, variables, as_user, trim_rows)))

    # lookup_ioc through observables
    for name, key, value in [
        ("ioc-ipv4", "value", "192.0.2.10"),
        ("ioc-ipv4-prefix", "value", "192.0.2.1"),
        ("ioc-domain", "value", "bad.example.com"),
        ("ioc-domain-upper", "value", "BAD.EXAMPLE.COM"),
        ("ioc-url", "value", "http://bad.example.com/payload.bin"),
        ("ioc-url-upper-path", "value", "http://bad.example.com/PAYLOAD.BIN"),
        ("ioc-email", "value", "phisher@example.net"),
        ("ioc-ipv6", "value", "2001:db8::10"),
        ("ioc-ipv6-query-expanded", "value", "2001:0db8:0000:0000:0000:0000:0000:0010"),
        ("ioc-ipv6-stored-expanded-query-canonical", "value", "2001:db8::20"),
        ("ioc-ipv6-stored-expanded-query-as-stored", "value", "2001:0DB8:0000:0000:0000:0000:0000:0020"),
        ("ioc-sha256-by-value", "value", SHA256),
        ("ioc-sha256", "hashes.SHA-256", SHA256),
        ("ioc-sha256-upper", "hashes.SHA-256", SHA256.upper()),
        ("ioc-md5", "hashes.MD5", hashlib.md5(SAMPLE2).hexdigest()),
        ("ioc-sha1", "hashes.SHA-1", hashlib.sha1(SAMPLE2).hexdigest()),
        ("ioc-sha512", "hashes.SHA-512", hashlib.sha512(SAMPLE2).hexdigest()),
        ("ioc-notfound", "value", "192.0.2.200"),
        ("ioc-orphan-via-observables", "value", "orphan.example.org"),
    ]:
        q(name, obs, {"first": 10, "filters": eq(key, value)})
    q("ioc-search-prefix", obs, {"first": 10, "search": "192.0.2.1"})
    q("ioc-red-readonly", obs, {"first": 10, "filters": eq("value", "198.51.100.7")}, "readonly")
    q("ioc-red-admin", obs, {"first": 10, "filters": eq("value", "198.51.100.7")})

    # lookup_ioc through indicators (the path an observable-less indicator needs)
    q("indicator-by-name", ind, {"first": 10, "filters": eq("name", "orphan.example.org")})
    q("indicator-by-pattern-contains", ind, {"first": 10, "filters": {"mode": "and", "filterGroups": [], "filters": [
        {"key": ["pattern"], "values": ["orphan.example.org"], "operator": "contains"}]}})
    q("indicator-by-pattern-contains-partial", ind, {"first": 10, "filters": {"mode": "and", "filterGroups": [], "filters": [
        {"key": ["pattern"], "values": ["orphan.example"], "operator": "contains"}]}})

    # sightings
    q("sightings-of-indicator", "sightings.graphql", {"first": 10, "filters": eq("fromId", i["ip_ind"])})
    q("sightings-of-observable", "sightings.graphql", {"first": 10, "filters": eq("fromId", i["dom_obs"])})

    # containers (get_reports): RED exclusion evidence for a key without TLP:RED
    q("containers-of-actor-admin", "containers-of.graphql", {"first": 50, "filters": eq("objects", i["actor"])})
    q("containers-of-actor-readonly", "containers-of.graphql", {"first": 50, "filters": eq("objects", i["actor"])}, "readonly")

    # get_related / get_entity
    q("related-apt28-uses-attack-pattern", "related.graphql",
      {"id": [i["apt28"]], "types": ["uses"], "toTypes": ["Attack-Pattern"], "first": 500})
    q("related-nonexistent-id", "related.graphql", {"id": ["00000000-0000-4000-8000-000000000000"], "first": 10})
    q("related-unknown-totype", "related.graphql", {"id": [i["apt28"]], "toTypes": ["No-Such-Type"], "first": 10})
    q("entity-apt28", "entity.graphql", {"id": i["apt28"]})

    # search_threats
    for s in ["TA-FIXTURE-01", "Fancy Bear", "Sofacy", "IGNORE ALL PREVIOUS"]:
        q("search-fulltext-" + s.lower().replace(" ", "-"), "search.graphql", {"search": s, "first": 5})
    name_or_alias = lambda s: {"mode": "or", "filterGroups": [], "filters": [
        {"key": [k], "values": [s], "operator": "eq"} for k in ("name", "aliases", "x_opencti_aliases")]}
    for s in ["Sofacy", "apt28", "CVE-2099-0001"]:
        q("search-exact-" + s.lower(), "search-exact.graphql", {"first": 10, "filters": name_or_alias(s)})
    for s in ["t1566", "G0007"]:
        q("search-mitre-id-" + s.lower(), "search-exact.graphql", {"first": 10, "filters": eq("x_mitre_id", s)})

    # paging
    page = "query($first: Int) { stixCoreRelationships(first: $first) { pageInfo { globalCount hasNextPage } edges { node { id } } } }"
    for n in (5000, 5001):
        q(f"page-first-{n}", page, {"first": n}, trim_rows=True)
    q("page-first-0", page, {"first": 0})

    # who am I
    q("me-admin", "me.graphql", {})
    q("me-readonly", "me.graphql", {}, "readonly")

    # errors
    about = "{ about { version } }"
    q("err-bad-token", about, {}, "bad-token")
    q("err-no-token", about, {}, "no-token")
    q("err-forbidden-read", "{ capabilities(first: 1) { edges { node { name } } } }", {}, "readonly")
    q("err-forbidden-write",
      "mutation { indicatorAdd(input: {name: \"probe-write\", pattern: \"[ipv4-addr:value = '192.0.2.251']\", pattern_type: \"stix\"}) { id } }",
      {}, "readonly")
    q("err-partial", "errors.graphql", {}, "readonly")
    q("err-negative-first", page, {"first": -1})
    q("err-introspection-schema", "{ __schema { queryType { name } } }", {})
    q("err-introspection-type", "{ __type(name: \"Indicator\") { name } }", {})
    q("err-unknown-filter-key", obs, {"first": 1, "filters": eq("no_such_key", "x")})
    q("err-parse", "{ about { version ", {})
    q("err-validation", "{ about { no_such_field } }", {})

    # report files
    q("files-green-readonly", "report-files.graphql", {"id": i["green_report"]}, "readonly")

    def downloads():
        base = f"import/Report/{i['green_report']}/"
        red = f"import/Report/{i['red_report']}/red-attachment.txt"
        record = {}
        for label, fid, who in [
            ("pdf", base + "fixture-report.pdf", "readonly"),
            ("txt", base + "fixture-attachment.txt", "readonly"),
            ("escaped-name", base + "escape attempt.txt", "readonly"),
            ("red-as-readonly", red, "readonly"),
            ("red-as-admin", red, "admin"),
            ("missing", base + "does-not-exist.txt", "readonly"),
            ("bad-token", base + "fixture-attachment.txt", "bad-token"),
        ]:
            record[label] = {"file_id": fid, "as": who, **get_file(fid, who)}
        save("files-downloads", {"query": "GET /storage/get/<url-encoded file id>", "variables": None,
                                 "as": "per entry", "http_status": None, "reply": record, "trimmed": "bodies reduced to size, sha256 and first 80 bytes"})

    c.append(("files-downloads", downloads))

    # list_recent
    for key in ("created_at", "created", "published"):
        q("recent-" + key, "recent.graphql", {"first": 3, "filters": {"mode": "and", "filterGroups": [], "filters": [
            {"key": [key], "values": ["2026-11-01T00:00:00.000Z"], "operator": "gte"}]}})
    return c


def main():
    os.makedirs(OUT, exist_ok=True)
    wanted = set(sys.argv[1:])
    all_cases = cases(ids())
    for name, fn in all_cases:
        if wanted and name not in wanted:
            continue
        fn()
        print("captured", name)


main()
