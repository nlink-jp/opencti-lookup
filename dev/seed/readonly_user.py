"""Create the read-only user the development stack tests run as.

Shape (Phase 0 default, until the production key's capabilities are known):
  role  "opencti-lookup read-only"  with only KNOWLEDGE ("Access knowledge")
  group "opencti-lookup read-only"  with that role, markings TLP:CLEAR,
                                    TLP:GREEN, TLP:AMBER (TLP:RED withheld on
                                    purpose, to measure marking filtering)
  user  "opencti-lookup-readonly"   in that group

Idempotent: an existing user is reused. The user's API token is written to
dev/.env as OPENCTI_READONLY_TOKEN and never printed.

Usage: python3 -I dev/seed/readonly_user.py
"""

import json
import os
import secrets
import sys
import urllib.request

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = os.path.join(DEV, ".env")
URL = "http://127.0.0.1:8080/graphql"
NAME = "opencti-lookup read-only"
USER_NAME = "opencti-lookup-readonly"
USER_EMAIL = "readonly@example.com"
MARKINGS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]


def read_env():
    values = {}
    with open(ENV) as f:
        for line in f:
            key, _, value = line.rstrip("\n").partition("=")
            values[key] = value
    return values


ADMIN = read_env()["OPENCTI_ADMIN_TOKEN"]


def gql(query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        URL,
        data=body,
        headers={"Authorization": f"Bearer {ADMIN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        reply = json.load(resp)
    if reply.get("errors"):
        sys.exit("GraphQL error: " + "; ".join(e["message"] for e in reply["errors"]))
    return reply["data"]


def find_user():
    data = gql(
        "query($s: String) { users(search: $s, first: 10) { edges { node { id name } } } }",
        {"s": USER_NAME},
    )
    for edge in data["users"]["edges"]:
        if edge["node"]["name"] == USER_NAME:
            return edge["node"]["id"]
    return None


def create():
    caps = gql("{ capabilities(first: 500) { edges { node { id name } } } }")
    knowledge = [e["node"]["id"] for e in caps["capabilities"]["edges"] if e["node"]["name"] == "KNOWLEDGE"]
    if len(knowledge) != 1:
        sys.exit(f"expected one KNOWLEDGE capability, found {len(knowledge)}")

    role = gql("mutation($i: RoleAddInput!) { roleAdd(input: $i) { id } }", {"i": {"name": NAME}})["roleAdd"]["id"]
    gql(
        "mutation($id: ID!, $i: InternalRelationshipAddInput!) { roleEdit(id: $id) { relationAdd(input: $i) { id } } }",
        {"id": role, "i": {"toId": knowledge[0], "relationship_type": "has-capability"}},
    )

    group = gql(
        "mutation($i: GroupAddInput!) { groupAdd(input: $i) { id } }",
        {"i": {"name": NAME, "group_confidence_level": {"max_confidence": 100, "overrides": []}}},
    )["groupAdd"]["id"]
    gql(
        "mutation($id: ID!, $i: InternalRelationshipAddInput!) { groupEdit(id: $id) { relationAdd(input: $i) { id } } }",
        {"id": group, "i": {"toId": role, "relationship_type": "has-role"}},
    )
    markings = gql("{ markingDefinitions(first: 100) { edges { node { id definition } } } }")
    by_name = {e["node"]["definition"]: e["node"]["id"] for e in markings["markingDefinitions"]["edges"]}
    for name in MARKINGS:
        gql(
            "mutation($id: ID!, $i: InternalRelationshipAddInput!) { groupEdit(id: $id) { relationAdd(input: $i) { id } } }",
            {"id": group, "i": {"toId": by_name[name], "relationship_type": "accesses-to"}},
        )

    user = gql(
        "mutation($i: UserAddInput!) { userAdd(input: $i) { id } }",
        {
            "i": {
                "name": USER_NAME,
                "user_email": USER_EMAIL,
                "password": secrets.token_hex(24),
                "groups": [group],
            }
        },
    )["userAdd"]["id"]
    return user


def main():
    user = find_user()
    created = user is None
    if created:
        user = create()
    token = gql("query($id: String!) { user(id: $id) { api_token } }", {"id": user})["user"]["api_token"]

    env = read_env()
    if env.get("OPENCTI_READONLY_TOKEN") != token:
        lines = [l for l in open(ENV).read().splitlines() if not l.startswith("OPENCTI_READONLY_TOKEN=")]
        lines.append(f"OPENCTI_READONLY_TOKEN={token}")
        with open(ENV, "w") as f:
            f.write("\n".join(lines) + "\n")
    print(("created" if created else "reused") + f" user {USER_NAME}; token stored in dev/.env")


main()
