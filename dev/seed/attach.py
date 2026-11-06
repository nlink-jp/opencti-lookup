"""Attach the fixture files to the fixture reports in the development OpenCTI.

Reproduces by script what Phase 0 first did by hand, so the attachment
measurements can be rerun from a fresh stack:

  GREEN "Operation Fixture Tide" report:
    fixture-report.pdf      a minimal but valid PDF generated here
    fixture-attachment.txt  a small text file
    ../escape attempt.txt   a hostile-looking name (file names are third-party
                            strings; how OpenCTI stores and returns them
                            decides how get_report_file must build paths)
  RED "restricted" report:
    red-attachment.txt      for the "invisible file" case

Run after dev/seed/push.sh has finished ingesting. Re-running re-uploads
under the same names. Uses the dev admin token from dev/.env.

Usage: python3 -I dev/seed/attach.py
"""

import json
import os
import sys
import urllib.request
import uuid

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL = "http://127.0.0.1:8080/graphql"


def admin_token():
    with open(os.path.join(DEV, ".env")) as f:
        for line in f:
            if line.startswith("OPENCTI_ADMIN_TOKEN="):
                return line.rstrip("\n").split("=", 1)[1]
    sys.exit("OPENCTI_ADMIN_TOKEN missing from dev/.env")


TOKEN = admin_token()


def gql(query, variables=None):
    req = urllib.request.Request(
        URL,
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        reply = json.load(resp)
    if reply.get("errors"):
        sys.exit("GraphQL error: " + "; ".join(e["message"] for e in reply["errors"]))
    return reply["data"]


def upload(report_id, name, content, mimetype):
    """GraphQL multipart upload (graphql-multipart-request-spec)."""
    operations = json.dumps(
        {
            "query": "mutation($id: ID!, $file: Upload!) { stixDomainObjectEdit(id: $id) { importPush(file: $file) { id name } } }",
            "variables": {"id": report_id, "file": None},
        }
    )
    boundary = uuid.uuid4().hex
    parts = []
    for field, value in (("operations", operations), ("map", '{"0":["variables.file"]}')):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"\r\n\r\n{value}\r\n'.encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="0"; filename="{name}"\r\n'
        f"Content-Type: {mimetype}\r\n\r\n".encode()
        + content
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        URL,
        data=b"".join(parts),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "apollo-require-preflight": "true",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        reply = json.load(resp)
    if reply.get("errors"):
        return "ERROR " + "; ".join(e["message"] for e in reply["errors"])
    return reply["data"]["stixDomainObjectEdit"]["importPush"]["id"]


def minimal_pdf(text):
    """A one-page PDF with one line of text, with a correct xref table."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


def report_id(fragment):
    data = gql('{ reports(first: 10, search: "Fixture") { edges { node { id name } } } }')
    ids = [e["node"]["id"] for e in data["reports"]["edges"] if fragment in e["node"]["name"]]
    if len(ids) != 1:
        sys.exit(f"expected one report matching {fragment!r}, found {len(ids)}")
    return ids[0]


green = report_id("Operation Fixture Tide (GREEN)")
red = report_id("restricted (RED)")

for rid, name, content, mime in [
    (green, "fixture-report.pdf", minimal_pdf("Fixture report full text for opencti-lookup"), "application/pdf"),
    (green, "fixture-attachment.txt", b"Fixture attachment for opencti-lookup.\nFull text of the fictional report would live here.\n", "text/plain"),
    (green, "../escape attempt.txt", b"A file whose name tries to leave its directory.\n", "text/plain"),
    (red, "red-attachment.txt", b"RED-only attachment.\n", "text/plain"),
]:
    print(f"{name!r:28} -> {upload(rid, name, content, mime)}")
