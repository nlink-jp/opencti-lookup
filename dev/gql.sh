#!/usr/bin/env bash
# Send one GraphQL query to the development OpenCTI and print the JSON reply.
#
#   dev/gql.sh QUERY_FILE [VARIABLES_JSON]
#   OPENCTI_DEV_TOKEN=<uuid> dev/gql.sh ...   # run as another (e.g. read-only) user
#
# The token is read from dev/.env (or OPENCTI_DEV_TOKEN) and passed to curl
# through a header file descriptor, so it never appears in argv or output.
# Development stack only: the URL is fixed to 127.0.0.1.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
query_file="${1:?usage: dev/gql.sh QUERY_FILE [VARIABLES_JSON]}"
variables="${2:-}"
[[ -n "$variables" ]] || variables='{}'

token="${OPENCTI_DEV_TOKEN:-}"
if [[ -z "$token" ]]; then
  token="$(sed -n 's/^OPENCTI_ADMIN_TOKEN=//p' "$dir/.env")"
fi

body="$(python3 -I -c '
import json, sys
print(json.dumps({"query": open(sys.argv[1]).read(), "variables": json.loads(sys.argv[2])}))
' "$query_file" "$variables")"

curl -sS --max-time 60 \
  -H @<(printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$token") \
  --data-binary @- \
  http://127.0.0.1:8080/graphql <<<"$body"
echo
