#!/usr/bin/env bash
# Push dev/seed/bundle.json into the development OpenCTI.
#
# Uses stixBundlePush under the import-file-stix connector's id, so the bundle
# goes straight onto the worker queue (no file upload, no workbench). The
# worker ingests it asynchronously; the call returning true only means queued.
# Re-pushing is safe: ids are deterministic, so objects are upserted.
set -euo pipefail

dev="$(cd "$(dirname "$0")/.." && pwd)"
connector_id="$(sed -n 's/^CONNECTOR_IMPORT_FILE_STIX_ID=//p' "$dev/.env")"

variables="$(python3 -I -c '
import json, sys
print(json.dumps({"connectorId": sys.argv[1], "bundle": open(sys.argv[2]).read()}))
' "$connector_id" "$dev/seed/bundle.json")"

"$dev/gql.sh" "$dev/queries/seed-push.graphql" "$variables"
