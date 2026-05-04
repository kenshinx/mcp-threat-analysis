#!/usr/bin/env bash
# Serve the prototype at http://localhost:7000/prototype/
# In a second terminal: mta-api --port 8080  (then the action buttons can hit /findings/.../confirm)
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -m http.server 7137
