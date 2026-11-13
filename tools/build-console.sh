#!/usr/bin/env bash
# build-console.sh — construit la console web (webui/.output), lue ensuite par build-ddibuntu.sh.
# Node.js 22 local si disponible ; sinon Docker (image node:22). Les dépendances sont celles de package-lock.json.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]; then
  cd "$ROOT/webui" && npm ci && npx --no-install nuxt build
elif command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$ROOT/webui:/w" -w /w node:22-bookworm sh -c 'npm ci && npx nuxt build'
else
  echo "ERREUR : Node.js 22 ou Docker est nécessaire pour construire la console web" >&2; exit 1
fi
test -f "$ROOT/webui/.output/server/index.mjs" && echo "OK : console construite (webui/.output)"
