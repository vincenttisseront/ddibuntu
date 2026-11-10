#!/usr/bin/env bash
# run-console-tests.sh [unit|e2e|all] — tests de la console web. unit : typage + tests sans base ; e2e : serveur construit + PostgreSQL.
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"   # absolu : on change de dossier juste après
cd "$(dirname "$SELF")/../webui"
case "${1:-unit}" in
  unit) npx tsc -p tsconfig.server-check.json; npx vitest run tests/unit-*.test.ts ;;
  e2e)  [ -f .output/server/index.mjs ] || { echo "console non construite : lancer tools/build-console.sh" >&2; exit 1; }
        for f in tests/e2e*.test.ts; do npx vitest run "$f"; done ;;   # un fichier à la fois : même base de données
  all)  "$SELF" unit; "$SELF" e2e ;;
  *) echo "usage : $0 [unit|e2e|all]" >&2; exit 2 ;;
esac
