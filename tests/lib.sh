#!/usr/bin/env bash
# lib.sh — mini-framework de test, sourcé par chaque batterie. Un journal par processus.
# shellcheck disable=SC2034
T_PASS=0; T_FAIL=0
T_NAME="${T_NAME:-$(basename "${0:-batterie}" .sh)}"
T_TMP="$(mktemp -d)"
trap 'rm -rf "$T_TMP"' EXIT

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
RFS="$ROOT/src/rootfs"
DIST="$ROOT/dist/build-ddibuntu.sh"
ART="$ROOT/tests/artifacts"
mkdir -p "$ART"
export LC_ALL=C.UTF-8

ok() { T_PASS=$((T_PASS + 1)); printf '  ok     %s\n' "$1"; }
ko() { T_FAIL=$((T_FAIL + 1)); printf '  ECHEC  %s\n' "$1"; if [ -n "${2:-}" ]; then printf '         %s\n' "$2"; fi; }

# note "texte" : limite constatée, ni réussite ni échec ; reprise dans le compte rendu
note() { printf '  NOTE   %s\n' "$1"; }

# check "nom" commande... : la commande doit réussir
check() {
  local n="$1"; shift
  if "$@" >"$T_TMP/out" 2>&1; then ok "$n"; else ko "$n" "$(head -c 500 "$T_TMP/out" | tr '\n' ' ')"; fi
}
# check_fail "nom" commande... : la commande doit échouer (code non nul)
check_fail() {
  local n="$1"; shift
  if "$@" >"$T_TMP/out" 2>&1; then ko "$n" "la commande aurait dû échouer : $(head -c 300 "$T_TMP/out" | tr '\n' ' ')"; else ok "$n"; fi
}
# expect_eq "nom" attendu obtenu
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else ko "$1" "attendu [$2], obtenu [$3]"; fi; }
# expect_grep "nom" motif fichier
expect_grep() { if grep -qE -- "$2" "$3" 2>/dev/null; then ok "$1"; else ko "$1" "motif absent : $2 (dans $3)"; fi; }
expect_nogrep() { if grep -qE -- "$2" "$3" 2>/dev/null; then ko "$1" "motif présent : $2 (dans $3)"; else ok "$1"; fi; }

finish() {
  printf 'RESULT %s pass=%d fail=%d\n' "$T_NAME" "$T_PASS" "$T_FAIL"
  [ "$T_FAIL" -eq 0 ]
}

# Sourcer les fonctions du script de construction sans lancer main
load_build_functions() {
  # shellcheck source=/dev/null
  DDI_BUILD_SOURCE_ONLY=1 DDI_SELF="$DIST" . "$DIST"
  set +e   # le script source active set -e ; les batteries gèrent elles-mêmes les échecs
}
