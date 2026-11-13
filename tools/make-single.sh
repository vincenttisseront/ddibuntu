#!/usr/bin/env bash
# make-single.sh — assemble le fichier unique de publication dist/build-ddibuntu.sh (script racine + archive embarquée).
# Usage : tools/make-single.sh [DOSSIER_DE_SORTIE]    (défaut : ./dist)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
DIST="${1:-$ROOT/dist}"
VERSION="$(tr -d '\n' < "$SRC/VERSION")"
MARK='#__DDIBUNTU_PAYLOAD_BELOW__'
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$DIST"
# La charge utile est préparée par le script racine lui-même (mode dépôt) : fichier unique et dépôt lisent le même contenu.
"$ROOT/build-ddibuntu.sh" --stage "$STAGE" >/dev/null

OUT="$DIST/build-ddibuntu.sh"
# Seules la ligne DDI_VERSION et le commentaire d'en-tête portent le marqueur : une substitution globale
# détruirait le code qui remplace ce même marqueur dans le modèle user-data à l'exécution.
sed -e "s/^DDI_VERSION=\"@@VERSION@@\"\$/DDI_VERSION=\"$VERSION\"/" -e "2s/@@VERSION@@/$VERSION/" "$ROOT/build-ddibuntu.sh" > "$OUT"
if [[ "$(grep -c '^DDI_VERSION="'"$VERSION"'"$' "$OUT")" != 1 ]]; then echo "ERREUR : DDI_VERSION non renseigné" >&2; exit 1; fi
# Le marqueur ne doit jamais apparaître dans le script : l'alphabet base64 ne contient ni « # » ni « _ »
if grep -q -x -F -- "$MARK" "$OUT"; then echo "ERREUR : marqueur déjà présent dans le modèle" >&2; exit 1; fi
{
  printf '%s\n' "$MARK"
  ( cd "$STAGE" && tar --sort=name --mtime='@1700000000' --owner=0 --group=0 --numeric-owner -cf - . ) | gzip -9 -n | base64
} >> "$OUT"
chmod 0755 "$OUT"

n="$(grep -c -x -F -- "$MARK" "$OUT")"
[[ "$n" = 1 ]] || { echo "ERREUR : marqueur présent $n fois" >&2; exit 1; }
bash -n "$OUT"
echo "OK : $OUT ($(wc -c < "$OUT") octets, version $VERSION)"
