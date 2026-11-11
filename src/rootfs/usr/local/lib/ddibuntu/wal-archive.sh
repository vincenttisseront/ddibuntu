#!/bin/bash
# wal-archive.sh — archive_command de PostgreSQL (exécuté par l'utilisateur postgres) : « wal-archive.sh %p %f ».
# Copie atomique et durable du segment WAL (ou du fichier d'historique) dans le dépôt de sauvegarde, compressé.
# Jamais d'écrasement : un fichier déjà archivé identique est un succès, un fichier différent est une erreur (PostgreSQL réessaie, rien n'est perdu).
# Sauvegardes désactivées : succès sans rien archiver (aucune accumulation de WAL) ; la réactivation prend une nouvelle sauvegarde complète.
set -u
ROOT="${DDI_ROOT:-}"; CONF="${DDI_BACKUP_CONF:-$ROOT/etc/ddibuntu/backup.conf}"
enabled=0; dir=/var/lib/ddibuntu/backup
if [ -f "$CONF" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^(ENABLED|DIR)=([A-Za-z0-9._/@:+-]*)$ ]] || continue
    case "${BASH_REMATCH[1]}" in ENABLED) enabled="${BASH_REMATCH[2]}" ;; DIR) dir="${BASH_REMATCH[2]}" ;; esac
  done < "$CONF"
fi
[ "$enabled" = 1 ] || exit 0
src="${1:-}"; name="${2:-}"
[[ "$name" =~ ^([0-9A-F]{24}(\.partial|\.[0-9A-F]{8}\.backup)?|[0-9A-F]{8}\.history)$ ]] || { echo "nom de fichier WAL invalide : $name" >&2; exit 1; }
[ -f "$src" ] || { echo "fichier source absent : $src" >&2; exit 1; }
[[ "$dir" = /* && "$dir" != *..* ]] || { echo "dépôt invalide : $dir" >&2; exit 1; }
wal="$ROOT$dir/wal"; dest="$wal/$name.gz"
mkdir -p -- "$wal" || exit 1
if [ -e "$dest" ]; then
  gzip -dc -- "$dest" 2>/dev/null | cmp -s - "$src" && exit 0
  echo "$name est déjà archivé avec un contenu différent : refus d'écraser" >&2; exit 1
fi
tmp="$wal/.tmp.$name.$$"
trap 'rm -f -- "$tmp"' EXIT
gzip -1 -c -- "$src" > "$tmp" || exit 1
gzip -t -- "$tmp" || exit 1
sync -- "$tmp" || exit 1
mv -- "$tmp" "$dest" || exit 1
sync -- "$wal" 2>/dev/null || true
exit 0
