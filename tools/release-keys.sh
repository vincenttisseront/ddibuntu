#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# tools/release-keys.sh — mêmes règles que l'appliance (src/rootfs/usr/local/lib/ddibuntu/release-keys.sh), appliquées au dépôt :
# clés de confiance = src/rootfs/etc/ddibuntu/update-pubkey.pem + keys/release.d/*.pem, après application de TOUS les manifestes
# de rotation du dépôt (keys/rotations/key-rotation-NNN.json, signés par keys/release-secours.pem), dans l'ordre.
# Aucune clé privée n'est lue, sauf par « check-signer » quand on lui en donne une : il n'en garde que la partie publique.
#
#   verify FICHIER SIGNATURE   la signature est-elle valide pour une clé de confiance ?
#   check-signer CLÉ           cette clé (publique, ou privée) est-elle une clé de confiance, et pas la clé de secours ?
#   check-rotations            tous les manifestes du dépôt sont-ils valides et signés par la clé de secours ?
#   list                       clés de confiance (empreinte, origine)
#   RK_REPO : racine du dépôt à contrôler (par défaut, celui de ce script ; les tests en donnent un autre)
set -euo pipefail
LIB="$(cd "$(dirname "$0")/.." && pwd)/src/rootfs/usr/local/lib/ddibuntu/release-keys.sh"
cd "${RK_REPO:-$(dirname "$0")/..}"
ROTDIR="keys/rotations"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export RK_CONFDIR="$PWD/src/rootfs/etc/ddibuntu" RK_STATE="$WORK/state" RK_LEGACY="$PWD/src/rootfs/etc/ddibuntu/update-pubkey.pem"
# shellcheck source=src/rootfs/usr/local/lib/ddibuntu/release-keys.sh
. "$LIB"

apply_repo_rotations() {
  local m n expect=1 rc
  for m in "$ROTDIR"/key-rotation-*.json; do
    [ -f "$m" ] || continue
    n="${m##*/key-rotation-}"; n="${n%.json}"
    [[ "$n" =~ ^[0-9]{3}$ ]] || { echo "nom de manifeste invalide : $m" >&2; return 1; }
    [ "$((10#$n))" -eq "$expect" ] || { echo "manifestes non consécutifs : $m (attendu n°$expect)" >&2; return 1; }
    rc=0; rk_apply_rotation "$m" "$m.sig" || rc=$?
    [ "$rc" -eq 0 ] || { echo "$m refusé : ${RK_ERR:-numéro de séquence différent du nom du fichier}" >&2; return 1; }
    [ "$(rk_seq)" -eq "$expect" ] || { echo "$m : le numéro de séquence du contenu ne correspond pas au nom" >&2; return 1; }
    expect=$((expect + 1))
  done
}

case "${1:-}" in
  verify)
    [ $# -eq 3 ] || { echo "usage : $0 verify FICHIER SIGNATURE" >&2; exit 2; }
    apply_repo_rotations
    if rk_verify "$2" "$3"; then echo "signature valide (clé $RK_KEY_FPR)"; else echo "::error::$RK_ERR" >&2; exit 1; fi ;;
  check-signer)
    [ $# -eq 2 ] || { echo "usage : $0 check-signer CLÉ (publique, ou privée dont seule la partie publique est gardée)" >&2; exit 2; }
    apply_repo_rotations
    openssl pkey -pubin -in "$2" -out "$WORK/signer.pub" 2>/dev/null || openssl pkey -in "$2" -pubout -out "$WORK/signer.pub" 2>/dev/null \
      || { echo "::error::clé de signature illisible" >&2; exit 1; }
    fp="$(rk_fpr "$WORK/signer.pub")" || { echo "::error::la clé de signature n'est pas une clé Ed25519" >&2; exit 1; }
    [ "$fp" != "$(rk_secours_fpr)" ] || { echo "::error::la clé de SECOURS ne signe jamais une archive" >&2; exit 1; }
    if rk_trusted | cut -f1 | grep -qxF "$fp"; then echo "clé de signature de confiance ($fp)"
    else echo "::error::la clé de signature ($fp) n'est pas une clé de confiance épinglée (ou elle est révoquée) : les appliances refuseraient l'archive" >&2; exit 1; fi ;;
  check-rotations)
    apply_repo_rotations
    for s in "$ROTDIR"/*; do
      [ -e "$s" ] || continue
      case "$s" in "$ROTDIR"/key-rotation-[0-9][0-9][0-9].json|"$ROTDIR"/key-rotation-[0-9][0-9][0-9].json.sig|"$ROTDIR"/README.md) ;;
        *) echo "fichier inattendu dans $ROTDIR : $s" >&2; exit 1 ;; esac
    done
    echo "manifestes de rotation valides : $(rk_seq)" ;;
  list)
    apply_repo_rotations
    rk_trusted | cut -f1,2 ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
