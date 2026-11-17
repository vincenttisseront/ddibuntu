#!/usr/bin/env bash
# pki-gen-profiles.sh — régénère les profils EJBCA fournis par le DDI (src/rootfs/usr/local/lib/ddibuntu/pki-profiles/*.xml) avec le code d'EJBCA lui-même.
# À relancer seulement quand on change tools/pki-profiles/Gen.java ou la version d'EJBCA de référence ; la sortie est versionnée.
# Prérequis : un conteneur EJBCA en marche (par défaut « ddibuntu-ejbca », ex. celui que laisse la batterie b33 / b35 avec DDI_TEST_PKI_KEEP=1)
# et son dossier d'échange visible depuis l'hôte (DDI_PKI_WORK_HOST, vu du conteneur : /mnt/persistent/work).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PODMAN="${DDI_PKI_PODMAN:-podman}"
NAME="${DDI_PKI_CONTAINER:-ddibuntu-ejbca}"
WORK_HOST="${DDI_PKI_WORK_HOST:-/var/lib/ddibuntu/pki/persistent/work}"
OUT="$ROOT/src/rootfs/usr/local/lib/ddibuntu/pki-profiles"
[[ -d "$WORK_HOST" ]] || { echo "dossier d'échange introuvable : $WORK_HOST (DDI_PKI_WORK_HOST)" >&2; exit 1; }
rm -rf "${WORK_HOST:?}/gen"; install -d -m 0777 "$WORK_HOST/gen"
cp "$ROOT/tools/pki-profiles/Gen.java" "$WORK_HOST/Gen.java"; chmod 0644 "$WORK_HOST/Gen.java"
"$PODMAN" exec -w /mnt/persistent/work "$NAME" java -cp '/opt/keyfactor/ejbca/dist/ejbca-ejb-cli/lib/*' Gen.java /mnt/persistent/work/gen
install -d "$OUT"
rm -f "$OUT"/*.xml
cp "$WORK_HOST"/gen/*.xml "$OUT"/
rm -rf "${WORK_HOST:?}/gen" "$WORK_HOST/Gen.java"
ls -l "$OUT"
