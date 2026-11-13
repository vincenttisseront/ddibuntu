#!/usr/bin/env bash
# Batterie 27 — pare-feu : demandes de la console (réseaux d'administration), validées et appliquées par root avec retour arrière.
# nft est remplacé par un bouchon : on vérifie la logique de ddibuntu-fw (validation, confirmation, restauration de firewall.conf), pas le noyau
# (le comportement réel des règles est couvert par la batterie 04).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

FW="$RFS/usr/local/sbin/ddibuntu-fw"
mkdir -p "$T_TMP/bin" "$T_TMP/gen" "$T_TMP/run" "$T_TMP/state"
printf '#!/bin/bash\n[ "$1" = list ] && exit 1\nexit 0\n' > "$T_TMP/bin/nft"; chmod +x "$T_TMP/bin/nft"
export PATH="$T_TMP/bin:$PATH" DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_FW_CONF="$T_TMP/fw.conf" DDI_NFT_FILE="$T_TMP/fw.nft"
export DDI_FW_STATE="$T_TMP/state" DDI_GENERATED_DIR="$T_TMP/gen" DDI_RUN_DIR="$T_TMP/run" DDI_FW_CONFIRM=3
req() { printf '%s' "$1" > "$T_TMP/gen/.fw-request"; "$FW" request >/dev/null 2>&1; }
nets() { sed -n 's/^ADMIN_NETS="\(.*\)"$/\1/p' "$T_TMP/fw.conf"; }
res() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$T_TMP/run/fw-result.json" "$1"; }

"$FW" set ADMIN_NETS "192.168.1.0/24" >/dev/null
echo "== Application avec confirmation =="
req '{"action":"set","nets":["10.20.0.15","192.168.1.0/24"]}'
expect_eq "demande consommée" no "$([ -e "$T_TMP/gen/.fw-request" ] && echo yes || echo no)"
expect_eq "réseaux normalisés dans firewall.conf" "10.20.0.15/32,192.168.1.0/24" "$(nets)"
expect_eq "résultat publié : ok" True "$(res ok)"
expect_grep "délai de confirmation publié" '"until"' "$T_TMP/run/fw-pending.json"
expect_grep "règles écrites : l'ensemble admin4 contient le nouveau réseau" '10.20.0.15/32' "$T_TMP/fw.nft"
req '{"action":"set","nets":["10.0.0.0/8"]}'
expect_eq "une application en attente bloque la suivante" False "$(res ok)"
expect_eq "…et ne modifie pas la configuration" "10.20.0.15/32,192.168.1.0/24" "$(nets)"
req '{"action":"confirm"}'
expect_eq "confirmation : ok" True "$(res ok)"
expect_eq "confirmation : configuration conservée" "10.20.0.15/32,192.168.1.0/24" "$(nets)"
expect_eq "confirmation : délai effacé" no "$([ -e "$T_TMP/run/fw-pending.json" ] && echo yes || echo no)"

echo "== Retour arrière demandé =="
req '{"action":"set","nets":["10.9.0.0/24"]}'
req '{"action":"rollback"}'
expect_eq "retour arrière : firewall.conf restauré" "10.20.0.15/32,192.168.1.0/24" "$(nets)"
expect_eq "retour arrière : ok" True "$(res ok)"

echo "== Retour arrière automatique (pas de confirmation) =="
req '{"action":"set","nets":["10.9.0.0/24"]}'
expect_eq "avant le délai : nouveau réseau en place" "10.9.0.0/24" "$(nets)"
sleep 5
expect_eq "après le délai : firewall.conf restauré tout seul" "10.20.0.15/32,192.168.1.0/24" "$(nets)"
expect_eq "après le délai : délai effacé" no "$([ -e "$T_TMP/run/fw-pending.json" ] && echo yes || echo no)"

echo "== Refus =="
for bad in '{"action":"set","nets":["0.0.0.0/0"]}' '{"action":"set","nets":["::/0"]}' '{"action":"set","nets":["x; rm -rf /"]}' '{"action":"set","nets":[]}' '{"action":"autre"}' 'pas du json' '{"action":"set","nets":"10.0.0.0/8"}'; do
  req "$bad"
  expect_eq "refusé : $bad" False "$(res ok)"
  expect_eq "…configuration intacte" "10.20.0.15/32,192.168.1.0/24" "$(nets)"
done
req '{"action":"confirm"}'; expect_eq "confirmer sans application en attente : refusé" False "$(res ok)"
ln -sf /etc/passwd "$T_TMP/gen/.fw-request"; "$FW" request >/dev/null 2>&1
expect_eq "lien symbolique supprimé sans être suivi" no "$([ -L "$T_TMP/gen/.fw-request" ] && echo yes || echo no)"
expect_eq "…et refusé" False "$(res ok)"
finish
