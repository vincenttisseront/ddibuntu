#!/usr/bin/env bash
# Batterie 09 — mise à jour en ligne (ddibuntu-selfupdate) contre un FAUX GitHub local (serveur HTTP) avec de vraies
# signatures Ed25519 : détection, notes, demandes hostiles, signature invalide, archive altérée, retour arrière si la
# console ne redémarre pas, installation réussie (données, pare-feu et réglages conservés), hors-ligne.
# Ne demande ni root ni systemd (DDI_TEST=1, DDI_NO_SYSTEMD=1, DDI_ROOT).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
for t in openssl python3 curl flock; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
SU="$RFS/usr/local/sbin/ddibuntu-selfupdate"
COMMON="$RFS/usr/local/lib/ddibuntu/common.sh"
W="$T_TMP/w"; mkdir -p "$W"
R=$W/root; SRV=$W/srv; PORT=$((20000 + RANDOM % 20000))
mk() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod "${3:-644}" "$1"; }
jget() { python3 -c "import json,sys; d=json.load(open('$1')); v=d.get('$2'); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
openssl genpkey -algorithm ed25519 -out "$W/priv.pem" 2>/dev/null; openssl pkey -in "$W/priv.pem" -pubout -out "$W/pub.pem"
openssl genpkey -algorithm ed25519 -out "$W/evil.pem" 2>/dev/null

echo "== Système simulé 0.4.0 =="
mk "$R/usr/local/lib/ddibuntu/VERSION" 0.4.0; cp "$COMMON" "$R/usr/local/lib/ddibuntu/common.sh"
mk "$R/etc/ddibuntu/update.conf" 'REPO="acme/ddibuntu"'
cp "$W/pub.pem" "$R/etc/ddibuntu/update-pubkey.pem"
mk "$R/etc/ddibuntu/firewall.conf" 'ADMIN_NETS="10.1.0.0/16"'
mk "$R/etc/ddibuntu/nftables.nft" "REGLES ADMIN"
mk "$R/opt/ddibuntu/console/app/server/index.mjs" "OLD CONSOLE"
mk "$R/var/lib/ddibuntu/installed-version" 0.4.0
mk "$R/var/lib/ddibuntu/pgdata-marker" "DONNEES"
# shellcheck disable=SC2016  # le $1 du stub doit rester littéral
mk "$R/usr/local/sbin/ddibuntu-fw" '#!/bin/bash
echo "$1" > "$(dirname "$0")/../../../etc/ddibuntu/fw-called"' 755
mkdir -p "$R/run" "$SRV/dl"

mkrelease() { # version signing-key [corrupt]
  local v="$1" key="$2" d="$W/rel-$1"; rm -rf "$d"; mkdir -p "$d/rootfs/usr/local/lib/ddibuntu" "$d/rootfs/etc/ddibuntu" "$d/rootfs/usr/local/sbin" "$d/con/app/server" "$d/b"
  echo "$v" > "$d/rootfs/usr/local/lib/ddibuntu/VERSION"; echo "NEW CONSOLE $v" > "$d/con/app/server/index.mjs"
  echo 'ADMIN_NETS=""' > "$d/rootfs/etc/ddibuntu/firewall.conf"; echo "REGLES DEFAUT" > "$d/rootfs/etc/ddibuntu/nftables.nft"; echo "NOUVEAU $v" > "$d/rootfs/etc/ddibuntu/nouveau.txt"
  cp "$R/usr/local/sbin/ddibuntu-fw" "$d/rootfs/usr/local/sbin/"; chmod 755 "$d/rootfs/usr/local/sbin/ddibuntu-fw"
  ( cd "$d/rootfs" && tar --owner=0 --group=0 -cf "$d/b/rootfs.tar" . ) ; ( cd "$d/b" && sha256sum rootfs.tar > rootfs.tar.sha256 )
  ( cd "$d/con" && tar -czf "$d/b/console.tar.gz" . ); echo "$v" > "$d/b/VERSION"
  ( cd "$d/b" && tar -czf "$SRV/dl/ddibuntu-update-$v.tar.gz" rootfs.tar rootfs.tar.sha256 console.tar.gz VERSION )
  ( cd "$SRV/dl" && sha256sum "ddibuntu-update-$v.tar.gz" > SHA256SUMS )
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$SRV/dl/SHA256SUMS" -out "$SRV/dl/SHA256SUMS.sig"
  mkdir -p "$SRV/repos/acme/ddibuntu/releases"
  python3 - "$SRV/repos/acme/ddibuntu/releases/latest" "$v" "$PORT" <<'PY'
import json, sys
p, v, port = sys.argv[1:4]
base = 'http://127.0.0.1:%s/dl/' % port
json.dump({'tag_name': 'v' + v, 'html_url': 'https://github.com/acme/ddibuntu/releases/tag/v' + v, 'published_at': '2026-11-10T10:00:00Z',
           'body': 'Notes de version %s\n- changement A\n- changement B' % v, 'draft': False, 'prerelease': False,
           'assets': [{'name': n, 'url': base + n} for n in ['ddibuntu-update-%s.tar.gz' % v, 'SHA256SUMS', 'SHA256SUMS.sig']]}, open(p, 'w'))
PY
}
( cd "$SRV" && python3 -m http.server $PORT --bind 127.0.0.1 >"$W/http.log" 2>&1 & echo $! > "$W/http.pid" )
sleep 1
cleanup_http() { kill "$(cat "$W/http.pid")" 2>/dev/null; }
trap 'cleanup_http; rm -rf "$T_TMP"' EXIT

export DDI_TEST=1 DDI_NO_SYSTEMD=1 DDI_ROOT="$R" DDI_LIBDIR="$R/usr/local/lib/ddibuntu" DDI_RUNDIR="$R/run" DDI_UPDATE_API="http://127.0.0.1:$PORT"
ST="$R/var/lib/ddibuntu/update-status.json"
req() { mkdir -p "$R/var/lib/ddibuntu/generated"; printf '%s' "$1" > "$R/var/lib/ddibuntu/generated/.update-request"; bash "$SU" request >"$W/out.log" 2>&1; echo $?; }

echo "== 0. Dépôt sans release publiée (404) : message distinct d'une panne réseau =="
expect_eq "aucune release : code 1" 1 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
if jget "$ST" error | grep -q "Aucune release"; then ok "message : aucune release publiée"; else ko "message aucune release" "$(jget "$ST" error)"; fi
if jget "$ST" error | grep -q "joindre GitHub"; then ko "ne doit PAS dire « impossible de joindre GitHub » pour un simple 404"; else ok "pas confondu avec une panne réseau"; fi

echo "== 1. Détection =="
mkrelease 0.5.0 "$W/priv.pem"
expect_eq "check : code 0" 0 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
expect_eq "état : latest = 0.5.0" 0.5.0 "$(jget "$ST" latest)"
expect_eq "état : current = 0.4.0" 0.4.0 "$(jget "$ST" current)"
expect_eq "état : available = true" true "$(jget "$ST" available)"
if jget "$ST" notes | grep -q "changement A"; then ok "notes de version récupérées"; else ko "notes" "$(jget "$ST" notes)"; fi
if stat -c %a "$ST" | grep -q 644; then ok "état lisible par la console (0644)"; else ko "mode état"; fi

echo "== 2. Demandes invalides (la console n'est pas fiable) =="
expect_eq "demande : JSON invalide ignorée" 0 "$(req 'pas du json')"
expect_eq "demande : action inconnue ignorée" 0 "$(req '{"action":"rm","version":"0.5.0"}')"
expect_eq "demande : version non numérique ignorée" 0 "$(req '{"action":"apply","version":"0.5.0; touch /tmp/pwn"}')"
if [ ! -e /tmp/pwn ]; then ok "aucune injection de commande"; else ko "injection"; fi
expect_eq "console intacte après demandes invalides" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "demande consommée" no "$([ -e "$R/var/lib/ddibuntu/generated/.update-request" ] && echo yes || echo no)"
expect_eq "apply d'une version qui n'est pas la dernière : refus" 1 "$(req '{"action":"apply","version":"0.9.9"}')"
expect_eq "état : failed" failed "$(jget "$ST" state)"

echo "== 3. Signature invalide (release signée par une autre clé) =="
mkrelease 0.6.0 "$W/evil.pem"
expect_eq "signature invalide : code 1" 1 "$(req '{"action":"apply","version":"0.6.0"}')"
expect_grep "message SIGNATURE INVALIDE" "SIGNATURE INVALIDE" "$W/out.log"
expect_eq "signature invalide : console intacte" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "signature invalide : version intacte" 0.4.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"

echo "== 4. Archive altérée (signature valide sur d'autres sommes) =="
mkrelease 0.6.0 "$W/priv.pem"; echo corrompu >> "$SRV/dl/ddibuntu-update-0.6.0.tar.gz"
expect_eq "archive altérée : code 1" 1 "$(req '{"action":"apply","version":"0.6.0"}')"
if grep -q "SHA-256" "$W/out.log"; then ok "somme SHA-256 incorrecte détectée"; else ko "message" "$(tail -3 "$W/out.log")"; fi

echo "== 5. Échec de santé -> retour arrière =="
mkrelease 0.5.0 "$W/priv.pem"
expect_eq "santé KO : code 1" 1 "$(DDI_TEST_HEALTH_FAIL=1 DDI_HEALTH_TRIES=2 DDI_HEALTH_SLEEP=0 req '{"action":"apply","version":"0.5.0"}')"
expect_eq "retour arrière : ancienne console restaurée" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "retour arrière : version restaurée" 0.4.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "retour arrière : état failed" failed "$(jget "$ST" state)"
expect_eq "retour arrière : pas de console.old résiduelle" no "$([ -e "$R/opt/ddibuntu/console.old" ] && echo yes || echo no)"
expect_eq "retour arrière : fichier nouveau VERSION restauré" 0.4.0 "$(tr -d '\n' < "$R/usr/local/lib/ddibuntu/VERSION")"

echo "== 6. Installation réussie =="
expect_eq "apply 0.5.0 : code 0" 0 "$(req '{"action":"apply","version":"0.5.0"}')"
tail -3 "$W/out.log"
expect_eq "console remplacée" "NEW CONSOLE 0.5.0" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "installed-version = 0.5.0" 0.5.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "VERSION de l'appliance = 0.5.0" 0.5.0 "$(tr -d '\n' < "$R/usr/local/lib/ddibuntu/VERSION")"
expect_eq "nouveau fichier déployé" "NOUVEAU 0.5.0" "$(cat "$R/etc/ddibuntu/nouveau.txt")"
expect_eq "firewall.conf de l'admin conservé" 'ADMIN_NETS="10.1.0.0/16"' "$(cat "$R/etc/ddibuntu/firewall.conf")"
expect_eq "nftables.nft de l'admin conservé" "REGLES ADMIN" "$(cat "$R/etc/ddibuntu/nftables.nft")"
expect_eq "update.conf conservé" 'REPO="acme/ddibuntu"' "$(cat "$R/etc/ddibuntu/update.conf")"
expect_eq "données conservées" DONNEES "$(cat "$R/var/lib/ddibuntu/pgdata-marker")"
expect_eq "re-rendu du pare-feu demandé" write "$(cat "$R/etc/ddibuntu/fw-called" 2>/dev/null)"
expect_eq "état : done" "done" "$(jget "$ST" state)"
expect_eq "état : current = 0.5.0" 0.5.0 "$(jget "$ST" current)"
expect_eq "état : available = false" false "$(jget "$ST" available)"
if grep -q "0.4.0 -> 0.5.0" "$R/var/lib/ddibuntu/update-history"; then ok "historique écrit"; else ko "historique"; fi
BK="$(find "$R/var/lib/ddibuntu/update-backup" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
if tar -tzf "$BK/replaced-files.tar.gz" | grep -q 'usr/local/lib/ddibuntu/VERSION'; then ok "sauvegarde des fichiers remplacés"; else ko "sauvegarde"; fi
expect_eq "répertoire de travail nettoyé" no "$([ -e "$R/var/lib/ddibuntu/update-work" ] && echo yes || echo no)"
expect_eq "apply de la même version : refus" 1 "$(req '{"action":"apply","version":"0.5.0"}')"

echo "== 7. Aucun accès réseau =="
export DDI_UPDATE_API="http://127.0.0.1:1"
expect_eq "check sans réseau : code 1" 1 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
if jget "$ST" error | grep -q "joindre GitHub"; then ok "erreur lisible dans l'état"; else ko "erreur" "$(jget "$ST" error)"; fi
expect_eq "check sans réseau : version actuelle conservée" 0.5.0 "$(jget "$ST" current)"

finish
