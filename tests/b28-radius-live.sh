#!/usr/bin/env bash
# Batterie 28 — service RADIUS (0.13.0, itération 1) : ddibuntu-radius contre un VRAI FreeRADIUS (le démon est lancé par un faux systemctl),
# trafic RADIUS réel (radclient et la sonde de la console), demandes de la console, validation stricte, retour arrière, pare-feu des clients.
# Prérequis : root, freeradius + freeradius-utils (radclient), node 22 ; nft pour contrôler les règles (sinon ces contrôles sont signalés).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

RAD="$RFS/usr/local/sbin/ddibuntu-radius"
FW="$RFS/usr/local/sbin/ddibuntu-fw"
if [ "$(id -u)" -ne 0 ] || ! command -v freeradius >/dev/null || ! command -v radclient >/dev/null; then
  note "prérequis absents (root, freeradius, radclient) : batterie ignorée"; finish; exit $?
fi
udp_listen() {   # udp_listen PORT : un socket UDP est-il ouvert sur ce port ? (lecture de /proc, sans dépendre de iproute2)
  local hex; hex="$(printf '%04X' "$1")"
  cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk -v h=":$hex" '$2 ~ (h "$") { f = 1 } END { exit !f }'   # /proc/net/udp6 est absent sans IPv6
}
if udp_listen 1812 || udp_listen 1813; then note "ports UDP 1812/1813 déjà utilisés : batterie ignorée"; finish; exit $?; fi
D="$T_TMP"; chmod 0755 "$D"   # le démon abandonne ses privilèges (freerad) : le dossier doit rester traversable
mkdir -p "$D/gen" "$D/run" "$D/state" "$D/bin"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_RADIUS_DIR="$D/etc" DDI_RADIUS_LOCK="$D/lock" DDI_STATE_DIR="$D/state" DDI_RUN_DIR="$D/run" DDI_GENERATED_DIR="$D/gen"
export DDI_RADIUS_SYSTEMCTL="$D/bin/systemctl" DDI_FW_BIN="$D/bin/fw"
export DDI_RADIUS_AUTHLOG_DIR="$D/authlog" DDI_CONSOLE_GROUP=daemon
SELF="0123456789abcdef0123456789abcdef"; WLC="abcdefABCDEF._~+=:@,;()!*-0123"

# faux systemctl : le service est un vrai freeradius lancé sur l'arborescence générée ; « fail » dans $D/failstart simule un démarrage impossible
cat > "$D/bin/systemctl" <<SH
#!/bin/bash
P="$D/radiusd.pid"
alive() { [ -f "\$P" ] && kill -0 "\$(cat "\$P")" 2>/dev/null; }
case "\$1" in
  daemon-reload|enable) exit 0 ;;
  restart) [ -e "$D/failstart" ] && exit 1
           alive && { kill "\$(cat "\$P")"; sleep 0.5; }
           ( /usr/sbin/freeradius -f -d "$D/etc" >"$D/daemon.out" 2>&1 9>&- </dev/null & echo \$! > "\$P" ); sleep 1; exit 0 ;;
  disable) alive && kill "\$(cat "\$P")"; rm -f "\$P"; sleep 0.3; exit 0 ;;
  is-active) alive; exit \$? ;;
  is-enabled) exit 0 ;;
esac
SH
# faux pare-feu : journalise les appels (le vrai est contrôlé plus bas)
cat > "$D/bin/fw" <<SH
#!/bin/bash
printf '%s\n' "\$*" >> "$D/fw.log"
[ -e "$D/fwfail" ] && exit 1
exit 0
SH
chmod +x "$D/bin/systemctl" "$D/bin/fw"
trap 'kill "$(cat "$D/radiusd.pid" 2>/dev/null)" 2>/dev/null; rm -rf "$T_TMP"' EXIT

clients() {   # clients [extra-bloc] -> fichier
  local f="$D/clients.$RANDOM"
  { printf 'client "ddi-selftest" {\n\tipaddr = 127.0.0.1\n\tsecret = "%s"\n\tshortname = ddi-selftest\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n\n' "$SELF"
    printf 'client "wlc-01" {\n\tipaddr = 10.10.0.0/24\n\tsecret = "%s"\n\tshortname = wlc-01\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n\n' "$WLC"
    printf 'client "vpn-gw" {\n\tipaddr = 192.0.2.7\n\tsecret = "zzzzzzzzzzzzzzzzzzzz"\n\tshortname = vpn-gw\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n\n'
    printf '%s' "${1:-}"; } > "$f"; printf '%s' "$f"
}
send() {   # send secret -> sortie radclient (une requête PAP signée)
  printf 'User-Name = "nobody", User-Password = "x", Message-Authenticator = 0x00\n' | radclient -t 2 -r 1 127.0.0.1:1812 auth "$1" 2>&1
}
rj() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

echo "== Validation stricte du fichier de clients (aucune écriture) =="
check "fichier conforme accepté" "$RAD" check "$(clients)"
out="$("$RAD" check "$(clients)" | sort | tr '\n' ' ')"
expect_eq "réseaux à ouvrir au pare-feu (sans le client d'essai)" "10.10.0.0/24 192.0.2.7/32 " "$out"
for bad in 'exec_wait = yes' '$INCLUDE /etc/passwd' 'client "x y" {' 'secret = "ab"'; do
  f="$(clients "client \"mal\" {
	ipaddr = 10.20.0.0/24
	secret = \"abcdefghijklmnop\"
	shortname = mal
	require_message_authenticator = yes
	nas_type = other
	$bad
}
")"
  check_fail "refusé : $bad" "$RAD" check "$f"
done
check_fail "réseau /8 refusé" "$RAD" check "$(clients 'client "gros" {
	ipaddr = 10.0.0.0/8
	secret = "abcdefghijklmnop"
	shortname = gros
	require_message_authenticator = yes
	nas_type = other
}
')"
check_fail "fichier sans client d'essai refusé" "$RAD" check <(sed '1,/^}$/d' "$(clients)")

echo "== Application réelle : arborescence, démon, trafic =="
mkdir -p "$D/state"; chmod 0755 "$D/state"   # le dossier d'état existe déjà : la console doit pouvoir le traverser
"$RAD" apply "$(clients)" >"$D/apply.out" 2>&1; rc=$?
expect_eq "apply : code 0" 0 "$rc"
expect_eq "apply : le dossier d'état garde ses droits (0755, traversable par la console)" 755 "$(stat -c '%a' "$D/state")"
expect_grep "message : 2 clients" 'démarré \(2 client' "$D/apply.out"
expect_eq "clients.conf : 0640 root:freerad" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/clients.conf")"
expect_eq "radiusd.conf : 0640 root:freerad" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/radiusd.conf")"
expect_eq "un seul site activé (pas de site « default » du paquet)" "ddibuntu" "$(ls "$D/etc/sites-enabled")"
expect_eq "modules limités à la liste blanche" "always attr_filter ddibuntu_authlog expr preprocess" "$(ls "$D/etc/mods-enabled" | tr '\n' ' ' | sed 's/ $//')"
expect_nogrep "aucun secret par défaut du paquet" 'testing123' "$D/etc/clients.conf"
expect_eq "statut publié : actif" True "$(rj "$D/run/radius-status.json" active)"
expect_eq "statut publié : 2 clients (sans le client d'essai)" 2 "$(rj "$D/run/radius-status.json" clients)"
expect_eq "statut publié : version du démon" 3 "$(rj "$D/run/radius-status.json" version | cut -d. -f1)"
udp_listen 1812 && ok "démon : écoute l'authentification (UDP 1812)" || ko "démon : écoute l'authentification (UDP 1812)" "port non ouvert"
udp_listen 1813 && ok "démon : écoute la comptabilité (UDP 1813)" || ko "démon : écoute la comptabilité (UDP 1813)" "port non ouvert"
expect_eq "pare-feu : réseaux des clients transmis" "set RADIUS_NETS 10.10.0.0/24,192.0.2.7/32" "$(sed -n 1p "$D/fw.log")"
expect_eq "pare-feu : puis application" "apply" "$(sed -n 2p "$D/fw.log")"

echo "== Journal des authentifications : droits, une ligne par refus, valeurs piégées =="
AL="$D/authlog/radius-auth.log"
expect_eq "dossier du journal : 2750 freerad:groupe de la console (setgid)" "2750 freerad daemon" "$(stat -c '%a %U %G' "$D/authlog")"
printf 'User-Name = "we|ird\\"na\x27me=", User-Password = "x", Calling-Station-Id = "aa:bb:cc:dd:ee:ff|zz", Message-Authenticator = 0x00\n' | radclient -t 2 -r 1 127.0.0.1:1812 auth "$SELF" >/dev/null 2>&1
sleep 0.5
expect_eq "journal : fichier 0640 freerad:groupe de la console" "640 freerad daemon" "$(stat -c '%a %U %G' "$AL" 2>/dev/null)"
lastline="$(tail -n 1 "$AL" 2>/dev/null)"
expect_eq "refus journalisé sur UNE ligne de 18 champs (les « | » des valeurs sont neutralisés)" 18 "$(printf '%s' "$lastline" | awk -F'|' '{print NF}')"
expect_eq "…version, résultat et équipement" "v1 reject ddi-selftest" "$(printf '%s' "$lastline" | awk -F'|' '{print $1" "$3" "$5}')"
expect_eq "…nom présenté : « | », guillemet, apostrophe, « = » codés" 'we=7Cird=22na=27me=3D' "$(printf '%s' "$lastline" | awk -F'|' '{print $4}')"
expect_eq "…adresse MAC : « | » codé" 'aa:bb:cc:dd:ee:ff=7Czz' "$(printf '%s' "$lastline" | awk -F'|' '{print $7}')"
r="$(send "$SELF")"
echo "$r" | grep -q 'Received Access-Reject' && ok "bon secret : Access-Reject authentique (aucune règle d'accès : refus par défaut)" || ko "bon secret : Access-Reject attendu" "$(echo "$r" | tail -3 | tr '\n' ' ')"
r="$(send "wrongsecretwrongsecretwrong")"
echo "$r" | grep -q 'Received' && ko "mauvais secret : aucune réponse attendue" "$r" || ok "mauvais secret : aucune réponse (paquet ignoré)"
# la sonde de la console elle-même (même code que la page), contre ce démon
probe="$(node --experimental-strip-types --no-warnings -e "
import('$ROOT/webui/server/utils/radius-proto.ts').then(async (m) => { console.log(JSON.stringify(await m.radiusProbe({ port: 1812, secret: '$SELF', timeoutMs: 3000 }))); const w = await m.radiusProbe({ port: 1812, secret: 'x'.repeat(32), timeoutMs: 1200 }); console.log(JSON.stringify(w)) })" 2>&1)"
expect_eq "sonde de la console : refus authentique" "true reject" "$(echo "$probe" | sed -n 1p | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(d["ok"]).lower(), d.get("reply"))')"
expect_eq "sonde de la console : mauvais secret = délai dépassé" "false timeout" "$(echo "$probe" | sed -n 2p | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(d["ok"]).lower(), d.get("error"))')"

echo "== Retour arrière si le service ne démarre pas =="
h1="$(cd "$D/etc" && find . -type f -o -type l | sort | xargs -I{} sh -c 'printf "%s " {}; readlink {} || sha256sum < {}' | sha256sum)"
touch "$D/failstart"
f="$(clients 'client "nouveau" {
	ipaddr = 10.30.0.0/24
	secret = "nouveaunouveaunouveau"
	shortname = nouveau
	require_message_authenticator = yes
	nas_type = other
}
')"
# 0.14.16 : la raison lue dans le journal du service accompagne l'échec (faux journalctl) ; rien d'autre que des lignes d'erreur
printf '#!/bin/bash\necho "Starting - reading configuration files ..."\necho "Unable to open file \\"/etc/ddibuntu/radius/mods-enabled/eap\\": Permission denied"\necho "Errors reading or parsing /etc/ddibuntu/radius/radiusd.conf"\necho "freeradius.service: Failed with result exit-code."\n' > "$D/bin/journalctl"; chmod +x "$D/bin/journalctl"
DDI_RADIUS_JOURNALCTL="$D/bin/journalctl" "$RAD" apply "$f" >"$D/why.out" 2>&1
expect_grep "…la raison du journal est donnée" 'journal : Unable to open file .*Permission denied Errors reading' "$D/why.out"
expect_nogrep "…sans les lignes sans erreur ni le bruit de systemd" 'Starting - reading|Failed with result' "$D/why.out"
check_fail "démarrage impossible : apply échoue" "$RAD" apply "$f"
h2="$(cd "$D/etc" && find . -type f -o -type l | sort | xargs -I{} sh -c 'printf "%s " {}; readlink {} || sha256sum < {}' | sha256sum)"
expect_eq "…ancienne arborescence restaurée à l'identique" "$h1" "$h2"
expect_nogrep "…le client refusé n'est pas resté" 'nouveau' "$D/etc/clients.conf"
rm -f "$D/failstart"

echo "== Demande de la console =="
cp "$(clients)" "$D/gen/radius-clients.conf"; printf '{"action":"apply"}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "request apply : code 0" 0 "$rc"
expect_eq "demande consommée" no "$([ -e "$D/gen/.radius-request" ] && echo yes || echo no)"
expect_eq "secrets déposés effacés du disque" no "$([ -e "$D/gen/radius-clients.conf" ] && echo yes || echo no)"
expect_eq "résultat publié : ok" True "$(rj "$D/run/radius-result.json" ok)"
expect_eq "résultat publié : action" apply "$(rj "$D/run/radius-result.json" action)"
expect_nogrep "résultat sans secret" "$WLC|$SELF" "$D/run/radius-result.json"
touch "$D/fwfail"; cp "$(clients)" "$D/gen/radius-clients.conf"; printf '{"action":"apply"}' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1
expect_eq "pare-feu en échec : le service reste, avertissement publié" "True" "$(rj "$D/run/radius-result.json" ok)"
expect_grep "…message d'avertissement" 'AVERTISSEMENT : pare-feu' "$D/run/radius-result.json"
rm -f "$D/fwfail"
for badreq in '{"action":"rm -rf"}' 'pas du json' '[]' '{"action":"apply"}'; do
  rm -f "$D/gen/radius-clients.conf"; printf '%s' "$badreq" > "$D/gen/.radius-request"
  "$RAD" request >/dev/null 2>&1
  expect_eq "refusée : $badreq" False "$(rj "$D/run/radius-result.json" ok)"
done
printf '{"action":"apply"}' > "$D/gen/.radius-request"; printf 'client "pirate" {\n\tipaddr = 10.0.0.1\n}\n' > "$D/gen/radius-clients.conf"
"$RAD" request >/dev/null 2>&1
expect_eq "fichier de clients invalide déposé : refusé" False "$(rj "$D/run/radius-result.json" ok)"
expect_eq "…et effacé" no "$([ -e "$D/gen/radius-clients.conf" ] && echo yes || echo no)"
expect_eq "…le service tourne toujours avec la bonne configuration" True "$(rj "$D/run/radius-status.json" active)"
ln -sf /etc/passwd "$D/gen/.radius-request"; "$RAD" request >/dev/null 2>&1
expect_eq "lien symbolique supprimé sans être suivi" no "$([ -L "$D/gen/.radius-request" ] && echo yes || echo no)"
expect_eq "…et refusé" False "$(rj "$D/run/radius-result.json" ok)"

echo "== Arrêt =="
printf '{"action":"stop"}' > "$D/gen/.radius-request"; "$RAD" request >/dev/null 2>&1
expect_eq "arrêt : ok" True "$(rj "$D/run/radius-result.json" ok)"
expect_eq "arrêt : service inactif" False "$(rj "$D/run/radius-status.json" active)"
udp_listen 1812 && ko "arrêt : le port 1812 est refermé" "encore ouvert" || ok "arrêt : le port 1812 est refermé"
send "$SELF" | grep -q 'Received' && ko "arrêt : plus aucune réponse attendue" || ok "arrêt : plus aucune réponse"
expect_eq "arrêt : pare-feu refermé" "set RADIUS_NETS " "$(grep '^set RADIUS_NETS' "$D/fw.log" | tail -1)"

echo "== Cluster : RADIUS actif sur le leader seulement (0.15.0) =="
cat > "$D/bin/cluster" <<SH
#!/bin/bash
[ "\$1" = role ] || exit 2
cat "$D/role"
SH
chmod +x "$D/bin/cluster"
export DDI_CLUSTER_CONF="$D/cluster.conf" DDI_CLUSTER_CMD="$D/bin/cluster"
creq() {   # creq ACTION : dépose une demande de la console et la fait traiter
  rm -f "$D/gen/radius-clients.conf"
  [ "$1" = apply ] && cp "$(clients)" "$D/gen/radius-clients.conf"
  printf '{"action":"%s"}' "$1" > "$D/gen/.radius-request"; "$RAD" request >/dev/null 2>&1
}
creq apply   # hors cluster : comme avant
expect_eq "hors cluster : le déploiement fonctionne" True "$(rj "$D/run/radius-result.json" ok)"
: > "$D/cluster.conf"; printf replica > "$D/role"
creq apply
expect_eq "secondaire : « Déployer » refusé" False "$(rj "$D/run/radius-result.json" ok)"
expect_grep "secondaire : la raison est dite" 'secondaire du cluster' "$D/run/radius-result.json"
creq stop
expect_eq "secondaire : « Arrêter » refusé aussi" False "$(rj "$D/run/radius-result.json" ok)"
creq crl
expect_eq "secondaire : l'envoi de CRL est refusé aussi" False "$(rj "$D/run/radius-result.json" ok)"
expect_eq "…rien n'a été modifié : le service tourne encore" True "$(rj "$D/run/radius-status.json" active)"
"$RAD" align leader >/dev/null 2>&1; rc=$?
expect_eq "align leader : code 0" 0 "$rc"
expect_eq "align leader : ne touche pas au service" True "$(rj "$D/run/radius-status.json" active)"
"$RAD" align replica >/dev/null 2>&1; rc=$?
expect_eq "align replica : code 0" 0 "$rc"
expect_eq "align replica : le service est arrêté" False "$(rj "$D/run/radius-status.json" active)"
udp_listen 1812 && ko "align replica : le port 1812 est refermé" "encore ouvert" || ok "align replica : le port 1812 est refermé"
send "$SELF" | grep -q 'Received' && ko "align replica : plus aucune réponse" "répond encore" || ok "align replica : plus aucune réponse (la borne bascule sur l'adresse virtuelle)"
"$RAD" align replica >/dev/null 2>&1; rc=$?
expect_eq "align replica : répété sans effet (idempotent)" 0 "$rc"
check_fail "align : rôle inconnu refusé" "$RAD" align arbitre
printf leader > "$D/role"; creq apply
expect_eq "leader : « Déployer » accepté" True "$(rj "$D/run/radius-result.json" ok)"
expect_eq "leader : le service tourne" True "$(rj "$D/run/radius-status.json" active)"
send "$SELF" | grep -q 'Received' && ok "leader : le service répond" || ko "leader : le service répond" "aucune réponse"
printf witness > "$D/role"; creq apply
expect_eq "arbitre : « Déployer » refusé" False "$(rj "$D/run/radius-result.json" ok)"
expect_grep "arbitre : la raison est dite" "arbitre du cluster" "$D/run/radius-result.json"
printf 'n importe quoi' > "$D/role"; creq stop
expect_eq "rôle inconnu : refusé par prudence" False "$(rj "$D/run/radius-result.json" ok)"
expect_eq "…le service tourne toujours (on ne coupe rien dans le doute)" True "$(rj "$D/run/radius-status.json" active)"
rm -f "$D/cluster.conf"; unset DDI_CLUSTER_CONF DDI_CLUSTER_CMD; export DDI_CLUSTER_CONF="$D/aucun-cluster.conf"
creq stop
expect_eq "hors cluster : « Arrêter » fonctionne toujours" True "$(rj "$D/run/radius-result.json" ok)"
expect_grep "ddibuntu-cluster follow aligne RADIUS avec le rôle Patroni" '^  \( cmd_radius_align "\$role" \)' "$RFS/usr/local/sbin/ddibuntu-cluster"

echo "== Pare-feu : seuls les clients atteignent 1812/1813 =="
export DDI_FW_CONF="$D/fw.conf" DDI_NFT_FILE="$D/fw.nft" DDI_FW_STATE="$D/fwstate"
"$FW" set ADMIN_NETS "10.0.0.0/24" >/dev/null
check "set RADIUS_NETS (IPv4, IPv6, adresse seule)" "$FW" set RADIUS_NETS "10.10.0.0/24,2001:db8::/48,192.0.2.7"
"$FW" render > "$D/r.nft"
expect_grep "règle IPv4 limitée à l'ensemble des clients" 'ip saddr @radius4 udp dport \{ 1812, 1813 \} accept' "$D/r.nft"
expect_grep "règle IPv6 limitée à l'ensemble des clients" 'ip6 saddr @radius6 udp dport \{ 1812, 1813 \} accept' "$D/r.nft"
expect_grep "adresse seule normalisée en /32" '192\.0\.2\.7/32' "$D/r.nft"
expect_nogrep "aucune ouverture générale de 1812" 'udp dport \{[^}]*1812[^}]*\} accept$' <(grep -v '@radius' "$D/r.nft")
if command -v nft >/dev/null; then check "règles produites : syntaxe valide (nft -c)" "$FW" check; else note "nft absent : syntaxe non contrôlée"; fi
check_fail "valeur piégée refusée" "$FW" set RADIUS_NETS "10.0.0.0/24; accept"
check_fail "réseau invalide refusé" "$FW" set RADIUS_NETS "pas-un-reseau"
expect_eq "…firewall.conf inchangé après refus" '10.10.0.0/24,2001:db8::/48,192.0.2.7' "$(sed -n 's/^RADIUS_NETS="\(.*\)"$/\1/p' "$D/fw.conf")"
"$FW" set RADIUS_NETS "" >/dev/null; "$FW" render > "$D/r2.nft"
expect_nogrep "sans client : aucune règle RADIUS" '@radius[46] udp dport' "$D/r2.nft"
expect_eq "ADMIN_NETS conservé par les écritures successives" "10.0.0.0/24" "$(sed -n 's/^ADMIN_NETS="\(.*\)"$/\1/p' "$D/fw.conf")"

echo "== Unités et fichiers livrés =="
expect_grep "unité : déclenchée par la demande de la console" '^PathChanged=/var/lib/ddibuntu/generated/\.radius-request$' "$RFS/etc/systemd/system/ddibuntu-radius-request.path"
expect_grep "unité : exécute ddibuntu-radius request" '^ExecStart=/usr/local/sbin/ddibuntu-radius request$' "$RFS/etc/systemd/system/ddibuntu-radius-request.service"
expect_grep "freeradius : lit uniquement l'arborescence Ipnoria" '^ExecStart=/usr/sbin/freeradius -f -d /etc/ddibuntu/radius$' "$RFS/etc/systemd/system/freeradius.service.d/ddibuntu.conf"
expect_grep "freeradius : contrôle avant démarrage sur cette arborescence" '^ExecStartPre=/usr/sbin/freeradius -d /etc/ddibuntu/radius -Cx -lstdout$' "$RFS/etc/systemd/system/freeradius.service.d/ddibuntu.conf"
finish
