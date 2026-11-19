#!/usr/bin/env bash
# Batterie 40 — identifiant et mot de passe (0.16.0) : ddibuntu-radius contre un VRAI FreeRADIUS, un VRAI Samba AD (tests/samba-lab.sh), un VRAI winbind joint au
# domaine et de VRAIES poignées de main PEAP-MSCHAPv2 et EAP-TTLS/PAP (eapol_test).
# Couvre : validation stricte du dépôt (auth.json, radius-join), jonction réelle au domaine (compte machine propre au nœud, secret jamais conservé), PEAP refusé
# tant que l'appliance n'est pas jointe, puis PEAP et TTLS : mêmes règles d'accès qu'EAP-TLS (groupes imbriqués, VLAN de réponse), comptes désactivé / verrouillé /
# expiré / sans règle refusés AVANT le mot de passe, mauvais mot de passe, formes d'identifiant (DOMAINE\compte, UPN, compte seul), domaine étranger, jeu de
# caractères, journal, retrait de la jonction.
# Prérequis : root, freeradius + freeradius-ldap, winbind (ntlm_auth, winbindd) + samba-common-bin (net), eapol_test, openssl, samba (voir samba-lab.sh) ; sinon ignorée.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=lib-pki.sh
. "$(dirname "$0")/lib-pki.sh"

RAD="$RFS/usr/local/sbin/ddibuntu-radius"
for t in freeradius eapol_test openssl ntlm_auth winbindd net; do
  command -v "$t" >/dev/null || { note "prérequis absents ($t) : batterie ignorée"; finish; exit $?; }
done
if [ "$(id -u)" -ne 0 ] || [ ! -e /usr/lib/freeradius/rlm_ldap.so ] || ! id freerad >/dev/null 2>&1; then
  note "prérequis absents (root, freeradius-ldap, utilisateur freerad) : batterie ignorée"; finish; exit $?
fi
udp_listen() { local hex; hex="$(printf '%04X' "$1")"; cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk -v h=":$hex" '$2 ~ (h "$") { f = 1 } END { exit !f }'; }
if udp_listen 1812 || udp_listen 1813; then note "ports UDP 1812/1813 déjà utilisés : batterie ignorée"; finish; exit $?; fi
D="$T_TMP"; chmod 0755 "$D"; LAB="$D/lab"
mkdir -p "$D/tmp"; export TMPDIR="$D/tmp"   # fichiers temporaires de root (identification de « net », cache Kerberos) : on vérifie qu'aucun ne subsiste
bash "$ROOT/tests/samba-lab.sh" start "$LAB" >"$D/lab.out" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then note "annuaire d'essai indisponible ($(tail -n 1 "$D/lab.out")) : batterie ignorée"; finish; exit $?; fi
bash "$ROOT/tests/samba-lab.sh" extra "$LAB" >"$D/lab-extra.out" 2>&1 || { ko "annuaire d'essai : comptes supplémentaires" "$(tail -n 3 "$D/lab-extra.out")"; finish; exit $?; }

mkdir -p "$D/gen" "$D/run" "$D/state" "$D/bin" "$D/pki" "$D/runsamba"; chmod 0755 "$D/runsamba"
WB="$D/state/radius-winbind"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_RADIUS_DIR="$D/etc" DDI_RADIUS_LOCK="$D/lock" DDI_STATE_DIR="$D/state" DDI_RUN_DIR="$D/run" DDI_GENERATED_DIR="$D/gen"
export DDI_RADIUS_SYSTEMCTL="$D/bin/systemctl" DDI_FW_BIN="$D/bin/fw" DDI_RADIUS_COMPUTER="RADTEST01"
export DDI_RADIUS_AUTHLOG_DIR="$D/authlog" DDI_CONSOLE_GROUP=daemon
SELF="0123456789abcdef0123456789abcdef"; BINDPW='Passw0rd-svc-radius-1!'; ADMPW='Passw0rd-Lab-1!'
CSECRET="$(openssl rand -hex 16)"
rj() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d := d[k] for k in sys.argv[2].split(".")]; print(d)' "$1" "$2"; }

# faux systemctl : lance VRAIMENT freeradius et winbindd (même convention que b30, plus l'unité winbind)
cat > "$D/bin/systemctl" <<SH
#!/bin/bash
unit="\${@: -1}"
if [ "\$unit" = ddibuntu-radius-winbind.service ]; then
  P="$D/winbindd.pid"; alive() { [ -f "\$P" ] && kill -0 "\$(cat "\$P")" 2>/dev/null; }
  case "\$1" in
    daemon-reload|enable) exit 0 ;;
    restart|start) alive && { kill "\$(cat "\$P")"; sleep 1; }
                   ( KRB5_CONFIG="$WB/krb5.conf" setsid unshare -m --propagation private sh -c 'mount --bind "$D/runsamba" /run/samba && exec /usr/sbin/winbindd -F --no-process-group -s "$WB/smb.conf"' >"$D/winbindd.out" 2>&1 9>&- </dev/null & echo \$! > "\$P" ); sleep 3; exit 0 ;;
    disable|stop) alive && { kill "\$(cat "\$P")"; sleep 1; }; rm -f "\$P"; exit 0 ;;
    is-active) alive; exit \$? ;;
    *) exit 0 ;;
  esac
fi
P="$D/radiusd.pid"
alive() { [ -f "\$P" ] && kill -0 "\$(cat "\$P")" 2>/dev/null; }
case "\$1" in
  daemon-reload|enable) exit 0 ;;
  restart) [ -e "$D/failstart" ] && exit 1
           alive && { kill "\$(cat "\$P")"; sleep 0.5; }
           ( setsid unshare -m --propagation private sh -c 'mount --bind "$D/runsamba" /run/samba && exec /usr/sbin/freeradius -f -d "$D/etc"' >"$D/daemon.out" 2>&1 9>&- </dev/null & echo \$! > "\$P" ); sleep 2; exit 0 ;;
  disable) alive && kill "\$(cat "\$P")"; rm -f "\$P"; sleep 0.3; exit 0 ;;
  is-active) alive; exit \$? ;;
  is-enabled) exit 0 ;;
esac
SH
printf '#!/bin/bash\nexit 0\n' > "$D/bin/fw"; chmod +x "$D/bin/systemctl" "$D/bin/fw"
cleanup() {
  [ -n "${B40_HOLD:-}" ] && { echo "B40_HOLD : environnement conservé dans $D"; trap - EXIT; exit; }
  "$D/bin/systemctl" disable --now freeradius.service >/dev/null 2>&1; "$D/bin/systemctl" disable --now ddibuntu-radius-winbind.service >/dev/null 2>&1
  [ -n "${RELAY:-}" ] && kill "$RELAY" 2>/dev/null
  bash "$ROOT/tests/samba-lab.sh" stop "$LAB" >/dev/null 2>&1; rm -rf "$D"
}
trap cleanup EXIT

# un petit relais UDP donne au client « wifi-ctrl » l'adresse source 127.0.0.2 (FreeRADIUS reconnaît un client à son adresse)
cat > "$D/relay.py" <<'PY'
import select, socket, sys
port, src = int(sys.argv[1]), sys.argv[2]
f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); f.bind(("127.0.0.1", port))
peers, back = {}, {}
while True:
    r, _, _ = select.select([f] + list(back), [], [])
    for s in r:
        if s is f:
            d, a = f.recvfrom(65535)
            if a not in peers:
                b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.bind((src, 0)); b.connect(("127.0.0.1", 1812)); peers[a] = b; back[b] = a
            peers[a].send(d)
        else:
            f.sendto(s.recv(65535), back[s])
PY
python3 "$D/relay.py" 18121 127.0.0.2 >/dev/null 2>&1 9>&- </dev/null & RELAY=$!
CL="$D/clients.conf.in"
printf 'client "ddi-selftest" {\n\tipaddr = 127.0.0.1\n\tsecret = "%s"\n\tshortname = ddi-selftest\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n\nclient "wifi-ctrl" {\n\tipaddr = 10.1.0.2\n\tsecret = "%s"\n\tshortname = wifi-ctrl\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n' "$SELF" "$CSECRET" > "$CL"
localize() { sed -i 's/ipaddr = 10\.1\.0\./ipaddr = 127.0.0./' "$D/etc/clients.conf" && "$D/bin/systemctl" restart freeradius.service; }

echo "== PKI de test (openssl) =="
P="$D/pki"
pki_root "$P/root" "Lab Root CA"; pki_inter "$P/issuing" "$P/root" "Lab Issuing CA"
pki_issue "$P/issuing" "$P/srv" "radius.lab.test" server "DNS:radius.lab.test"
pki_crl "$P/issuing" "$P/crl.pem"
check "PKI de test fabriquée" test -s "$P/crl.pem"
LABCA="$LAB/private/tls/ca.pem"
DEP="$D/dep"; rm -rf "$DEP"; mkdir -p "$DEP/crl"
printf '{"checkCrl": true}\n' > "$DEP/pki.json"; cat "$P/root/ca.pem" "$P/issuing/ca.pem" > "$DEP/ca.pem"
cat "$P/srv.pem" "$P/issuing/ca.pem" > "$DEP/server.pem"; cp "$P/srv.key" "$DEP/server.key"; cp "$P/crl.pem" "$DEP/crl/issuing.pem"

# règles : membres de grp-wifi (alice, dave par imbrication) → VLAN 120 ; tout le reste est refusé par défaut
RJ="$D/rules.json"
cat > "$RJ" <<'JSON'
{"rules":[{"name":"Wi-Fi","action":"accept","kind":"user","groups":["CN=grp-wifi,CN=Users,DC=lab,DC=test"],"reply":{"vlan":120,"sessionTimeout":3600}}]}
JSON
mkaz() {   # mkaz DIR [auth.json] : dépôt des règles de la console
  rm -rf "$1"; mkdir -p "$1"; cp "$RJ" "$1/rules.json"
  printf '{"urls":["ldaps://dc1.lab.test"],"baseDn":"DC=lab,DC=test","bindDn":"svc-radius@lab.test","bindPassword":"%s","tlsRejectUnauthorized":true}\n' "$BINDPW" > "$1/ldap.json"
  cp "$LABCA" "$1/ldap-ca.pem"
  [ -n "${2:-}" ] && printf '%s\n' "$2" > "$1/auth.json"
  chmod 0600 "$1"/*
}
mkjoin() {   # mkjoin DIR [user] [password] : dépôt de la jonction
  rm -rf "$1"; mkdir -p "$1"
  printf '{"realm":"lab.test","netbios":"LAB","servers":["dc1.lab.test"],"user":"%s","password":"%s"}\n' "${2:-Administrator}" "${3:-$ADMPW}" > "$1/join.json"; chmod 0600 "$1/join.json"
}
AZ="$D/az"

echo "== Validation stricte de auth.json (aucune écriture) =="
mkaz "$AZ" '{"peap":true,"ttls":true,"netbios":"LAB"}'
check "dépôt conforme accepté" "$RAD" check-authz "$AZ" "$CL"
bad() {   # bad "nom" 'contenu auth.json'
  mkaz "$D/azbad" "$2"; check_fail "$1" "$RAD" check-authz "$D/azbad" "$CL"
}
bad "méthode inconnue refusée"                  '{"peap":true,"pap":true}'
bad "peap non booléen refusé"                   '{"peap":"oui"}'
bad "ttls non booléen refusé"                   '{"ttls":1}'
bad "NetBIOS avec espace refusé"                '{"ttls":true,"netbios":"MON DOMAINE"}'
bad "NetBIOS trop long refusé"                  '{"ttls":true,"netbios":"ABCDEFGHIJKLMNOP"}'
bad "NetBIOS avec guillemet refusé"             '{"ttls":true,"netbios":"A\"B"}'
bad "auth.json illisible refusé"                'pas du json'
mkaz "$D/azbad" '{"ttls":true}'; ln -sf /etc/passwd "$D/azbad/extra"; check_fail "fichier inattendu refusé" "$RAD" check-authz "$D/azbad" "$CL"

echo "== Dépôt de jonction : validation stricte =="
jbad() {   # jbad "nom" 'code python modifiant d'
  local d="$D/jbad"; mkjoin "$d"
  python3 - "$d/join.json" "$2" <<'PY' || { ko "$1 (préparation)" "script de modification en échec"; return; }
import json, sys
f, code = sys.argv[1], sys.argv[2]
d = json.load(open(f)); exec(code); json.dump(d, open(f, "w"))
PY
  check_fail "$1" "$RAD" join "$d"
}
jbad "royaume sans point refusé"                'd["realm"] = "lab"'
jbad "royaume avec espace refusé"               'd["realm"] = "lab test"'
jbad "NetBIOS vide refusé"                      'd["netbios"] = ""'
jbad "serveur avec point-virgule refusé"        'd["servers"] = ["dc1;rm"]'
jbad "aucun serveur refusé"                     'd["servers"] = []'
jbad "serveurs en double refusés"               'd["servers"] = ["dc1.lab.test", "dc1.lab.test"]'
jbad "champ inconnu refusé"                     'd["exec"] = "x"'
jbad "compte avec « % » refusé"                 'd["user"] = "a%b"'
jbad "mot de passe avec saut de ligne refusé"   'd["password"] = "a\nb"'
jbad "mot de passe absent refusé"               'del d["password"]'
mkjoin "$D/jbad"; ln -sf /etc/passwd "$D/jbad/extra"; check_fail "fichier inattendu dans la jonction refusé" "$RAD" join "$D/jbad"
expect_eq "…aucune jonction n'a été enregistrée" no "$([ -e "$WB/joined.json" ] && echo yes || echo no)"

echo "== Déploiement : PEAP demandé mais appliance non jointe =="
mkaz "$AZ" '{"peap":true,"ttls":true,"netbios":"LAB"}'
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply1.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply : code 0" || ko "apply : code 0" "$(tail -n 5 "$D/apply1.out" | tr '\n' ' ')"
expect_grep "message : PEAP non activé faute de jonction" "AVERTISSEMENT : PEAP-MSCHAPv2 demandé mais cette appliance n'est pas jointe" "$D/apply1.out"
expect_grep "message : TTLS actif" "Identifiant et mot de passe : TTLS" "$D/apply1.out"
expect_nogrep "aucun module mschap installé" "mschap" <(ls "$D/etc/mods-enabled")
expect_grep "le module eap porte TTLS" "ttls \{" "$D/etc/mods-enabled/eap"
expect_nogrep "…et pas PEAP" "peap \{" "$D/etc/mods-enabled/eap"
expect_grep "le serveur « tunnel » est dans le site" "server ddibuntu-inner" "$D/etc/sites-available/ddibuntu"
check "le démon, EN TANT QUE freerad, lit toute l'arborescence" runuser -u freerad -- /usr/sbin/freeradius -d "$D/etc" -Cx -lstdout
localize
expect_nogrep "le démon ne signale aucune erreur de configuration" 'Error:|Failed to' "$D/daemon.out"
RLOG="$D/authlog/radius.log"; AL="$D/authlog/radius-auth.log"
mac="AA-BB-CC-DD-EE-FF"
pw_auth() {   # pw_auth PEAP|TTLS IDENTIFIANT MOT_DE_PASSE : sortie d'eapol_test
  local m="$1" id="$2" pw="$3" cf; cf="$(mktemp "$D/pw.XXXXXX")"
  { echo 'network={'; echo ' key_mgmt=WPA-EAP'
    if [ "$m" = PEAP ]; then echo ' eap=PEAP'; echo ' phase2="auth=MSCHAPV2"'; else echo ' eap=TTLS'; echo ' phase2="auth=PAP"'; fi
    echo " identity=\"$id\""; echo " password=\"$pw\""; echo " ca_cert=\"$P/root/ca.pem\""; echo '}'; } > "$cf"
  eapol_test -c "$cf" -a 127.0.0.1 -p 18121 -s "$CSECRET" -t "${ET:-15}" -N "30:s:$mac:CorpWifi" 2>&1; rm -f "$cf"
}
verdict() { grep -q 'SUCCESS' "$1" && echo accept || echo reject; }
t() {   # t "nom" attendu(accept|reject) méthode identifiant mot_de_passe
  local out="$D/t.out"; pw_auth "$3" "$4" "$5" > "$out"
  expect_eq "$1" "$2" "$(verdict "$out")"
}
t "TTLS/PAP : alice (groupes imbriqués) acceptée"                  accept TTLS 'LAB\alice' 'Passw0rd-alice-1!'
grep -q 'Tunnel-Private-Group' "$D/t.out" && ok "…le VLAN de la règle est dans l'Access-Accept" || ko "…le VLAN de la règle est dans l'Access-Accept" "$(grep -i 'attr\|vlan\|Tunnel' "$D/t.out" | head -n 3 | tr '\n' ' ')"
t "PEAP : refusé tant que non joint (méthode inconnue du serveur)"  reject PEAP 'LAB\alice' 'Passw0rd-alice-1!'

echo "== Jonction réelle au domaine =="
mkjoin "$D/jn"
"$RAD" join "$D/jn" >"$D/join.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "join : code 0" || ko "join : code 0" "$(tail -n 6 "$D/join.out" | tr '\n' ' ')"
expect_grep "message : jointe, compte machine nommé" "Appliance jointe au domaine lab.test \(compte machine RADTEST01\)" "$D/join.out"
check "joined.json écrit" test -s "$WB/joined.json"
expect_eq "…royaume et NetBIOS enregistrés" "lab.test LAB" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["realm"], d["netbios"])' "$WB/joined.json")"
expect_eq "…le secret du compte machine reste privé (dossier 0700 root)" "700 root" "$(stat -c '%a %U' "$WB/private")"
check "secrets.tdb créé" test -e "$WB/private/secrets.tdb"
expect_nogrep "mot de passe du compte de jonction : absent de la sortie" "$(printf '%s' "$ADMPW" | sed 's/[][\.*^$/]/\\&/g')" "$D/join.out"
expect_eq "…aucun fichier d'identification ni cache Kerberos ne subsiste" "" "$(find "$D/tmp" -mindepth 1 2>/dev/null)"
expect_nogrep "…le mot de passe n'est dans aucun fichier d'état" "$(printf '%s' "$ADMPW" | sed 's/[][\.*^$/]/\\&/g')" <(grep -rI "" "$WB/joined.json" "$WB/smb.conf" "$WB/krb5.conf")
expect_eq "statut publié : jonction connue" True "$(rj "$D/run/radius-status.json" winbind.joined)"

echo "== Déploiement : PEAP-MSCHAPv2 activé =="
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply2.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply : code 0" || ko "apply : code 0" "$(tail -n 5 "$D/apply2.out" | tr '\n' ' ')"
expect_grep "message : PEAP et TTLS actifs" "Identifiant et mot de passe : PEAP, TTLS" "$D/apply2.out"
expect_nogrep "…plus d'avertissement de jonction" "AVERTISSEMENT" "$D/apply2.out"
expect_eq "module mschap : 0640 root:freerad" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/mods-enabled/mschap")"
check "winbindd tourne" "$D/bin/systemctl" is-active --quiet ddibuntu-radius-winbind.service
check "le canal privilégié de winbindd est ouvert au groupe freerad" test "$(stat -c '%G %a' "$WB/state/winbindd_privileged")" = "freerad 750"
check "le démon, EN TANT QUE freerad, lit toute l'arborescence" runuser -u freerad -- /usr/sbin/freeradius -d "$D/etc" -Cx -lstdout
localize
expect_nogrep "le démon ne signale aucune erreur de configuration" 'Error:|Failed to' "$D/daemon.out"
[ "${B40_PAUSE:-}" = peap ] && { B40_HOLD=1; exit 0; }   # mise au point : s'arrête ici, tout reste en place
t "PEAP-MSCHAPv2 : alice acceptée"                                accept PEAP 'LAB\alice' 'Passw0rd-alice-1!'
grep -q 'Tunnel-Private-Group' "$D/t.out" && ok "…le VLAN de la règle est dans l'Access-Accept (PEAP)" || ko "…le VLAN de la règle est dans l'Access-Accept (PEAP)" "$(grep -iE 'Tunnel|Reply|attr' "$D/t.out" | head -n 4 | tr '\n' ' ')"
t "PEAP : UPN accepté"                                            accept PEAP 'alice@lab.test' 'Passw0rd-alice-1!'
t "PEAP : compte seul accepté"                                    accept PEAP 'alice' 'Passw0rd-alice-1!'
t "PEAP : casse du domaine et du compte indifférente"             accept PEAP 'lab\ALICE' 'Passw0rd-alice-1!'
t "TTLS/PAP : UPN accepté"                                        accept TTLS 'alice@lab.test' 'Passw0rd-alice-1!'
t "TTLS/PAP : compte seul accepté"                                accept TTLS 'alice' 'Passw0rd-alice-1!'
t "PEAP : mauvais mot de passe refusé"                            reject PEAP 'LAB\alice' 'faux-mot-de-passe'
t "TTLS/PAP : mauvais mot de passe refusé"                        reject TTLS 'LAB\alice' 'faux-mot-de-passe'
t "PEAP : alice acceptée de nouveau (le compteur d'échecs repart à zéro)" accept PEAP 'LAB\alice' 'Passw0rd-alice-1!'
t "PEAP : compte désactivé refusé (bon mot de passe)"             reject PEAP 'LAB\bob' 'Passw0rd-bob-1!'
t "TTLS/PAP : compte désactivé refusé (bon mot de passe)"         reject TTLS 'LAB\bob' 'Passw0rd-bob-1!'
t "PEAP : compte expiré refusé (bon mot de passe)"                reject PEAP 'LAB\carol' 'Passw0rd-carol-1!'
t "PEAP : compte verrouillé refusé (bon mot de passe)"            reject PEAP 'LAB\dave' 'Passw0rd-dave-1!'
t "PEAP : compte sans règle refusé par défaut (bon mot de passe)" reject PEAP 'LAB\erin' 'Passw0rd-erin-1!'
t "TTLS/PAP : compte sans règle refusé par défaut"                reject TTLS 'LAB\erin' 'Passw0rd-erin-1!'
t "PEAP : compte inconnu refusé"                                  reject PEAP 'LAB\personne' 'x'
t "PEAP : domaine étranger refusé"                                reject PEAP 'AUTRE\alice' 'Passw0rd-alice-1!'
t "TTLS/PAP : domaine étranger refusé"                            reject TTLS 'AUTRE\alice' 'Passw0rd-alice-1!'
t "PEAP : identifiant avec caractères refusés"                    reject PEAP 'alice;ls' 'x'
t "TTLS/PAP : identifiant avec espace refusé"                     reject TTLS 'alice bob' 'x'
t "TTLS/PAP : mot de passe vide refusé"                           reject TTLS 'LAB\alice' ''

echo "== Journal =="
sleep 1
check "journal des authentifications écrit" test -s "$AL"
expect_grep "…acceptation d'alice journalisée avec la règle" '^v1\|[0-9]+\|accept\|.*regle 1 : Wi-Fi' "$AL"
expect_grep "…refus du compte désactivé : raison explicite" 'compte=desactive|compte desactive' "$AL"
expect_grep "…refus du compte verrouillé : raison explicite" 'compte verrouille' "$AL"
expect_grep "…refus du compte expiré : raison explicite" 'compte expire' "$AL"
expect_grep "…refus par défaut : raison explicite" 'aucune regle ne correspond' "$AL"
expect_grep "…domaine étranger : raison explicite" 'domaine inconnu' "$AL"
expect_nogrep "…aucun mot de passe dans le journal" 'Passw0rd' "$AL"
expect_nogrep "…ni dans le journal du démon" 'Passw0rd' "$RLOG"

echo "== Sans méthode par mot de passe : EAP-TLS seulement =="
mkaz "$AZ"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply3.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply sans auth.json : code 0" || ko "apply sans auth.json : code 0" "$(tail -n 5 "$D/apply3.out" | tr '\n' ' ')"
expect_nogrep "…aucune mention de méthode par mot de passe" "Identifiant et mot de passe" "$D/apply3.out"
expect_nogrep "…plus de module mschap" "mschap" <(ls "$D/etc/mods-enabled")
expect_nogrep "…plus de PEAP ni de TTLS dans eap" "peap \{|ttls \{" "$D/etc/mods-enabled/eap"
expect_nogrep "…plus de serveur tunnel" "server ddibuntu-inner" "$D/etc/sites-available/ddibuntu"
check_fail "…winbindd est arrêté" "$D/bin/systemctl" is-active --quiet ddibuntu-radius-winbind.service
localize
t "TTLS/PAP : refusé (méthode non activée)"                       reject TTLS 'LAB\alice' 'Passw0rd-alice-1!'
t "PEAP : refusé (méthode non activée)"                           reject PEAP 'LAB\alice' 'Passw0rd-alice-1!'

echo "== TTLS seul, sans jonction nécessaire =="
mkaz "$AZ" '{"ttls":true,"netbios":"LAB"}'
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply4.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply TTLS seul : code 0" || ko "apply TTLS seul : code 0" "$(tail -n 5 "$D/apply4.out" | tr '\n' ' ')"
expect_nogrep "…pas de module mschap" "mschap" <(ls "$D/etc/mods-enabled")
check_fail "…winbindd reste arrêté" "$D/bin/systemctl" is-active --quiet ddibuntu-radius-winbind.service
localize
t "TTLS/PAP : alice acceptée"                                     accept TTLS 'LAB\alice' 'Passw0rd-alice-1!'
t "PEAP : refusé"                                                 reject PEAP 'LAB\alice' 'Passw0rd-alice-1!'

echo "== Retrait de la jonction =="
"$RAD" leave >"$D/leave.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "leave : code 0" || ko "leave : code 0" "$(tail -n 4 "$D/leave.out" | tr '\n' ' ')"
check_fail "…joined.json supprimé" test -e "$WB/joined.json"
check_fail "…secrets.tdb supprimé" test -e "$WB/private/secrets.tdb"
expect_grep "…le message prévient que le compte machine reste dans l'annuaire" "Le compte machine reste dans l'annuaire" "$D/leave.out"

finish
