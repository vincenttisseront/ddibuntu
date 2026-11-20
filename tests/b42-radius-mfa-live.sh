#!/usr/bin/env bash
# Batterie 42 — MFA par client RADIUS (0.17.0) : ddibuntu-radius contre un VRAI FreeRADIUS (module REST), un VRAI Samba AD (tests/samba-lab.sh) et un FAUX fournisseur
# MFA en HTTPS (point de jeton OAuth2 « mot de passe » + code TOTP, vrais codes RFC 6238), joué par un vrai client PAP (radclient) et un vrai client EAP (eapol_test).
# Couvre : validation stricte du dépôt (mfa.json, mfa-ca.pem, directive virtual_server), refus d'un client MFA sans fournisseur, déploiement (module REST 0640, secret
# client jamais affiché), PAP + code accepté / mauvais code / mauvais mot de passe / code absent ou mal formé, décision d'accès AVANT le fournisseur (compte désactivé,
# verrouillé, expiré, sans règle, inconnu : le fournisseur n'est JAMAIS appelé), identité envoyée (saisie ou compte), caractères spéciaux du mot de passe, fournisseur en
# panne / lent / en erreur / certificat inconnu, EAP et CHAP refusés sur un client MFA, autre client inchangé, 20 requêtes simultanées, mot de passe et code absents des
# journaux, retrait du MFA (module effacé).
# Prérequis : root, freeradius + freeradius-ldap + freeradius-rest, radclient, eapol_test, openssl, python3, samba (voir samba-lab.sh) ; sinon la batterie est ignorée.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=lib-pki.sh
. "$(dirname "$0")/lib-pki.sh"

RAD="$RFS/usr/local/sbin/ddibuntu-radius"
for t in freeradius radclient eapol_test openssl python3; do
  command -v "$t" >/dev/null || { note "prérequis absents ($t) : batterie ignorée"; finish; exit $?; }
done
if [ "$(id -u)" -ne 0 ] || [ ! -e /usr/lib/freeradius/rlm_ldap.so ] || [ ! -e /usr/lib/freeradius/rlm_rest.so ] || ! id freerad >/dev/null 2>&1; then
  note "prérequis absents (root, freeradius-ldap, freeradius-rest, utilisateur freerad) : batterie ignorée"; finish; exit $?
fi
udp_listen() { local hex; hex="$(printf '%04X' "$1")"; cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk -v h=":$hex" '$2 ~ (h "$") { f = 1 } END { exit !f }'; }
if udp_listen 1812 || udp_listen 1813; then note "ports UDP 1812/1813 déjà utilisés : batterie ignorée"; finish; exit $?; fi
D="$T_TMP"; chmod 0755 "$D"; LAB="$D/lab"
mkdir -p "$D/tmp"; export TMPDIR="$D/tmp"
bash "$ROOT/tests/samba-lab.sh" start "$LAB" >"$D/lab.out" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then note "annuaire d'essai indisponible ($(tail -n 1 "$D/lab.out")) : batterie ignorée"; finish; exit $?; fi
bash "$ROOT/tests/samba-lab.sh" extra "$LAB" >"$D/lab-extra.out" 2>&1 || { ko "annuaire d'essai : comptes supplémentaires" "$(tail -n 3 "$D/lab-extra.out")"; finish; exit $?; }

mkdir -p "$D/gen" "$D/run" "$D/state" "$D/bin" "$D/pki" "$D/runsamba"; chmod 0755 "$D/runsamba"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_RADIUS_DIR="$D/etc" DDI_RADIUS_LOCK="$D/lock" DDI_STATE_DIR="$D/state" DDI_RUN_DIR="$D/run" DDI_GENERATED_DIR="$D/gen"
export DDI_RADIUS_SYSTEMCTL="$D/bin/systemctl" DDI_FW_BIN="$D/bin/fw"
export DDI_RADIUS_AUTHLOG_DIR="$D/authlog" DDI_CONSOLE_GROUP=daemon
SELF="0123456789abcdef0123456789abcdef"; BINDPW='Passw0rd-svc-radius-1!'
CSECRET="$(openssl rand -hex 16)"; VSECRET="$(openssl rand -hex 20)"   # secrets partagés : client Wi-Fi, pare-feu VPN (40 caractères)

# faux systemctl : lance VRAIMENT freeradius (même convention que b30 / b40)
cat > "$D/bin/systemctl" <<SH
#!/bin/bash
P="$D/radiusd.pid"
alive() { [ -f "\$P" ] && kill -0 "\$(cat "\$P")" 2>/dev/null; }
case "\$1" in
  daemon-reload|enable) exit 0 ;;
  restart) alive && { kill "\$(cat "\$P")"; sleep 0.5; }
           ( setsid unshare -m --propagation private sh -c 'mount --bind "$D/runsamba" /run/samba && exec /usr/sbin/freeradius -f -d "$D/etc"' >"$D/daemon.out" 2>&1 9>&- </dev/null & echo \$! > "\$P" ); sleep 2; exit 0 ;;
  disable) alive && kill "\$(cat "\$P")"; rm -f "\$P"; sleep 0.3; exit 0 ;;
  is-active) alive; exit \$? ;;
  is-enabled) exit 0 ;;
esac
SH
printf '#!/bin/bash\nexit 0\n' > "$D/bin/fw"; chmod +x "$D/bin/systemctl" "$D/bin/fw"
cleanup() {
  [ -n "${B42_HOLD:-}" ] && { echo "B42_HOLD : environnement conservé dans $D"; trap - EXIT; exit; }
  "$D/bin/systemctl" disable --now freeradius.service >/dev/null 2>&1
  [ -n "${RELAY:-}" ] && kill "$RELAY" 2>/dev/null; [ -n "${RELAY2:-}" ] && kill "$RELAY2" 2>/dev/null; [ -n "${IDP:-}" ] && kill "$IDP" 2>/dev/null
  bash "$ROOT/tests/samba-lab.sh" stop "$LAB" >/dev/null 2>&1; rm -rf "$D"
}
trap cleanup EXIT

# relais UDP : donne au client « wifi-ctrl » l'adresse source 127.0.0.2 et au client « fw-vpn » 127.0.0.3
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
python3 "$D/relay.py" 18122 127.0.0.3 >/dev/null 2>&1 9>&- </dev/null & RELAY2=$!

# faux fournisseur : point de jeton OAuth2 (grant_type=password) + code TOTP RFC 6238 (SHA-1, 6 chiffres, 30 s, fenêtre ±1). Le mode (fichier idp.mode) change son comportement.
cat > "$D/idp.py" <<'PY'
import base64, hashlib, hmac, http.server, json, os, ssl, struct, sys, time, urllib.parse
D = sys.argv[1]
USERS = {"alice": (["Passw0rd-alice-1!", "p&a=s%+x{1}%{2}$y z"], "JBSWY3DPEHPK3PXP"), "erin": (["Passw0rd-erin-1!"], "KRSXG5CTMVRXEZLU")}
def totp(secret, t):
    k = base64.b32decode(secret); h = hmac.new(k, struct.pack(">Q", t // 30), hashlib.sha1).digest(); o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
        f = {k: v[0] for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()}
        mode = open(os.path.join(D, "idp.mode")).read().strip() if os.path.exists(os.path.join(D, "idp.mode")) else "ok"
        open(os.path.join(D, "idp.log"), "a").write(json.dumps({"path": self.path, "ctype": self.headers.get("Content-Type"), "fields": f}) + "\n")
        if mode == "slow": time.sleep(12)
        code, out = 401, {"error": "invalid_grant"}
        if mode == "500": code, out = 500, {"error": "server_error"}
        elif mode == "400": code, out = 400, {"error": "invalid_grant"}
        elif mode == "200vide": code, out = 200, {"error": "invalid_grant", "note": "un 2xx sans jeton d'acces"}
        elif mode == "ok":
            u = f.get("username"); pw = f.get("password"); otp = f.get("totp")
            if f.get("grant_type") == "password" and f.get("client_id") == "ddi-radius" and f.get("client_secret") == sys.argv[2] and u in USERS and pw in USERS[u][0]:
                now = int(time.time())
                if otp in [totp(USERS[u][1], now + d) for d in (-30, 0, 30)]: code, out = 200, {"access_token": "AAA.BBB.CCC", "token_type": "Bearer", "reply:Reply-Message": {"value": ["injecte"]}}
        b = json.dumps(out).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(http.server.ThreadingHTTPServer): daemon_threads = True
s = S(("127.0.0.1", int(sys.argv[3])), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[4], sys.argv[5]); s.socket = c.wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)   # la poignée de main se fait dans le fil de la requête : une connexion à vide (sonde du module REST) ne bloque pas l'écoute
s.serve_forever()
PY
cat > "$D/totp.py" <<'PY'
import base64, hashlib, hmac, struct, sys, time
k = base64.b32decode(sys.argv[1]); t = int(time.time()) + int(sys.argv[2] if len(sys.argv) > 2 else 0)
h = hmac.new(k, struct.pack(">Q", t // 30), hashlib.sha1).digest(); o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))
PY
ALICE_SECRET=JBSWY3DPEHPK3PXP; ERIN_SECRET=KRSXG5CTMVRXEZLU
code() { python3 "$D/totp.py" "$1" "${2:-0}"; }

echo "== PKI de test (openssl) : EAP-TLS du site, certificat du fournisseur =="
P="$D/pki"
pki_root "$P/root" "Lab Root CA"; pki_inter "$P/issuing" "$P/root" "Lab Issuing CA"
pki_issue "$P/issuing" "$P/srv" "radius.lab.test" server "DNS:radius.lab.test"
pki_issue "$P/issuing" "$P/idp" "localhost" server "DNS:localhost"
pki_root "$P/other" "Autre CA"          # une autre autorité : le fournisseur ne doit pas être reconnu avec elle
pki_crl "$P/issuing" "$P/crl.pem"
check "PKI de test fabriquée" test -s "$P/idp.pem"
cat "$P/idp.pem" "$P/issuing/ca.pem" > "$P/idp-chain.pem"
LABCA="$LAB/private/tls/ca.pem"
DEP="$D/dep"; rm -rf "$DEP"; mkdir -p "$DEP/crl"
printf '{"checkCrl": true}\n' > "$DEP/pki.json"; cat "$P/root/ca.pem" "$P/issuing/ca.pem" > "$DEP/ca.pem"
cat "$P/srv.pem" "$P/issuing/ca.pem" > "$DEP/server.pem"; cp "$P/srv.key" "$DEP/server.key"; cp "$P/crl.pem" "$DEP/crl/issuing.pem"
IDPSECRET='abcDEF123-._~xyz'; IDPPORT=18443
echo ok > "$D/idp.mode"; : > "$D/idp.log"
python3 "$D/idp.py" "$D" "$IDPSECRET" "$IDPPORT" "$P/idp-chain.pem" "$P/idp.key" >"$D/idp.out" 2>&1 9>&- </dev/null & IDP=$!
sleep 1; check "le faux fournisseur écoute en HTTPS" curl -sS --cacert "$P/root/ca.pem" -o /dev/null -X POST "https://localhost:$IDPPORT/realms/corp/protocol/openid-connect/token" -d x=1 -w ''

# clients : le client d'essai, le contrôleur Wi-Fi (EAP) et le pare-feu VPN (client MFA)
CL="$D/clients.conf.in"
cl_conf() {   # cl_conf [MFA] : MFA = marque « fw-vpn » comme client MFA
  printf 'client "ddi-selftest" {\n\tipaddr = 127.0.0.1\n\tsecret = "%s"\n\tshortname = ddi-selftest\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n\n' "$SELF"
  printf 'client "wifi-ctrl" {\n\tipaddr = 10.1.0.2\n\tsecret = "%s"\n\tshortname = wifi-ctrl\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n\n' "$CSECRET"
  printf 'client "fw-vpn" {\n\tipaddr = 10.1.0.3\n\tsecret = "%s"\n\tshortname = fw-vpn\n\trequire_message_authenticator = yes\n\tnas_type = other\n' "$VSECRET"
  [ "${1:-}" = MFA ] && printf '\tvirtual_server = ddibuntu-mfa\n'
  printf '}\n'
}
cl_conf MFA > "$CL"
localize() { sed -i 's/ipaddr = 10\.1\.0\./ipaddr = 127.0.0./' "$D/etc/clients.conf" && "$D/bin/systemctl" restart freeradius.service; }

# règles : le VPN accepte les membres de grp-vpn (alice) et rend un Filter-Id ; le Wi-Fi accepte grp-wifi sur le contrôleur Wi-Fi seulement
RJ="$D/rules.json"
cat > "$RJ" <<'JSON'
{"rules":[{"name":"VPN","action":"accept","kind":"user","groups":["CN=grp-vpn,CN=Users,DC=lab,DC=test"],"nas":["fw-vpn"],"reply":{"filterId":"vpn-users"}},
{"name":"Wi-Fi","action":"accept","kind":"user","groups":["CN=grp-wifi,CN=Users,DC=lab,DC=test"],"nas":["wifi-ctrl"],"reply":{"vlan":120}}]}
JSON
mfajson() {   # mfajson [JSON] : mfa.json par défaut
  cat <<JSON
{"type":"oauth2_password","tokenUrl":"https://localhost:$IDPPORT/realms/corp/protocol/openid-connect/token","clientId":"ddi-radius","clientSecret":"$IDPSECRET","fields":{"identity":"username","password":"password","otp":"totp"},"identity":"account","otpDigits":6,"extra":[{"name":"scope","value":"openid profile"}],"timeoutSec":3,"tlsVerify":true}
JSON
}
mkaz() {   # mkaz DIR [mfa.json] [pem CA du fournisseur] : dépôt des règles de la console
  rm -rf "$1"; mkdir -p "$1"; cp "$RJ" "$1/rules.json"
  printf '{"urls":["ldaps://dc1.lab.test"],"baseDn":"DC=lab,DC=test","bindDn":"svc-radius@lab.test","bindPassword":"%s","tlsRejectUnauthorized":true}\n' "$BINDPW" > "$1/ldap.json"
  cp "$LABCA" "$1/ldap-ca.pem"
  [ -n "${2:-}" ] && printf '%s\n' "$2" > "$1/mfa.json"
  [ -n "${3:-}" ] && cp "$3" "$1/mfa-ca.pem"
  chmod 0600 "$1"/*
}
AZ="$D/az"; MCA="$D/mfa-ca.in"; cat "$P/root/ca.pem" > "$MCA"

echo "== Validation stricte du dépôt MFA (aucune écriture) =="
mkaz "$AZ" "$(mfajson)" "$MCA"
check "dépôt conforme accepté" "$RAD" check-authz "$AZ" "$CL"
"$RAD" check-authz "$AZ" "$CL" > "$D/chk.out" 2>&1
expect_grep "…le serveur MFA est généré" "^server ddibuntu-mfa \{" "$D/chk.out"
expect_grep "…le module REST est généré" "^rest ddibuntu_mfa \{" "$D/chk.out"
expect_nogrep "…le secret client n'est pas affiché par « check-authz »" "$(printf '%s' "$IDPSECRET" | sed 's/[][\.*^$/~]/\\&/g')" "$D/chk.out"
expect_grep "…le formulaire porte les champs, le code et le paramètre supplémentaire" 'username=%\{urlquote:.*totp=%\{urlquote:.*scope=openid\+profile' "$D/chk.out"
expect_grep "…le certificat du fournisseur est vérifié (check_cert et nom d'hôte)" "check_cert = yes" "$D/chk.out"
bad() {   # bad "nom" 'code python modifiant d (mfa.json)'
  local d="$D/azbad"; mkaz "$d" "$(mfajson)" "$MCA"
  python3 - "$d/mfa.json" "$2" <<'PY' || { ko "$1 (préparation)" "script de modification en échec"; return; }
import json, sys
f, code = sys.argv[1], sys.argv[2]
d = json.load(open(f)); exec(code); json.dump(d, open(f, "w"))
PY
  check_fail "$1" "$RAD" check-authz "$d" "$CL"
}
bad "champ inconnu refusé"                          'd["exec"] = "x"'
bad "type de fournisseur inconnu refusé"            'd["type"] = "ldap"'
bad "adresse en http refusée"                       'd["tokenUrl"] = "http://localhost/token"'
bad "adresse avec paramètres refusée"               'd["tokenUrl"] += "?a=b"'
bad "adresse sans chemin ni hôte refusée"           'd["tokenUrl"] = "https://"'
bad "adresse avec « % » refusée"                    'd["tokenUrl"] += "/%7B"'
bad "port hors limites refusé"                      'd["tokenUrl"] = "https://localhost:70000/t"'
bad "identifiant client avec « & » refusé"          'd["clientId"] = "a&b"'
bad "secret client avec « % » refusé"               'd["clientSecret"] = "ab%25cd"'
bad "secret client avec guillemet refusé"           'd["clientSecret"] = "ab\"cd"'
bad "nom de champ avec espace refusé"               'd["fields"]["otp"] = "to tp"'
bad "noms de champs en double refusés"              'd["fields"]["otp"] = "username"'
bad "champ réservé refusé (grant_type)"             'd["fields"]["identity"] = "grant_type"'
bad "identité inconnue refusée"                     'd["identity"] = "upn"'
bad "code à 7 chiffres refusé"                      'd["otpDigits"] = 7'
bad "délai de 1 s refusé"                           'd["timeoutSec"] = 1'
bad "délai de 60 s refusé"                          'd["timeoutSec"] = 60'
bad "tlsVerify non booléen refusé"                  'd["tlsVerify"] = "oui"'
bad "tlsVerify absent refusé"                       'del d["tlsVerify"]'
bad "six paramètres supplémentaires refusés"        'd["extra"] = [{"name": "p%d" % i, "value": "x"} for i in range(6)]'
bad "paramètre supplémentaire réservé refusé"       'd["extra"] = [{"name": "client_id", "value": "x"}]'
bad "valeur supplémentaire avec « & » refusée"      'd["extra"] = [{"name": "scope", "value": "a&b=c"}]'
bad "paramètre supplémentaire mal formé refusé"     'd["extra"] = [{"name": "scope"}]'
mkaz "$D/azbad" "$(mfajson)"; printf 'pas un certificat\n' > "$D/azbad/mfa-ca.pem"; check_fail "mfa-ca.pem illisible refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad" "$(mfajson)" "$MCA"; ln -sf /etc/passwd "$D/azbad/extra"; check_fail "fichier inattendu refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; check_fail "client MFA sans fournisseur refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad" "$(mfajson)" "$MCA"; cl_conf > "$D/cl-nomfa.in"
check "fournisseur déposé sans client MFA : accepté, rien n'est généré" "$RAD" check-authz "$D/azbad" "$D/cl-nomfa.in"
"$RAD" check-authz "$D/azbad" "$D/cl-nomfa.in" > "$D/chk2.out" 2>&1
expect_nogrep "…aucun serveur MFA" "ddibuntu-mfa" "$D/chk2.out"
sed 's/virtual_server = ddibuntu-mfa/virtual_server = autre/' "$CL" > "$D/cl-bad.in"; check_fail "directive virtual_server étrangère refusée" "$RAD" check "$D/cl-bad.in"
python3 - "$CL" "$D/cl-self.in" <<'PY'
import sys
s = open(sys.argv[1]).read().replace('shortname = ddi-selftest\n', 'shortname = ddi-selftest\n\tvirtual_server = ddibuntu-mfa\n', 1)
open(sys.argv[2], "w").write(s)
PY
check_fail "le client d'essai ne peut pas être un client MFA" "$RAD" check "$D/cl-self.in"
check "fichier de clients conforme accepté" "$RAD" check "$CL"

echo "== Déploiement avec un client MFA =="
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply1.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply : code 0" || ko "apply : code 0" "$(tail -n 5 "$D/apply1.out" | tr '\n' ' ')"
expect_grep "message : client MFA nommé" "Clients MFA \(mot de passe \+ code\) : fw-vpn" "$D/apply1.out"
expect_eq "module REST : 0640 root:freerad" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/mods-enabled/ddibuntu_mfa")"
expect_eq "CA du fournisseur : dossier haché (ca_path), fichiers 0640 root:freerad" "750 root freerad 640 root freerad" "$(stat -c '%a %U %G' "$D/etc/certs/mfa-ca") $(stat -c '%a %U %G' "$D/etc/certs/mfa-ca/01.pem")"
expect_grep "le serveur MFA est dans le site" "^server ddibuntu-mfa" "$D/etc/sites-available/ddibuntu"
expect_grep "la directive du client est conservée" "virtual_server = ddibuntu-mfa" "$D/etc/clients.conf"
check "le démon, EN TANT QUE freerad, lit toute l'arborescence" runuser -u freerad -- /usr/sbin/freeradius -d "$D/etc" -Cx -lstdout
localize
expect_nogrep "le démon ne signale aucune erreur de configuration" 'Error:|Failed to' "$D/daemon.out"
AL="$D/authlog/radius-auth.log"; RLOG="$D/authlog/radius.log"
calls() { wc -l < "$D/idp.log" | tr -d ' '; }
pap() {   # pap CLIENT USER MOTDEPASSE [attributs] : requête PAP avec Message-Authenticator ; CLIENT = vpn (127.0.0.3 via 18122) ou wifi (127.0.0.2 via 18121)
  local c="$1" u="$2" pw="$3" port=18122 sec="$VSECRET" f; f="$(mktemp "$D/req.XXXXXX")"
  [ "$c" = wifi ] && { port=18121; sec="$CSECRET"; }
  { printf 'User-Name = "%s"\nUser-Password = "%s"\nMessage-Authenticator = 0x00\n' "$u" "$pw"; [ -n "${4:-}" ] && printf '%s\n' "$4"; } > "$f"
  radclient -x -t 15 -r 1 -f "$f" "127.0.0.1:$port" auth "$sec" 2>&1; rm -f "$f"
}
verdict() { if grep -q 'Received Access-Accept' "$1"; then echo accept; elif grep -q 'Received Access-Reject' "$1"; then echo reject; else echo none; fi; }
tp() {   # tp "nom" attendu CLIENT USER MOTDEPASSE
  pap "$3" "$4" "$5" > "$D/t.out"; expect_eq "$1" "$2" "$(verdict "$D/t.out")"
}

echo "== PAP + code à usage unique =="
OK_PW='Passw0rd-alice-1!'
C="$(code $ALICE_SECRET)"; n0="$(calls)"
tp "alice : mot de passe + bon code → accepté"                   accept vpn alice "$OK_PW$C"
expect_grep "…le Filter-Id de la règle est dans l'Access-Accept" 'Filter-Id = "vpn-users"' "$D/t.out"
expect_nogrep "…la réponse du fournisseur n'atteint jamais le client (ni jeton ni attribut injecté)" 'REST-HTTP-Body|AAA\.BBB|injecte|Reply-Message' "$D/t.out"
expect_eq "…le fournisseur a reçu exactement une requête" "$((n0 + 1))" "$(calls)"
last="$(tail -n 1 "$D/idp.log")"
expect_eq "…le mot de passe lui est transmis SANS le code" "$OK_PW" "$(printf '%s' "$last" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fields"]["password"])')"
expect_eq "…le code lui est transmis seul" "$C" "$(printf '%s' "$last" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fields"]["totp"])')"
expect_eq "…le compte transmis est celui de l'annuaire (identity=account)" "alice" "$(printf '%s' "$last" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fields"]["username"])')"
expect_eq "…identifiant et secret client, type de flux et paramètre supplémentaire" "ddi-radius $IDPSECRET password openid profile" "$(printf '%s' "$last" | python3 -c 'import json,sys; f=json.load(sys.stdin)["fields"]; print(f["client_id"], f["client_secret"], f["grant_type"], f["scope"])')"
expect_eq "…requête en formulaire (x-www-form-urlencoded)" "application/x-www-form-urlencoded" "$(printf '%s' "$last" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ctype"])')"
tp "alice@lab.test (UPN saisi) : accepté, le fournisseur reçoit le compte" accept vpn "alice@lab.test" "$OK_PW$(code $ALICE_SECRET)"
expect_eq "…compte transmis : alice (pas l'UPN)" "alice" "$(tail -n 1 "$D/idp.log" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fields"]["username"])')"
tp "caractères spéciaux (& = % + { } \$ espace) : acceptés tels quels" accept vpn alice 'p&a=s%+x{1}%{2}$y z'"$(code $ALICE_SECRET)"
expect_eq "…le fournisseur reçoit le mot de passe exact (aucune expansion, aucun double codage)" 'p&a=s%+x{1}%{2}$y z' "$(tail -n 1 "$D/idp.log" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fields"]["password"])')"
tp "code de la fenêtre précédente (±30 s) : accepté (décision du fournisseur)" accept vpn alice "$OK_PW$(code $ALICE_SECRET -30)"
tp "code faux → refusé"                                          reject vpn alice "${OK_PW}000000"
expect_grep "…raison : mot de passe ou code refusé par le fournisseur" 'fournisseur MFA : mot de passe ou code refuse' "$AL"
tp "mauvais mot de passe, bon code → refusé"                     reject vpn alice "Passw0rd-faux-1!$(code $ALICE_SECRET)"
tp "mot de passe sans code (aucun chiffre final) → refusé"       reject vpn alice "$OK_PW"
expect_grep "…raison : code absent ou mal formé" 'code a usage unique absent ou mal forme' "$AL"
n1="$(calls)"; tp "code de 5 chiffres → refusé sans appeler le fournisseur" reject vpn alice "${OK_PW}12345"
expect_eq "…fournisseur non appelé" "$n1" "$(calls)"
tp "code de 7 chiffres : les 6 derniers sont le code, le reste du mot de passe → refusé" reject vpn alice "${OK_PW}0$(code $ALICE_SECRET)"
tp "mot de passe vide + code seul → refusé"                      reject vpn alice "$(code $ALICE_SECRET)"
tp "identifiant à caractères interdits → refusé"                 reject vpn 'alice;rm' "$OK_PW$(code $ALICE_SECRET)"

echo "== Décision d'accès AVANT le fournisseur =="
n2="$(calls)"
tp "bob (compte désactivé) → refusé"                             reject vpn bob "Passw0rd-bob-1!123456"
tp "carol (compte expiré) → refusé"                              reject vpn carol "Passw0rd-carol-1!123456"
tp "dave (compte verrouillé) → refusé"                           reject vpn dave "Passw0rd-dave-1!123456"
tp "erin (aucune règle ne la couvre) → refusé"                   reject vpn erin "Passw0rd-erin-1!$(code $ERIN_SECRET)"
tp "compte inconnu → refusé"                                     reject vpn nobody "Passw0rd-x-1!123456"
expect_eq "…le fournisseur n'a reçu AUCUNE de ces cinq requêtes" "$n2" "$(calls)"
expect_grep "…raison : compte désactivé" 'compte desactive' "$AL"
expect_grep "…raison : compte verrouillé" 'compte verrouille' "$AL"
expect_grep "…raison : compte expiré" 'compte expire' "$AL"
expect_grep "…raison : aucune règle" 'aucune regle ne correspond' "$AL"
expect_grep "…raison : compte introuvable" 'compte introuvable' "$AL"

echo "== Autres protocoles et autre client =="
n3="$(calls)"
tp "le contrôleur Wi-Fi (client sans MFA) : PAP refusé comme avant" reject wifi alice "$OK_PW$(code $ALICE_SECRET)"
expect_eq "…le fournisseur n'est pas appelé pour un client sans MFA" "$n3" "$(calls)"
cat > "$D/ttls.conf" <<EOF
network={
 key_mgmt=WPA-EAP
 eap=TTLS
 phase2="auth=PAP"
 identity="alice"
 password="${OK_PW}"
 ca_cert="$P/root/ca.pem"
}
EOF
eapol_test -c "$D/ttls.conf" -a 127.0.0.1 -p 18122 -s "$VSECRET" -t 10 > "$D/eap.out" 2>&1
expect_eq "EAP (TTLS) sur le client MFA → refusé" reject "$(grep -q SUCCESS "$D/eap.out" && echo accept || echo reject)"
expect_grep "…raison : EAP non pris en charge sur un client MFA" 'EAP non pris en charge' "$AL"
expect_eq "…fournisseur non appelé" "$n3" "$(calls)"
f="$D/chap.req"; printf 'User-Name = "alice"\nCHAP-Password = "%s"\nMessage-Authenticator = 0x00\n' "$OK_PW" > "$f"
radclient -t 10 -r 1 -f "$f" 127.0.0.1:18122 auth "$VSECRET" > "$D/chap.out" 2>&1
expect_eq "CHAP sur le client MFA → refusé" reject "$(verdict "$D/chap.out")"
expect_grep "…raison : mot de passe PAP attendu" 'mot de passe PAP attendu' "$AL"
expect_eq "…fournisseur non appelé" "$n3" "$(calls)"
# sans Message-Authenticator : le client ne peut pas échapper à l'exigence (Blast-RADIUS)
# radclient (3.2.5) ajoute seul un Message-Authenticator : le paquet est donc fabriqué à la main (RFC 2865, aucun attribut 80)
noma() { python3 - "$@" <<'PY'
import hashlib, os, socket, struct, sys
port, secret, user, pw = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3].encode(), sys.argv[4].encode()
auth = os.urandom(16); pw += b"\0" * (-len(pw) % 16); hid, prev = b"", auth
for i in range(0, len(pw), 16):
    k = hashlib.md5(secret + prev).digest(); blk = bytes(a ^ b for a, b in zip(pw[i:i + 16], k)); hid += blk; prev = blk
attrs = bytes([1, 2 + len(user)]) + user + bytes([2, 2 + len(hid)]) + hid
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.3", 0)); s.settimeout(3)
s.sendto(struct.pack(">BBH", 1, 77, 20 + len(attrs)) + auth + attrs, ("127.0.0.1", port))
try: print({2: "accept", 3: "reject"}.get(s.recvfrom(4096)[0][0], "autre"))
except socket.timeout: print("aucune")
PY
}
expect_eq "requête sans Message-Authenticator : jamais acceptée" "no" "$(noma 18122 "$VSECRET" alice "$OK_PW$(code $ALICE_SECRET)" | grep -q '^accept$' && echo yes || echo no)"

echo "== Fournisseur indisponible ou en erreur =="
echo 500 > "$D/idp.mode"; tp "fournisseur en erreur 500 → refusé" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"
expect_grep "…raison : erreur du fournisseur" 'fournisseur MFA : erreur=2C injoignable ou refus' "$AL"
echo 400 > "$D/idp.mode"; tp "fournisseur répond 400 → refusé" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"
echo 200vide > "$D/idp.mode"; tp "fournisseur répond 200 sans jeton → refusé (un 2xx ne suffit pas)" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"
expect_grep "…raison : réponse sans jeton" 'fournisseur MFA : erreur=2C reponse sans jeton' "$AL"
echo slow > "$D/idp.mode"; s0="$(date +%s)"; tp "fournisseur trop lent → refusé" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"; s1="$(date +%s)"
[ "$((s1 - s0))" -lt 10 ] && ok "…refus dans le délai configuré (3 s), pas après 12 s ($((s1 - s0)) s)" || ko "…refus dans le délai configuré" "$((s1 - s0)) s"
echo ok > "$D/idp.mode"
kill "$IDP" 2>/dev/null; wait "$IDP" 2>/dev/null; IDP=""
tp "fournisseur éteint → refusé" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"
python3 "$D/idp.py" "$D" "$IDPSECRET" "$IDPPORT" "$P/idp-chain.pem" "$P/idp.key" >"$D/idp.out" 2>&1 9>&- </dev/null & IDP=$!; sleep 1
tp "fournisseur rallumé : accepté sans redémarrer FreeRADIUS" accept vpn alice "$OK_PW$(code $ALICE_SECRET)"
expect_eq "…le service tourne toujours" yes "$("$D/bin/systemctl" is-active freeradius.service && echo yes || echo no)"

echo "== 20 requêtes simultanées =="
rm -f "$D"/par.*; pids=""
for i in $(seq 1 20); do ( pap vpn alice "$OK_PW$(code $ALICE_SECRET)" > "$D/par.$i" ) & pids="$pids $!"; done
for q in $pids; do wait "$q"; done
expect_eq "…toutes acceptées" 20 "$(grep -l 'Received Access-Accept' "$D"/par.* 2>/dev/null | wc -l | tr -d ' ')"

echo "== Certificat du fournisseur =="
mkaz "$AZ" "$(mfajson)" "$P/other/ca.pem"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply2.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply avec une autre CA : code 0" || ko "apply avec une autre CA : code 0" "$(tail -n 4 "$D/apply2.out" | tr '\n' ' ')"
localize
tp "certificat du fournisseur non reconnu (autre CA) → refusé" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"
mkaz "$AZ" "$(mfajson | python3 -c 'import json,sys; d=json.load(sys.stdin); d["tlsVerify"]=False; print(json.dumps(d))')" "$P/other/ca.pem"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply3.out" 2>&1; localize
tp "vérification désactivée (tlsVerify=false) → accepté" accept vpn alice "$OK_PW$(code $ALICE_SECRET)"
mkaz "$AZ" "$(mfajson)" "$MCA"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply4.out" 2>&1; localize
tp "retour à la bonne CA → accepté" accept vpn alice "$OK_PW$(code $ALICE_SECRET)"

echo "== Identité saisie (identity=typed) et noms de champs personnalisés =="
mkaz "$AZ" "$(mfajson | python3 -c 'import json,sys; d=json.load(sys.stdin); d["identity"]="typed"; print(json.dumps(d))')" "$MCA"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply5.out" 2>&1; localize
tp "identity=typed : alice@lab.test envoyé tel quel → refusé par le fournisseur (inconnu de lui)" reject vpn "alice@lab.test" "$OK_PW$(code $ALICE_SECRET)"
expect_eq "…le fournisseur a reçu l'identifiant saisi" "alice@lab.test" "$(tail -n 1 "$D/idp.log" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fields"]["username"])')"
tp "identity=typed : alice → accepté" accept vpn alice "$OK_PW$(code $ALICE_SECRET)"
mkaz "$AZ" "$(mfajson | python3 -c 'import json,sys; d=json.load(sys.stdin); d["fields"]={"identity":"login","password":"pass","otp":"otp"}; print(json.dumps(d))')" "$MCA"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply6.out" 2>&1; localize
pap vpn alice "$OK_PW$(code $ALICE_SECRET)" > "$D/t.out"
expect_eq "champs personnalisés : le fournisseur les reçoit sous ces noms" "login pass otp" "$(tail -n 1 "$D/idp.log" | python3 -c 'import json,sys; f=json.load(sys.stdin)["fields"]; print(*[k for k in ("login","pass","otp") if k in f])')"
mkaz "$AZ" "$(mfajson | python3 -c 'import json,sys; d=json.load(sys.stdin); d["otpDigits"]=8; print(json.dumps(d))')" "$MCA"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply7.out" 2>&1; localize
n5="$(calls)"; tp "code de 8 chiffres configuré : un code de 6 chiffres est refusé sans appel" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"
expect_eq "…fournisseur non appelé" "$n5" "$(calls)"

echo "== Aucun secret dans les journaux =="
expect_nogrep "journal des authentifications : aucun mot de passe" 'Passw0rd|p&a=s' "$AL"
expect_nogrep "…aucun code à usage unique (6 derniers chiffres envoyés)" "$(code $ALICE_SECRET)" "$AL"
expect_nogrep "journal du service : aucun mot de passe ni secret du fournisseur" "Passw0rd-alice|$(printf '%s' "$IDPSECRET" | sed 's/[][\.*^$/~]/\\&/g')" "$RLOG"
expect_nogrep "sortie du démon : aucun mot de passe ni secret du fournisseur" "Passw0rd-alice|$(printf '%s' "$IDPSECRET" | sed 's/[][\.*^$/~]/\\&/g')" "$D/daemon.out"
expect_nogrep "messages de apply : aucun secret" "$(printf '%s' "$IDPSECRET" | sed 's/[][\.*^$/~]/\\&/g')" <(cat "$D"/apply*.out)

echo "== Retrait du MFA =="
check_fail "client MFA sans dépôt des règles ni du fournisseur : refusé, rien n'est changé" "$RAD" apply "$CL" "$DEP"
cl_conf > "$CL"; mkaz "$AZ" "$(mfajson)" "$MCA"
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply8.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply sans client MFA : code 0" || ko "apply sans client MFA : code 0" "$(tail -n 4 "$D/apply8.out" | tr '\n' ' ')"
expect_nogrep "…plus de mention MFA" "Clients MFA" "$D/apply8.out"
check_fail "…module REST supprimé (secret client effacé)" test -e "$D/etc/mods-enabled/ddibuntu_mfa"
check_fail "…CA du fournisseur supprimée" test -e "$D/etc/certs/mfa-ca"
expect_nogrep "…plus de serveur MFA dans le site" "ddibuntu-mfa" "$D/etc/sites-available/ddibuntu"
localize
tp "fw-vpn n'est plus un client MFA : PAP refusé comme tout client sans MFA" reject vpn alice "$OK_PW$(code $ALICE_SECRET)"

finish
