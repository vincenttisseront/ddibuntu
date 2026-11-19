#!/usr/bin/env bash
# Batterie 30 — règles d'accès du service RADIUS (0.13.3) : ddibuntu-radius contre un VRAI FreeRADIUS, un VRAI contrôleur de domaine Samba AD en LDAPS
# (tests/samba-lab.sh) et de VRAIES poignées de main EAP-TLS (eapol_test). Le jeu de cas tests/radius-rules-cases.json est le MÊME que celui du moteur de la
# console (tests/unit-radius-rules.test.ts, simulation) : mêmes règles, mêmes comptes, mêmes décisions attendues, y compris les attributs de réponse.
# Couvre : validation stricte du dépôt (check-authz), génération et droits des fichiers, mot de passe de liaison jamais divulgué, décisions (comptes
# désactivé / verrouillé / expiré / inconnu, groupes imbriqués, caractères spéciaux, clients, SSID), annuaire injoignable puis rétabli, démarrage sans annuaire,
# validation du certificat de l'annuaire (autorité manquante ou fausse), bascule entre serveurs, charge parallèle, retour arrière d'un déploiement refusé.
# Prérequis : root, freeradius + freeradius-ldap, eapol_test, openssl, samba (voir samba-lab.sh) ; sinon la batterie est ignorée.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=lib-pki.sh
. "$(dirname "$0")/lib-pki.sh"

RAD="$RFS/usr/local/sbin/ddibuntu-radius"
if [ "$(id -u)" -ne 0 ] || ! command -v freeradius >/dev/null || ! command -v eapol_test >/dev/null || ! command -v openssl >/dev/null || [ ! -e /usr/lib/freeradius/rlm_ldap.so ]; then
  note "prérequis absents (root, freeradius, freeradius-ldap, eapol_test, openssl) : batterie ignorée"; finish; exit $?
fi
udp_listen() { local hex; hex="$(printf '%04X' "$1")"; cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk -v h=":$hex" '$2 ~ (h "$") { f = 1 } END { exit !f }'; }
if udp_listen 1812 || udp_listen 1813; then note "ports UDP 1812/1813 déjà utilisés : batterie ignorée"; finish; exit $?; fi
D="$T_TMP"; chmod 0755 "$D"; LAB="$D/lab"
bash "$ROOT/tests/samba-lab.sh" start "$LAB" >"$D/lab.out" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then note "annuaire d'essai indisponible ($(tail -n 1 "$D/lab.out")) : batterie ignorée"; finish; exit $?; fi
bash "$ROOT/tests/samba-lab.sh" extra "$LAB" >"$D/lab-extra.out" 2>&1 || { ko "annuaire d'essai : comptes supplémentaires" "$(tail -n 3 "$D/lab-extra.out")"; finish; exit $?; }

mkdir -p "$D/gen" "$D/run" "$D/state" "$D/bin" "$D/pki"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_RADIUS_DIR="$D/etc" DDI_RADIUS_LOCK="$D/lock" DDI_STATE_DIR="$D/state" DDI_RUN_DIR="$D/run" DDI_GENERATED_DIR="$D/gen"
export DDI_RADIUS_SYSTEMCTL="$D/bin/systemctl" DDI_FW_BIN="$D/bin/fw"
SELF="0123456789abcdef0123456789abcdef"; BINDPW='Passw0rd-svc-radius-1!'
FX="$ROOT/tests/radius-rules-cases.json"; GOLD="$ROOT/tests/radius-rules-compiled.json"

cat > "$D/bin/systemctl" <<SH
#!/bin/bash
P="$D/radiusd.pid"
alive() { [ -f "\$P" ] && kill -0 "\$(cat "\$P")" 2>/dev/null; }
case "\$1" in
  daemon-reload|enable) exit 0 ;;
  restart) [ -e "$D/failstart" ] && exit 1
           alive && { kill "\$(cat "\$P")"; sleep 0.5; }
           ( /usr/sbin/freeradius -f -d "$D/etc" >"$D/daemon.out" 2>&1 9>&- </dev/null & echo \$! > "\$P" ); sleep 2; exit 0 ;;
  disable) alive && kill "\$(cat "\$P")"; rm -f "\$P"; sleep 0.3; exit 0 ;;
  is-active) alive; exit \$? ;;
  is-enabled) exit 0 ;;
esac
SH
printf '#!/bin/bash\nexit 0\n' > "$D/bin/fw"; chmod +x "$D/bin/systemctl" "$D/bin/fw"
RELAYS=()
cleanup() { [ -n "${B30_HOLD:-}" ] && { echo "B30_HOLD : environnement conservé dans $D (daemon, annuaire et relais laissés en marche)"; trap - EXIT; exit; }; kill "$(cat "$D/radiusd.pid" 2>/dev/null)" 2>/dev/null; for p in "${RELAYS[@]}"; do kill "$p" 2>/dev/null; done; bash "$ROOT/tests/samba-lab.sh" stop "$LAB" 2>/dev/null; rm -rf "$T_TMP"; }
trap cleanup EXIT

# ---- Clients distincts : FreeRADIUS reconnaît un client à son adresse source. Un petit relais UDP par client émet depuis 127.0.0.2, .3 et .4 (tout 127/8 est local).
# root refuse (à raison) une adresse de bouclage pour un client : le fichier validé porte donc 10.1.0.N, et le banc d'essai, APRÈS le déploiement, remplace ces
# adresses par 127.0.0.N dans la configuration installée et redémarre le service. Seule l'adresse source change : la décision ne dépend que du nom du client. ----
cat > "$D/relay.py" <<'PY'
import select, socket, sys
port, src = int(sys.argv[1]), sys.argv[2]
f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); f.bind(("127.0.0.1", port))
peers, back = {}, {}      # un socket côté serveur par client eapol_test (échanges simultanés)
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
declare -A CPORT=([wifi-ctrl]=18121 [vpn-gw]=18122 [sw1]=18123) CADDR=([wifi-ctrl]=127.0.0.2 [vpn-gw]=127.0.0.3 [sw1]=127.0.0.4) CSEC
for c in wifi-ctrl vpn-gw sw1; do CSEC[$c]="$(openssl rand -hex 16)"; python3 "$D/relay.py" "${CPORT[$c]}" "${CADDR[$c]}" >/dev/null 2>&1 9>&- </dev/null & RELAYS+=("$!"); done
clients() {
  local f="$D/clients.$RANDOM" c
  printf 'client "ddi-selftest" {\n\tipaddr = 127.0.0.1\n\tsecret = "%s"\n\tshortname = ddi-selftest\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n' "$SELF" > "$f"
  for c in wifi-ctrl vpn-gw sw1; do printf '\nclient "%s" {\n\tipaddr = %s\n\tsecret = "%s"\n\tshortname = %s\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n' "$c" "${CADDR[$c]/127.0.0./10.1.0.}" "${CSEC[$c]}" "$c" >> "$f"; done
  printf '%s' "$f"
}
localize() {   # après un déploiement : adresses des clients d'essai → 127.0.0.N, puis redémarrage
  sed -i 's/ipaddr = 10\.1\.0\./ipaddr = 127.0.0./' "$D/etc/clients.conf" && "$D/bin/systemctl" restart freeradius.service
}
rj() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d := d[k] for k in sys.argv[2].split(".")]; print(d)' "$1" "$2"; }

echo "== PKI de test (openssl) et comptes =="
P="$D/pki"
pki_root "$P/root" "Lab Root CA"; pki_inter "$P/issuing" "$P/root" "Lab Issuing CA"
pki_issue "$P/issuing" "$P/srv" "radius.lab.test" server "DNS:radius.lab.test"
for u in alice bob carol dave erin zoe; do pki_issue "$P/issuing" "$P/$u" "$u" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$u@lab.test"; done
for m in pc001 pc002 pc003; do pki_issue "$P/issuing" "$P/$m" "$m" client "DNS:$m.lab.test"; done
pki_crl "$P/issuing" "$P/crl.pem"
check "PKI de test fabriquée" test -s "$P/crl.pem"
LABCA="$LAB/private/tls/ca.pem"
check "annuaire d'essai : CA LDAPS lisible" test -s "$LABCA"

mkdep() {   # mkdep DIR : dépôt PKI de la console
  rm -rf "$1"; mkdir -p "$1/crl"
  printf '{"checkCrl": true}\n' > "$1/pki.json"
  cat "$P/root/ca.pem" "$P/issuing/ca.pem" > "$1/ca.pem"
  cat "$P/srv.pem" "$P/issuing/ca.pem" > "$1/server.pem"; cp "$P/srv.key" "$1/server.key"; cp "$P/crl.pem" "$1/crl/issuing.pem"
}
mkaz() {   # mkaz DIR [rules.json] : dépôt des règles de la console (jeu de référence + annuaire d'essai)
  rm -rf "$1"; mkdir -p "$1"
  cp "${2:-$GOLD}" "$1/rules.json"
  printf '{"urls":["ldaps://dc1.lab.test"],"baseDn":"DC=lab,DC=test","bindDn":"svc-radius@lab.test","bindPassword":"%s","tlsRejectUnauthorized":true}\n' "$BINDPW" > "$1/ldap.json"
  cp "$LABCA" "$1/ldap-ca.pem"; chmod 0600 "$1"/*
}
DEP="$D/dep"; AZ="$D/az"; CL="$(clients)"
mkdep "$DEP"; mkaz "$AZ"

echo "== Validation stricte du dépôt des règles (aucune écriture) =="
check "dépôt conforme accepté" "$RAD" check-authz "$AZ" "$CL"
"$RAD" check-authz "$AZ" "$CL" >"$D/check.out" 2>&1
expect_nogrep "check-authz masque le mot de passe de liaison" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" "$D/check.out"
expect_grep "…le module LDAP généré est montré, mot de passe remplacé" 'password = "\*\*\*"' "$D/check.out"
expect_grep "…la décision générée montre les règles numérotées" '# règle 2 : Wi-Fi IT \(accepter\)' "$D/check.out"
expect_grep "…un refus par défaut est écrit en dernier" 'aucune regle ne correspond \(refus par defaut\)' "$D/check.out"
expect_grep "…la règle « client disparu » est écrite en commentaire, jamais évaluée" 'aucun client ne correspond : cette règle ne s.applique jamais' "$D/check.out"
expect_grep "…chaîne d'appartenance imbriquée activée" '1\.2\.840\.113556\.1\.4\.1941' "$D/check.out"
expect_grep "…les connexions LDAP démarrent à zéro (annuaire absent au lancement)" 'start = 0' "$D/check.out"
expect_grep "…le réservoir de connexions couvre tous les fils du démon (aucun refus à tort en pointe)" 'max = 32' "$D/check.out"
expect_grep "…un DN à virgule échappée et accent est comparé tel quel" "LDAP-Group == 'CN=Réseau\\\\\\\\, Wi-Fi d" "$D/check.out"

bad() {   # bad "nom" 'code python modifiant r (rules) / l (ldap)' : dépôt modifié, doit être refusé
  local name="$1" code="$2" d="$D/azbad"
  mkaz "$d"
  python3 - "$d" "$code" <<'PY' || { ko "$name (préparation)" "script de modification en échec"; return; }
import json, os, sys
d, code = sys.argv[1], sys.argv[2]
r = json.load(open(d + "/rules.json")); l = json.load(open(d + "/ldap.json"))
exec(code)
json.dump(r, open(d + "/rules.json", "w"), ensure_ascii=False); json.dump(l, open(d + "/ldap.json", "w"))
PY
  check_fail "$name" "$RAD" check-authz "$d" "$CL"
}
bad "champ inconnu dans une règle refusé"                 'r["rules"][0]["exec"] = "x"'
bad "action inconnue refusée"                              'r["rules"][0]["action"] = "peut-etre"'
bad "type de compte inconnu refusé"                        'r["rules"][0]["kind"] = "robot"'
bad "VLAN 0 refusé"                                        'r["rules"][2]["reply"]["vlan"] = 0'
bad "VLAN 4095 refusé"                                     'r["rules"][2]["reply"]["vlan"] = 4095'
bad "VLAN non entier refusé"                               'r["rules"][2]["reply"]["vlan"] = "130"'
bad "durée de session trop courte refusée"                 'r["rules"][1]["reply"]["sessionTimeout"] = 59'
bad "refus portant une réponse refusé"                     'r["rules"][0]["reply"] = {"vlan": 5}'
bad "attribut constructeur hors liste blanche refusé"      'r["rules"][1]["reply"]["attrs"][0]["name"] = "Service-Type"'
bad "valeur d'attribut avec guillemet refusée"             'r["rules"][1]["reply"]["attrs"][0]["value"] = "a\"b"'
bad "pool avec espace refusé"                              'r["rules"][2]["reply"]["pool"] = "a b"'
bad "Filter-Id avec apostrophe refusé"                     'r["rules"][1]["reply"]["filterId"] = "x'"'"'y"'
bad "SSID trop long refusé"                                'r["rules"][1]["ssids"] = ["a" * 33]'
bad "SSID avec guillemet refusé"                           'r["rules"][1]["ssids"] = ["a\"b"]'
bad "DN de groupe avec guillemet refusé"                   'r["rules"][0]["groups"] = ["CN=g\"x,DC=y"]'
bad "DN de groupe avec « \${ » refusé"                     'r["rules"][0]["groups"] = ["CN=${HOME},DC=y"]'
bad "DN de groupe avec « %{ » refusé"                      'r["rules"][0]["groups"] = ["CN=%{x},DC=y"]'
bad "DN de groupe avec échappement invalide refusé"        'r["rules"][0]["groups"] = ["CN=g\\q,DC=y"]'
bad "DN de groupe à échappement hexadécimal refusé (FreeRADIUS ne le retrouve pas)" 'r["rules"][0]["groups"] = ["CN=T a\\3Db,DC=y"]'
bad "DN de groupe sans « = » refusé"                       'r["rules"][0]["groups"] = ["groupe-sans-egal"]'
bad "client inconnu du fichier de clients refusé"          'r["rules"][2]["nas"] = ["inconnu"]'
bad "nom de client piégé refusé"                           'r["rules"][2]["nas"] = ["a b"]'
bad "plus de 200 règles refusé"                            'r["rules"] = r["rules"] * 30'
bad "liste de règles absente refusée"                      'del r["rules"]'
bad "règles ni liste ni objet refusées"                    'r = ["x"]'
bad "adresse d'annuaire en clair (ldap://) refusée"        'l["urls"] = ["ldap://dc1.lab.test"]'
bad "adresse d'annuaire avec chemin refusée"               'l["urls"] = ["ldaps://dc1.lab.test/x"]'
bad "plus de 5 serveurs refusé"                            'l["urls"] = ["ldaps://dc%d.lab.test" % i for i in range(6)]'
bad "aucun serveur refusé"                                 'l["urls"] = []'
bad "DN de base avec guillemet refusé"                     'l["baseDn"] = "DC=a\"b"'
bad "mot de passe de liaison avec « \${ » refusé"          'l["bindPassword"] = "a${HOME}b"'
bad "mot de passe de liaison avec « \$ENV » refusé"        'l["bindPassword"] = "a$ENV{HOME}b"'
bad "mot de passe de liaison avec saut de ligne refusé"    'l["bindPassword"] = "a\nb"'
bad "mot de passe de liaison vide refusé"                  'l["bindPassword"] = ""'
bad "option TLS non booléenne refusée"                     'l["tlsRejectUnauthorized"] = "oui"'
bad "champ inconnu dans les réglages refusé"               'l["exec"] = "x"'
mkaz "$D/azbad"; echo "pas un certificat" > "$D/azbad/ldap-ca.pem"; check_fail "autorité LDAPS illisible refusée" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; cat "$P/srv.key" >> "$D/azbad/ldap-ca.pem"; check_fail "clé privée glissée dans l'autorité LDAPS refusée" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; rm "$D/azbad/ldap.json"; check_fail "ldap.json manquant refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; rm "$D/azbad/rules.json"; check_fail "rules.json manquant refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; ln -sf /etc/passwd "$D/azbad/extra"; check_fail "fichier inattendu dans le dépôt refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; rm "$D/azbad/rules.json"; ln -s "$GOLD" "$D/azbad/rules.json"; check_fail "lien symbolique refusé" "$RAD" check-authz "$D/azbad" "$CL"
mkaz "$D/azbad"; python3 - "$D/azbad/ldap.json" <<'PY'
import json, sys
l = json.load(open(sys.argv[1])); l["bindDn"] = 'CN=svc "x",DC=lab'; json.dump(l, open(sys.argv[1], "w"))
PY
"$RAD" check-authz "$D/azbad" "$CL" >"$D/check2.out" 2>&1
expect_grep "guillemet dans le compte de liaison : échappé dans la configuration (pas d'injection)" 'identity = "CN=svc \\"x\\",DC=lab"' "$D/check2.out"
mkaz "$D/azbad"; chmod 0644 "$D/azbad/ldap.json"; check "droits larges (0644) tolérés : root relit et réécrit avec ses propres droits" "$RAD" check-authz "$D/azbad" "$CL"

echo "== Règles sans EAP-TLS, sans module LDAP : refus du déploiement =="
check_fail "règles sans dépôt PKI refusées (elles s'appliquent après EAP-TLS)" "$RAD" apply "$CL" "" "$AZ"
expect_eq "…rien n'a été installé" no "$([ -e "$D/etc/radiusd.conf" ] && echo yes || echo no)"

echo "== Déploiement avec règles =="
"$RAD" apply "$CL" "$DEP" "$AZ" >"$D/apply.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "apply avec PKI + règles : code 0" || ko "apply avec PKI + règles : code 0" "$(tail -n 5 "$D/apply.out" | tr '\n' ' ')"
expect_grep "message : règles d'accès comptées" 'Règles d.accès : 7 règle' "$D/apply.out"
expect_eq "module ldap : 0640 root:freerad (il contient le mot de passe de liaison)" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/mods-enabled/ldap")"
expect_eq "autorité LDAPS installée : 0640 root:freerad" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/certs/ldap-ca.pem")"
expect_eq "modules : liste blanche + eap + ldap + expr" "always attr_filter eap expr ldap preprocess" "$(find "$D/etc/mods-enabled" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
expect_eq "statut publié : règles actives" True "$(rj "$D/run/radius-status.json" authz.enabled)"
expect_eq "statut publié : 7 règles" 7 "$(rj "$D/run/radius-status.json" authz.rules)"
expect_eq "statut publié : module LDAP présent" True "$(rj "$D/run/radius-status.json" ldap_module)"
# 0.14.16 : sous systemd le démon tourne en freerad (le faux systemctl le lance en root) : toute l'arborescence, module LDAP et site de décision compris, doit lui être lisible
check "le démon, EN TANT QUE freerad, lit toute l'arborescence (freeradius -Cx)" runuser -u freerad -- /usr/sbin/freeradius -d "$D/etc" -Cx -lstdout
expect_eq "aucun fichier de l'arborescence hors du groupe freerad (liens symboliques exceptés)" "" "$(find "$D/etc" ! -type l ! -group freerad)"
expect_nogrep "mot de passe de liaison : absent du résultat publié" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" "$D/run/radius-status.json"
expect_nogrep "…de la sortie de apply" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" "$D/apply.out"
expect_nogrep "…du site généré" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" "$D/etc/sites-available/ddibuntu"
localize
expect_eq "service actif" yes "$("$D/bin/systemctl" is-active x && echo yes || echo no)"
expect_nogrep "le démon ne signale aucune erreur de configuration" 'Error:|Failed to|rlm_ldap.*failed' "$D/daemon.out"

RLOG=/var/log/freeradius/radius.log
mac="AA-BB-CC-DD-EE-FF"
eap() {   # eap CERT_BASE CLIENT SSID : sortie d'eapol_test (SSID « - » : aucun)
  local n="$1" c="${2:-wifi-ctrl}" ssid="${3:--}" cf; cf="$(mktemp "$D/eap.XXXXXX")"
  { echo 'network={'; echo ' key_mgmt=WPA-EAP'; echo ' eap=TLS'; echo ' identity="test@lab.test"'; echo " ca_cert=\"$P/root/ca.pem\""
    echo " client_cert=\"$P/$n.pem\""; echo " private_key=\"$P/$n.key\""; echo '}'; } > "$cf"
  local args=(-c "$cf" -a 127.0.0.1 -p "${CPORT[$c]}" -s "${CSEC[$c]}" -t "${ET:-10}")
  [ "$ssid" = "-" ] || args+=(-N "30:s:$mac:$ssid")
  eapol_test "${args[@]}" 2>&1; rm -f "$cf"
}
cat > "$D/replycheck.py" <<'PY'
# replycheck.py FICHIER vlan pool timeout filter attrs : compare les attributs de l'Access-Accept vus par eapol_test à ceux attendus (et vérifie l'absence des autres)
import re, sys
txt = open(sys.argv[1], errors="replace").read()
vlan, pool, timeout, filt, attrs = sys.argv[2:7]
part = txt.split("Access-Accept")[-1] if "Access-Accept" in txt else txt.split("code=2")[-1]
got, cur = [], None
for line in part.splitlines():
    m = re.match(r"\s*Attribute (\d+) \((.*?)\) length=(\d+)", line)
    if m: cur = [int(m.group(1)), m.group(2), int(m.group(3)), None]; got.append(cur); continue
    m = re.match(r"\s*Value: (.*)$", line)
    if m and cur is not None and cur[3] is None: cur[3] = m.group(1).strip()
def one(i): return [g for g in got if g[0] == i]
def text(v):
    if v is None: return None
    if v.startswith("'"): return v.strip("'")
    try: return bytes.fromhex(v).decode("utf-8", "replace")
    except ValueError: return v
errs = []
if vlan:
    t, mt, g = one(64), one(65), one(81)
    if not (t and t[0][3] == "0000000d"): errs.append("Tunnel-Type 13 attendu : %r" % t)
    if not (mt and mt[0][3] == "00000006"): errs.append("Tunnel-Medium-Type 6 attendu : %r" % mt)
    if not (g and text(g[0][3]) == vlan): errs.append("Tunnel-Private-Group-Id %s attendu : %r" % (vlan, g))
elif one(64) or one(65) or one(81): errs.append("aucun VLAN attendu : %r" % (one(64) + one(65) + one(81)))
p = one(88)
if pool and not (p and p[0][2] == 2 + len(pool.encode())): errs.append("Framed-Pool de %d octets attendu : %r" % (len(pool.encode()), p))   # eapol_test ne décode pas cet attribut : on compare la longueur
if not pool and p: errs.append("aucun pool attendu : %r" % p)
t = one(27)
if timeout and not (t and t[0][3] == timeout): errs.append("Session-Timeout %s attendu : %r" % (timeout, t))
if not timeout and t: errs.append("aucune durée attendue : %r" % t)
f = one(11)
if filt and not (f and f[0][2] == 2 + len(filt.encode())): errs.append("Filter-Id de %d octets attendu : %r" % (len(filt.encode()), f))
if not filt and f: errs.append("aucun Filter-Id attendu : %r" % f)
VEND = {"Aruba-User-Role": (14823, 1), "Fortinet-Group-Name": (12356, 1), "Cisco-AVPair": (9, 1)}
vs = [g[3] for g in one(26) if g[3]]
for kv in [a for a in attrs.split(",") if a]:
    n, v = kv.split("=", 1); vid, aid = VEND[n]
    want = "%08x%02x%02x%s" % (vid, aid, 2 + len(v.encode()), v.encode().hex())
    if want not in vs: errs.append("%s = %s attendu (non reçu)" % (n, v))
if not attrs and any(x.startswith("000039e7") or x.startswith("00003044") for x in vs): errs.append("aucun attribut constructeur attendu")
print("; ".join(errs) if errs else "OK")
PY
recent() { tail -n "${1:-30}" "$RLOG"; }
lastlog() { tail -n "${1:-6}" "$RLOG" | grep -E 'Login (OK|incorrect)' | tail -n 1; }

echo "== Jeu de cas partagé avec le moteur de la console (simulation) =="
python3 - "$FX" > "$D/cases.tsv" <<'PY'
import json, sys
fx = json.load(open(sys.argv[1]))
for k in fx["cases"]:
    e = k["expect"]
    print("|".join([k["id"], k["who"].split("@")[0].split(".")[0], k["client"], k["ssid"] or "-", e["decision"], e["code"], str(e.get("rule", "")), str(e.get("vlan", "")), e.get("pool", ""), str(e.get("timeout", "")), e.get("filter", ""), ",".join("%s=%s" % kv for kv in e.get("attrs", {}).items())]))
PY
# message du journal selon le motif de la décision
declare -A WHY=([account_disabled]='compte desactive' [account_locked]='compte verrouille' [account_expired]='compte expire' [account_not_found]='compte introuvable' [default_reject]='aucune regle ne correspond')
while IFS='|' read -r id base client ssid decision code rule vlan pool timeout filter attrs; do
  r="$(eap "$base" "$client" "$ssid")"; last="$(echo "$r" | tail -1)"
  [ "${B30_SHOW:-}" = "$id" ] && { echo "$r" > /tmp/b30-show.txt; }
  if [ "$decision" = accept ]; then
    echo "$last" | grep -q '^SUCCESS' && ok "$id : accepté" || ko "$id : accepté attendu" "$(echo "$r" | tail -3)"
    # attributs de réponse reçus par l'équipement (VLAN, pool, durée, Filter-Id, attributs constructeur)
    echo "$r" > "$D/out.$id"; rc2="$(python3 "$D/replycheck.py" "$D/out.$id" "$vlan" "$pool" "$timeout" "$filter" "$attrs")"
    [ "$rc2" = OK ] && ok "$id : attributs de réponse conformes (VLAN, pool, durée, Filter-Id, constructeur ; rien de plus)" || ko "$id : attributs de réponse" "$rc2"
  else
    echo "$last" | grep -q '^FAILURE' && ok "$id : refusé" || ko "$id : refus attendu" "$(echo "$r" | tail -3)"
    if [ "$code" = rule_reject ]; then expect_grep "$id : journal « règle $rule : refus »" "Login incorrect.*regle $rule : refus" <(lastlog 8)
    else expect_grep "$id : journal « ${WHY[$code]} »" "Login incorrect.*${WHY[$code]}" <(lastlog 8); fi
  fi
done < "$D/cases.tsv"

echo "== Le vérificateur d'attributs détecte bien une réponse non conforme =="
r="$(python3 "$D/replycheck.py" "$D/out.alice-it" 121 "" 3600 ACL-IT Aruba-User-Role=it-staff)"; [ "$r" != OK ] && ok "mauvais VLAN attendu : détecté" || ko "mauvais VLAN attendu : détecté" "$r"
r="$(python3 "$D/replycheck.py" "$D/out.alice-it" 120 "" 3600 ACL-IT Aruba-User-Role=autre)"; [ "$r" != OK ] && ok "mauvaise valeur d'attribut constructeur : détectée" || ko "attribut constructeur" "$r"
r="$(python3 "$D/replycheck.py" "$D/out.alice-it" 120 "pool" 3600 ACL-IT Aruba-User-Role=it-staff)"; [ "$r" != OK ] && ok "pool attendu mais absent : détecté" || ko "pool absent" "$r"
r="$(python3 "$D/replycheck.py" "$D/out.alice-vpn" 130 pool-vpn "" "" "")"; [ "$r" != OK ] && ok "VLAN inattendu sur une réponse sans VLAN : détecté" || ko "VLAN inattendu" "$r"

echo "== Certificat de l'annuaire : validation réelle (LDAPS) =="
deploy() {   # deploy PKI AUTHZ : apply + adresses d'essai ; code de apply
  "$RAD" apply "$CL" "$@" >"$D/apply.out" 2>&1; local rc=$?; [ "$rc" -eq 0 ] && localize; return "$rc"
}
verdict() { eap "$1" "${2:-wifi-ctrl}" "${3:--}" | tail -1; }
# autorité de l'annuaire absente : le certificat de Samba n'est pas reconnu, tout est refusé
mkaz "$D/az2"; rm "$D/az2/ldap-ca.pem"; "$RAD" check-authz "$D/az2" "$CL" >/dev/null 2>&1 && ok "sans autorité déposée : accepté à la validation (le magasin du système sert)" || ko "sans autorité déposée"
deploy "$DEP" "$D/az2"; expect_eq "…déployé" 0 "$?"
expect_eq "…le certificat de l'annuaire n'est pas reconnu : alice refusée" FAILURE "$(verdict alice wifi-ctrl "Corp Wifi")"
expect_grep "…journal : l'annuaire n'a pas pu être joint (la liaison TLS échoue : refus, pas « compte introuvable »)" "Can.t contact LDAP server" <(recent 120)
expect_nogrep "…le refus n'est pas présenté comme un compte inconnu" 'compte introuvable dans l.annuaire' <(recent 20)
# autorité d'une AUTRE PKI : refusé aussi
mkaz "$D/az2"; cp "$P/root/ca.pem" "$D/az2/ldap-ca.pem"; deploy "$DEP" "$D/az2"
expect_eq "autorité LDAPS étrangère : alice refusée" FAILURE "$(verdict alice wifi-ctrl "Corp Wifi")"
# vérification coupée : accepté sans autorité (réglage explicite de l'administrateur)
mkaz "$D/az2"; rm "$D/az2/ldap-ca.pem"; python3 - "$D/az2/ldap.json" <<'PY'
import json, sys
l = json.load(open(sys.argv[1])); l["tlsRejectUnauthorized"] = False; json.dump(l, open(sys.argv[1], "w"))
PY
deploy "$DEP" "$D/az2"
expect_eq "vérification du certificat coupée : alice acceptée" SUCCESS "$(verdict alice wifi-ctrl "Corp Wifi")"
expect_grep "…un avertissement le dit dans la configuration générée" 'require_cert = .?never' "$D/etc/mods-enabled/ldap"
# bonne autorité : retour à la normale
deploy "$DEP" "$AZ"; expect_eq "bonne autorité déposée : alice acceptée" SUCCESS "$(verdict alice wifi-ctrl "Corp Wifi")"

echo "== Annuaire injoignable, puis rétabli (sans redémarrer le service) =="
tcp_listen() { local hex; hex="$(printf '%04X' "$1")"; cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v h=":$hex" '$4 == "0A" && $2 ~ (h "$") { f = 1 } END { exit !f }'; }
lab_down() { for f in "$LAB/samba.pid" "$LAB/run/samba.pid"; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; for _ in $(seq 1 40); do tcp_listen 636 || return 0; sleep 0.5; done; return 1; }
lab_up() { ( cd "$LAB" || exit 1; setsid nohup /usr/sbin/samba -s "$LAB/etc/smb.conf" -i -M single >"$LAB/samba.log" 2>&1 </dev/null & echo $! > "$LAB/samba.pid" ); for _ in $(seq 1 60); do tcp_listen 636 && { sleep 2; return 0; }; sleep 0.5; done; return 1; }
check "annuaire arrêté" lab_down
pid="$(cat "$D/radiusd.pid")"
expect_eq "annuaire coupé : alice (règle d'acceptation) refusée" FAILURE "$(verdict alice wifi-ctrl "Corp Wifi")"
expect_grep "…journal : la recherche dans l'annuaire a échoué" 'Login incorrect \(ldap: Failed performing search' <(recent 120)
expect_eq "annuaire coupé : un refus explicite reste un refus" FAILURE "$(verdict pc003)"
expect_eq "…le service tourne toujours (aucun plantage)" "$pid" "$(cat "$D/radiusd.pid")"
# démarrage du service pendant la panne : il doit démarrer quand même (connexions LDAP ouvertes à la demande)
"$D/bin/systemctl" restart freeradius.service
expect_eq "démarrage pendant la panne de l'annuaire : le service est actif" yes "$("$D/bin/systemctl" is-active x && echo yes || echo no)"
expect_eq "…et refuse" FAILURE "$(verdict alice wifi-ctrl "Corp Wifi")"
check "annuaire relancé" lab_up
v=FAILURE; for _ in 1 2 3 4 5 6 7 8; do v="$(verdict alice wifi-ctrl "Corp Wifi")"; [ "$v" = SUCCESS ] && break; sleep 3; done   # reprise : nouvelle tentative de connexion au bout de retry_delay = 5 s
expect_eq "annuaire rétabli : alice acceptée de nouveau (sans redéploiement, au plus quelques secondes)" SUCCESS "$v"
expect_eq "…un compte inconnu reste refusé" FAILURE "$(verdict zoe)"

echo "== Plusieurs serveurs : bascule sur le deuxième =="
mkaz "$D/az2"; python3 - "$D/az2/ldap.json" <<'PY'
import json, sys
l = json.load(open(sys.argv[1])); l["urls"] = ["ldaps://127.0.0.1:1", "ldaps://dc1.lab.test"]; json.dump(l, open(sys.argv[1], "w"))
PY
deploy "$DEP" "$D/az2"; expect_eq "premier serveur injoignable, second joignable : accepté" SUCCESS "$(verdict alice wifi-ctrl "Corp Wifi")"
expect_eq "…et la décision est la même (compte désactivé refusé)" FAILURE "$(verdict bob)"

echo "== Charge : authentifications simultanées, décisions cohérentes =="
deploy "$DEP" "$AZ"
pids=(); rm -f "$D"/par.*; ET=60   # Samba (processus unique) sert les recherches de groupes imbriqués une à une : on laisse le temps de les enchaîner
for i in $(seq 1 24); do
  case $((i % 4)) in 0) w=alice; e=SUCCESS ;; 1) w=bob; e=FAILURE ;; 2) w=pc001; e=SUCCESS ;; 3) w=dave; e=FAILURE ;; esac
  ( o="$(eap "$w" wifi-ctrl "Corp Wifi")"; v="$(echo "$o" | tail -1)"; [ "$v" != "$e" ] && [ -n "${B30_DEBUG:-}" ] && { mkdir -p /tmp/b30-par; echo "$o" > "/tmp/b30-par/$i.$w.txt"; }; [ "$v" = "$e" ] && echo ok > "$D/par.$i" || echo "ko $w attendu=$e obtenu=$v" > "$D/par.$i" ) & pids+=("$!")
done
wait "${pids[@]}"; ET=10
n="$(cat "$D"/par.* | grep -c '^ok$')"; [ "$n" = 24 ] && ok "24 authentifications parallèles : toutes conformes" || ko "24 authentifications parallèles : toutes conformes" "$n sur 24 ; $(cat "$D"/par.* | grep -v '^ok$' | sort | uniq -c | tr '\n' ';')"
expect_eq "…le service tourne toujours" yes "$("$D/bin/systemctl" is-active x && echo yes || echo no)"

echo "== Déploiement refusé : l'ancienne configuration reste en service =="
mkaz "$D/az2"; python3 - "$D/az2/rules.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); r["rules"][2]["reply"]["vlan"] = 9999; json.dump(r, open(sys.argv[1], "w"))
PY
"$RAD" apply "$CL" "$DEP" "$D/az2" >"$D/apply-bad.out" 2>&1; rc=$?
[ "$rc" -ne 0 ] && ok "règles invalides : déploiement refusé (code $rc)" || ko "règles invalides refusées"
expect_grep "…le motif est dit" 'VLAN|vlan' "$D/apply-bad.out"
expect_eq "…le service précédent répond toujours : alice acceptée" SUCCESS "$(verdict alice wifi-ctrl "Corp Wifi")"
expect_eq "…avec les anciennes règles (VLAN 120 renvoyé)" OK "$(eap alice wifi-ctrl "Corp Wifi" > "$D/o.txt"; python3 "$D/replycheck.py" "$D/o.txt" 120 "" 3600 ACL-IT Aruba-User-Role=it-staff)"

echo "== Chemin de la console : demande déposée, dépôt effacé après traitement =="
rm -rf "$D/gen/radius-pki" "$D/gen/radius-authz"; cp -r "$DEP" "$D/gen/radius-pki"; cp -r "$AZ" "$D/gen/radius-authz"; cp "$CL" "$D/gen/radius-clients.conf"
printf '{"action":"apply","pki":true,"authz":true}\n' > "$D/gen/.radius-request"
"$RAD" request >"$D/request.out" 2>&1; rc=$?; localize
expect_eq "request apply+pki+authz : code 0" 0 "$rc"
expect_eq "…dépôt des règles effacé" no "$([ -e "$D/gen/radius-authz" ] && echo yes || echo no)"
expect_eq "…dépôt PKI effacé" no "$([ -e "$D/gen/radius-pki" ] && echo yes || echo no)"
expect_eq "…demande effacée" no "$([ -e "$D/gen/.radius-request" ] && echo yes || echo no)"
expect_grep "…résultat publié : règles comptées" 'Règles d.accès : 7 règle' "$D/run/radius-result.json"
expect_eq "…alice acceptée" SUCCESS "$(verdict alice wifi-ctrl "Corp Wifi")"
# demande « authz » sans PKI : refusée sans rien installer
rm -rf "$D/gen/radius-authz"; cp -r "$AZ" "$D/gen/radius-authz"; cp "$CL" "$D/gen/radius-clients.conf"; printf '{"action":"apply","authz":true}\n' > "$D/gen/.radius-request"
"$RAD" request >"$D/request2.out" 2>&1; rc=$?
[ "$rc" -ne 0 ] || [ "$(rj "$D/run/radius-result.json" ok)" = False ] && ok "règles sans PKI par la console : refusées" || ko "règles sans PKI par la console"
expect_eq "…dépôt effacé malgré le refus" no "$([ -e "$D/gen/radius-authz" ] && echo yes || echo no)"
expect_eq "…le service précédent répond toujours" SUCCESS "$(verdict alice wifi-ctrl "Corp Wifi")"

echo "== Retrait des règles : retour au refus par défaut =="
deploy "$DEP"; rc=$?
expect_eq "déploiement sans règles : code 0" 0 "$rc"
expect_eq "…modules : plus de module LDAP" "always attr_filter eap preprocess" "$(find "$D/etc/mods-enabled" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
expect_eq "…statut publié : règles inactives" False "$(rj "$D/run/radius-status.json" authz.enabled)"
expect_eq "…alice, valide, est refusée" FAILURE "$(verdict alice wifi-ctrl "Corp Wifi")"
expect_grep "…journal : certificat valide, aucune règle d'accès" 'Login incorrect.*aucune regle d.acces' <(lastlog 8)
expect_eq "…plus de mot de passe de liaison dans l'arborescence" 0 "$(grep -rlF -- "$BINDPW" "$D/etc" 2>/dev/null | wc -l)"
expect_eq "…ni d'autorité LDAPS résiduelle" no "$([ -e "$D/etc/certs/ldap-ca.pem" ] && echo yes || echo no)"

echo "== Aucune divulgation du mot de passe de liaison =="
deploy "$DEP" "$AZ"
expect_eq "mot de passe : présent seulement dans le module LDAP (0640 root:freerad)" "$D/etc/mods-enabled/ldap" "$(grep -rlF -- "$BINDPW" "$D/etc" 2>/dev/null)"
expect_eq "…absent du dossier de dépôt de la console après traitement" 0 "$(grep -rlF -- "$BINDPW" "$D/gen" 2>/dev/null | wc -l)"
expect_eq "…absent de l'état et du résultat publiés" 0 "$(grep -rlF -- "$BINDPW" "$D/run" "$D/state" 2>/dev/null | wc -l)"
expect_nogrep "…absent de la sortie du démon" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" "$D/daemon.out"
expect_nogrep "…absent du journal de FreeRADIUS" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" "$RLOG"
psargs() { ps -eo args | grep -vF 'grep -qE'; }   # (le grep du test porte le motif sur sa propre ligne de commande : on l'écarte)
expect_nogrep "…absent des lignes de commande en cours" "$(printf '%s' "$BINDPW" | sed 's/[][\.*^$/]/\\&/g')" <(psargs)
expect_eq "…et la décision générée ne contient que des données entre apostrophes (pas d'expansion)" 0 "$(grep -cE '"[^"]*%\{[^}]*(Tunnel|Called)[^"]*"[^=]*==' "$D/etc/sites-available/ddibuntu" | head -1)"

finish
