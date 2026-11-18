#!/usr/bin/env bash
# Batterie 38 — SCEP de la PKI du DDI (0.14.8), sans conteneur ni PostgreSQL : (1) le helper pki-helper.py (analyse des demandes SCEP, lecture du défi déposé,
# publication de l'état) ; (2) la logique de ddibuntu-pki avec des bouchons (podman, psql, systemctl, curl) : alias activé et désactivé, équipement préenregistré
# avec les lignes de commande exactes envoyées à la CLI d'EJBCA, défi qui ne fuit nulle part, réarmement, annulation, péremption, refus.
# EJBCA Community n'a que le mode « CA » de SCEP (équipement préenregistré, mot de passe à usage unique) : le vrai EJBCA est vu par la batterie 39.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

H="$RFS/usr/local/lib/ddibuntu/pki-helper.py"
PKI="$RFS/usr/local/sbin/ddibuntu-pki"
T="$T_TMP"
W="$T/m"; mkdir -p "$W"
command -v openssl >/dev/null || { note "openssl absent : batterie ignorée"; finish; exit $?; }
ph() { python3 "$H" "$@"; }
pr() { printf '%s' "$1" | ph parse-request; }
refuse() { local why="$1" json="$2"; if pr "$json" >/dev/null 2>&1; then check "REFUS ATTENDU — $why" false; else check "refusée : $why" true; fi; }
b64() { openssl x509 -in "$1" -outform DER | base64 -w0; }

echo "== Helper : demandes SCEP =="
out="$(pr '{"action":"scep_enable"}')"; expect_eq "scep_enable : acceptée" "action	scep_enable" "$out"
out="$(pr '{"action":"scep_disable"}')"; expect_eq "scep_disable : acceptée" "action	scep_disable" "$out"
refuse "scep_enable avec un champ en trop" '{"action":"scep_enable","ca":"Lab-Sub"}'
refuse "scep_disable avec un champ en trop" '{"action":"scep_disable","force":true}'
OFF='{"action":"scep_offer","id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"network","cn":"sw-core-1.lab.test","o":"Laboratoire","c":"FR","dns":["SW-Core-1.Lab.Test"],"ip":["10.1.2.3"]}'
out="$(pr "$OFF")"; rc=$?
expect_eq "scep_offer : acceptée" 0 "$rc"
expect_eq "scep_offer : sortie canonique (le CN est rendu à part, DNS en minuscules)" "action	scep_offer
id	0123456789abcdef
ca	Lab-SubRSA
profile	network
dn	CN=sw-core-1.lab.test,O=Laboratoire,C=FR
altname	dNSName=sw-core-1.lab.test,iPAddress=10.1.2.3
cn	sw-core-1.lab.test" "$out"
out="$(pr '{"action":"scep_offer","id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"machine","cn":"pc01","dns":["pc01.lab.test"]}')"
expect_eq "scep_offer machine : acceptée" "cn	pc01" "$(printf '%s\n' "$out" | grep ^cn)"
OB='"id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"network","dns":["a.lab.test"]'
refuse "nom d'équipement avec une espace" '{"action":"scep_offer",'"$OB"',"cn":"Jean Dupont"}'
refuse "nom d'équipement avec une virgule (injection de composant)" '{"action":"scep_offer",'"$OB"',"cn":"x,O=Evil"}'
refuse "nom d'équipement commençant par un point" '{"action":"scep_offer",'"$OB"',"cn":".sw1"}'
refuse "nom d'équipement commençant par un tiret" '{"action":"scep_offer",'"$OB"',"cn":"-sw1"}'
refuse "nom d'équipement de 64 caractères" '{"action":"scep_offer",'"$OB"',"cn":"'"$(printf 'a%.0s' $(seq 1 64))"'"}'
refuse "nom d'équipement : entité de service superadmin" '{"action":"scep_offer",'"$OB"',"cn":"superadmin"}'
refuse "nom d'équipement : entité de service ejbca (casse ignorée)" '{"action":"scep_offer",'"$OB"',"cn":"EJBCA"}'
refuse "nom d'équipement réservé aux entités d'émission (ddi-)" '{"action":"scep_offer",'"$OB"',"cn":"ddi-0123456789abcdef"}'
refuse "nom d'équipement absent" '{"action":"scep_offer",'"$OB"'}'
refuse "identifiant absent" '{"action":"scep_offer","ca":"Lab-SubRSA","profile":"network","cn":"sw1","dns":["a.lab.test"]}'
refuse "identifiant en majuscules" '{"action":"scep_offer","id":"0123456789ABCDEF","ca":"Lab-SubRSA","profile":"network","cn":"sw1","dns":["a.lab.test"]}'
refuse "autorité avec une barre" '{"action":"scep_offer","id":"0123456789abcdef","ca":"a/b","profile":"network","cn":"sw1","dns":["a.lab.test"]}'
refuse "autorité ManagementCA" '{"action":"scep_offer","id":"0123456789abcdef","ca":"ManagementCA","profile":"network","cn":"sw1","dns":["a.lab.test"]}'
refuse "profil inconnu" '{"action":"scep_offer","id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"EMPTY","cn":"sw1","dns":["a.lab.test"]}'
refuse "équipement réseau sans SAN" '{"action":"scep_offer","id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"network","cn":"sw1"}'
refuse "SAN injectant un autre SAN" '{"action":"scep_offer","id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"network","cn":"sw1","dns":["a.lab.test,dNSName=evil.test"]}'
refuse "demande de plus de 4 Ko" '{"action":"scep_offer","id":"0123456789abcdef","ca":"Lab-SubRSA","profile":"network","cn":"'"$(head -c 5000 /dev/zero | tr '\0' 'a')"'","dns":["a.t"]}'
out="$(pr '{"action":"scep_rearm","id":"0123456789abcdef","cn":"sw1.lab.test"}')"
expect_eq "scep_rearm : acceptée" "action	scep_rearm
id	0123456789abcdef
cn	sw1.lab.test" "$out"
refuse "scep_rearm avec un champ en trop" '{"action":"scep_rearm","id":"0123456789abcdef","cn":"sw1","ca":"Lab-SubRSA"}'
refuse "scep_rearm sans identifiant" '{"action":"scep_rearm","cn":"sw1"}'
refuse "scep_rearm : entité de service" '{"action":"scep_rearm","id":"0123456789abcdef","cn":"superadmin"}'
refuse "scep_rearm : nom invalide" '{"action":"scep_rearm","id":"0123456789abcdef","cn":"a b"}'
out="$(pr '{"action":"scep_cancel","cn":"sw1.lab.test"}')"; expect_eq "scep_cancel : acceptée" "action	scep_cancel
cn	sw1.lab.test" "$out"
refuse "scep_cancel avec un champ en trop" '{"action":"scep_cancel","cn":"sw1","id":"0123456789abcdef"}'
refuse "scep_cancel : entité de service" '{"action":"scep_cancel","cn":"ejbca"}'
refuse "scep_cancel : entité d'émission" '{"action":"scep_cancel","cn":"ddi-0123456789abcdef"}'
refuse "scep_cancel : nom injectant du SQL" '{"action":"scep_cancel","cn":"x'"'"';drop table userdata"}'

echo "== Helper : défi déposé par la console =="
D="$T/dep"; mkdir -p "$D"
PWOK="ABCDEFGHJKLMNPQRSTUVWXYZ"
printf '%s' "$PWOK" > "$D/ok"; out="$(ph scep-pw "$D/ok")"; rc=$?
expect_eq "défi de 24 caractères : accepté" 0 "$rc"; expect_eq "défi rendu tel quel" "$PWOK" "$out"
printf '%s\n' "$PWOK" > "$D/nl"; expect_eq "défi suivi d'un retour à la ligne : accepté, sans le retour" "$PWOK" "$(ph scep-pw "$D/nl")"
printf '%s' "abcdefghijklmno" > "$D/short"; out="$(ph scep-pw "$D/short")"; expect_eq "défi de 15 caractères : refusé" ERR "${out%%	*}"
printf '%s' "$(printf 'a%.0s' $(seq 1 65))" > "$D/long"; out="$(ph scep-pw "$D/long")"; expect_eq "défi de 65 caractères : refusé" ERR "${out%%	*}"
printf '%s' "abcdefghij-lmnopqrstuv" > "$D/dash"; out="$(ph scep-pw "$D/dash")"; expect_eq "défi avec un tiret : refusé" ERR "${out%%	*}"
printf '%s' "abcdefghij klmnopqrstuv" > "$D/sp"; out="$(ph scep-pw "$D/sp")"; expect_eq "défi avec une espace : refusé" ERR "${out%%	*}"
printf '%s' "abcdefghijklmnopqrstu\"" > "$D/q"; out="$(ph scep-pw "$D/q")"; expect_eq "défi avec un guillemet : refusé" ERR "${out%%	*}"
head -c 400 /dev/zero | tr '\0' 'a' > "$D/big"; out="$(ph scep-pw "$D/big")"; expect_eq "fichier de plus de 256 octets : refusé" ERR "${out%%	*}"
out="$(ph scep-pw "$D/absent")"; expect_eq "fichier absent : refusé" ERR "${out%%	*}"
ln -s "$D/ok" "$D/link"; out="$(ph scep-pw "$D/link")"; expect_eq "lien symbolique : refusé (jamais suivi)" ERR "${out%%	*}"
mkdir "$D/dir"; out="$(ph scep-pw "$D/dir")"; expect_eq "répertoire : refusé" ERR "${out%%	*}"

echo "== Helper : état publié =="
NOW_MS=$(( $(date +%s) * 1000 ))
OLD_MS=$(( NOW_MS - 9 * 86400 * 1000 ))
{
  printf 'sw-wait\t10\t%s\t%s\tLab-SubRSA\t5010004\tCN=sw-wait,O=Lab,C=FR\tdNSName=sw-wait.lab.test\t\t\t\t\n' "$NOW_MS" "$NOW_MS"
  printf 'sw-old\t10\t%s\t%s\tLab-SubRSA\t5010004\tCN=sw-old\t\t\t\t\t\n' "$OLD_MS" "$OLD_MS"
  printf 'sw-done\t40\t%s\t%s\tLab-SubRSA\t5010002\tCN=sw-done\tdNSName=sw-done\t1311768467294899695\t1795001470000\t20\t0123456789abcdef0123456789abcdef01234567\n' "$NOW_MS" "$NOW_MS"
  printf 'sw-rev\t40\t%s\t%s\tLab-SubRSA\t5010003\tCN=sw-rev\t\t255\t1795001470000\t40\t0123456789abcdef0123456789abcdef01234567\n' "$NOW_MS" "$NOW_MS"
  printf 'sw-fail\t11\t%s\t%s\tLab-SubRSA\t5010001\tCN=sw-fail\t\t\t\t\t\n' "$NOW_MS" "$NOW_MS"
  printf 'sw-gone\t50\t%s\t%s\tLab-SubRSA\t5010004\tCN=sw-gone\t\t\t\t\t\n' "$NOW_MS" "$NOW_MS"
  printf 'sw-odd\t30\t%s\t%s\t\t99\tCN=sw-odd\t\t\t\t\t\n' "$NOW_MS" "$NOW_MS"
  printf 'bad name\t10\t1\t1\tx\t1\tx\t\t\t\t\t\n'
  printf 'court\t10\n'
  printf 'sw-ctl\t10\t%s\t%s\tLab-SubRSA\t5010004\tCN=sw-ctl\001\033[31m\tdNSName=x\t\t\t\t\n' "$NOW_MS" "$NOW_MS"
} > "$T/rows.tsv"
ph scep-publish 1 7 pki.lab.test 8080 < "$T/rows.tsv" > "$T/pub.json"; expect_eq "scep-publish : code 0" 0 $?
J() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
v = d
for k in sys.argv[2].split("."):
    v = v[int(k)] if isinstance(v, list) else v.get(k) if isinstance(v, dict) else None
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$@" 2>/dev/null; }
expect_eq "publié : activé" true "$(J "$T/pub.json" enabled)"
expect_eq "publié : alias fixe" ddibuntu "$(J "$T/pub.json" alias)"
expect_eq "publié : chemin" /ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe "$(J "$T/pub.json" path)"
expect_eq "publié : adresse complète (nom public, port 8080)" http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe "$(J "$T/pub.json" url)"
expect_eq "publié : durée de l'attente" 7 "$(J "$T/pub.json" offerDays)"
expect_eq "publié : 7 équipements, les lignes invalides ignorées" 8 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["offers"]))' "$T/pub.json")"
st() { python3 -c 'import json,sys
for o in json.load(open(sys.argv[1]))["offers"]:
    if o["cn"] == sys.argv[2]: print(o[sys.argv[3]] if o[sys.argv[3]] is not None else "")' "$T/pub.json" "$1" "$2"; }
expect_eq "sw-wait : en attente" waiting "$(st sw-wait state)"
expect_eq "sw-wait : profil réseau" network "$(st sw-wait profile)"
expect_eq "sw-wait : autorité" Lab-SubRSA "$(st sw-wait ca)"
expect_eq "sw-old : attente dépassée (9 jours > 7)" expired "$(st sw-old state)"
expect_eq "sw-done : certificat délivré" issued "$(st sw-done state)"
expect_eq "sw-done : série en hexadécimal" 1234567890ABCDEF "$(python3 -c 'print("%X" % 1311768467294899695)')"
expect_eq "sw-done : série publiée en hexadécimal majuscules" "$(python3 -c 'print("%X" % 1311768467294899695)')" "$(python3 -c 'import json,sys
for o in json.load(open(sys.argv[1]))["offers"]:
    if o["cn"] == "sw-done": print(o["cert"]["serial"])' "$T/pub.json")"
expect_eq "sw-done : profil machine" machine "$(st sw-done profile)"
expect_eq "sw-done : pas d'échéance d'attente" "" "$(st sw-done expiresAt)"
expect_eq "sw-rev : certificat délivré mais révoqué" true "$(python3 -c 'import json,sys
for o in json.load(open(sys.argv[1]))["offers"]:
    if o["cn"] == "sw-rev": print(str(o["cert"]["revoked"]).lower())' "$T/pub.json")"
expect_eq "sw-fail : refusé" failed "$(st sw-fail state)"
expect_eq "sw-gone : entité révoquée" revoked "$(st sw-gone state)"
expect_eq "sw-odd : état inconnu" other "$(st sw-odd state)"
expect_eq "sw-odd : profil inconnu" "" "$(st sw-odd profile)"
check "caractères de contrôle retirés du nom distinctif publié" bash -c "! grep -q $'\\\\\\\\u0001\\|\\\\\\\\u001b' '$T/pub.json'"
ph scep-publish 0 7 pki.lab.test 8080 < /dev/null > "$T/pub0.json"
expect_eq "sans équipement : liste vide" 0 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["offers"]))' "$T/pub0.json")"
expect_eq "alias absent : désactivé" false "$(J "$T/pub0.json" enabled)"
check "mauvais nombre d'arguments refusé" bash -c "! python3 '$H' scep-publish 1 7 < /dev/null"

echo "== Racine : bouchons =="
B="$T/bin"; mkdir -p "$B" "$T/etc" "$T/data/ca/Lab-Sub" "$T/data/ca/Lab-SubRSA" "$T/data/ca/Lab-Root" "$T/quad" "$T/run" "$T/gen/pki-in" "$T/profiles"
LOG="$T/calls.log"; PLOG="$T/psql.log"; : > "$LOG"; : > "$PLOG"; : > "$T/ejbca.log"
printf '{"kind":"root","signedBy":"self","alg":"rsa3072","createdAt":1700000000}' > "$T/data/ca/Lab-Root/meta.json"
printf '{"kind":"issuing","signedBy":"Lab-Root","alg":"ecp256","createdAt":1700000100}' > "$T/data/ca/Lab-Sub/meta.json"
printf '{"kind":"issuing","signedBy":"Lab-Root","alg":"rsa3072","createdAt":1700000200}' > "$T/data/ca/Lab-SubRSA/meta.json"
printf '{"hostname":"pki.lab.test","tag":"9.6.3","digest":"sha256:%s","nets":"","installedAt":1700000000}' "$(printf 'a%.0s' $(seq 1 64))" > "$T/etc/instance.json"
printf 'HTTPSERVER_HOSTNAME=pki.lab.test\n' > "$T/etc/ejbca.env"
for n in DDI-RADIUS-Server-5010001 DDI-Client-Machine-5010002 DDI-Client-User-5010003 DDI-Network-Device-5010004; do printf '<java/>' > "$T/profiles/certprofile_$n.xml"; done
printf '<java/>' > "$T/profiles/entityprofile_DDI-Endentity-5020001.xml"
openssl ecparam -name prime256v1 -genkey -noout -out "$W/root.key" 2>/dev/null
openssl req -x509 -new -key "$W/root.key" -days 3650 -subj "/C=FR/O=Laboratoire/CN=Lab Root CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/root.pem" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$W/ca.ext"
openssl ecparam -name prime256v1 -genkey -noout -out "$W/ec.key" 2>/dev/null
openssl req -new -key "$W/ec.key" -subj "/C=FR/O=Laboratoire/CN=Emettrice EC" -out "$W/ec.csr" 2>/dev/null
openssl x509 -req -in "$W/ec.csr" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial -days 1825 -extfile "$W/ca.ext" -out "$W/ec.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$W/rsa.key" -subj "/C=FR/O=Laboratoire/CN=Emettrice RSA" -out "$W/rsa.csr" 2>/dev/null
openssl x509 -req -in "$W/rsa.csr" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial -days 1825 -extfile "$W/ca.ext" -out "$W/rsa.pem" 2>/dev/null
for f in root.pem ec.pem rsa.pem; do check "matériel : $f fabriqué" test -s "$W/$f"; done
{
  printf 'Lab-Root\t1\tCN=Lab Root CA,O=Laboratoire,C=FR\t1001\t%s\n' "$(b64 "$W/root.pem")"
  printf 'Lab-Sub\t1\tCN=Emettrice EC,O=Laboratoire,C=FR\t1002\t%s\n' "$(b64 "$W/ec.pem")"
  printf 'Lab-SubRSA\t1\tCN=Emettrice RSA,O=Laboratoire,C=FR\t1003\t%s\n' "$(b64 "$W/rsa.pem")"
} > "$T/cas.tsv"
printf 'Lab-Root\t1\tCN=Lab Root CA,O=Laboratoire,C=FR\t1001\nLab-Sub\t1\tCN=Emettrice EC,O=Laboratoire,C=FR\t1002\nLab-SubRSA\t1\tCN=Emettrice RSA,O=Laboratoire,C=FR\t1003\n' > "$T/cadb.tsv"
touch "$T/db.exists" "$T/healthy" "$T/active"; echo 9 > "$T/tables"
# « base d'EJBCA » : la table userdata est un fichier TSV tenu par ce petit programme (les bouchons de podman et de psql l'appellent)
cat > "$T/ee.py" <<'PY'
import sys, time, os
F = os.environ["EE_FILE"]
EE = {"DDI-Endentity": "5020001"}
CP = {"DDI-RADIUS-Server": "5010001", "DDI-Client-Machine": "5010002", "DDI-Client-User": "5010003", "DDI-Network-Device": "5010004"}
def rows():
    try:
        return [l.rstrip("\n").split("\t") for l in open(F) if l.strip()]
    except OSError:
        return []
def save(r):
    open(F, "w").write("".join("\t".join(x) + "\n" for x in r))
now = lambda: str(int(time.time() * 1000))
c, a = sys.argv[1], sys.argv[2:]
if c == "add":     # user ca certprofile dn san eeprofile
    if any(r[0] == a[0] for r in rows()): sys.exit(1)
    save(rows() + [[a[0], "10", now(), now(), a[1], CP.get(a[2], "0"), a[3], a[4], EE.get(a[5], "1")]])
elif c == "setstatus":
    r = rows()
    for x in r:
        if x[0] == a[0]: x[1] = a[1]; x[3] = now()
    save(r)
elif c == "del":
    save([x for x in rows() if x[0] != a[0]])
elif c == "age":   # user secondes : vieillit l'entité
    r = rows()
    for x in r:
        if x[0] == a[0]: x[2] = str(int(x[2]) - int(a[1]) * 1000); x[3] = str(int(x[3]) - int(a[1]) * 1000)
    save(r)
elif c == "status":   # user profil : état d'une entité de ce profil, hors entités d'émission
    for x in rows():
        if x[0] == a[0] and x[8] == a[1] and not x[0].startswith("ddi-"): print(x[1])
elif c == "taken":
    if any(x[0] == a[0] for x in rows()): print(1)
elif c == "expired":   # profil coupure_ms
    for x in sorted(rows(), key=lambda x: int(x[3])):
        if x[8] == a[0] and not x[0].startswith("ddi-") and x[1] in ("10", "11") and int(x[3]) < int(a[1]): print(x[0])
elif c == "publish":   # profil
    for x in rows():
        if x[8] == a[0] and not x[0].startswith("ddi-"):
            extra = ["", "", "", ""]
            p = os.environ["EE_FILE"] + ".cert." + x[0]
            if os.path.exists(p): extra = open(p).read().rstrip("\n").split("\t")
            print("\t".join(x[:8] + extra))
PY
export EE_FILE="$T/userdata.tsv"; : > "$EE_FILE"
cat > "$B/podman" <<EOF
#!/bin/bash
echo "podman \$*" >> "$LOG"
[ "\$1" = exec ] || exit 0
a=("\$@"); i=0; while [ "\$i" -lt "\$#" ] && [ "\${a[\$i]}" != /opt/keyfactor/bin/ejbca.sh ]; do i=\$((i+1)); done
s=("\${a[@]:\$((i+1))}")
echo "ejbca \${s[*]}" >> "$T/ejbca.log"
opt() { local k="\$1" j; for ((j=0; j<\${#s[@]}; j++)); do [ "\${s[\$j]}" = "\$k" ] && { printf '%s' "\${s[\$((j+1))]}"; return; }; done; }
case "\${s[0]} \${s[1]}" in
  "ca importprofiles")
    [ -f "$T/fail.import" ] && { echo "boom import" >&2; exit 1; }
    d="\${s[3]}"; d="$T/data/persistent/work/\${d#/mnt/persistent/work/}"
    for f in "\$d"/*.xml; do b="\${f##*/}"; b="\${b%.xml}"; b="\${b#certprofile_}"; b="\${b#entityprofile_}"; touch "$T/prof.\${b%-*}"; done ;;
  "ca editca")
    en=""; ef=""; ev=""; for ((j=2; j<\${#s[@]}; j++)); do case "\${s[\$j]}" in --caname) en="\${s[\$((j+1))]}";; --field) ef="\${s[\$((j+1))]}";; --value) ev="\${s[\$((j+1))]}";; esac; done
    [ "\$ef" = doEnforceUniqueDistinguishedName ] && [ "\$ev" = false ] && touch "$T/dnoff.\$en" ;;
  "config scep")
    case "\${s[2]}" in
      addalias) [ -f "$T/fail.addalias" ] && { echo "boom addalias" >&2; exit 1; }; touch "$T/alias.exists" ;;
      updatealias) [ -f "$T/fail.updatealias" ] && { echo "boom updatealias" >&2; exit 1; } ;;
      removealias) [ -f "$T/fail.removealias" ] && exit 0; rm -f "$T/alias.exists" ;;
    esac ;;
  "ra addendentity")
    [ -f "$T/fail.add" ] && { echo "boom add \$(opt --password)" >&2; exit 1; }
    python3 "$T/ee.py" add "\$(opt --username)" "\$(opt --caname)" "\$(opt --certprofile)" "\$(opt --dn)" "\$(opt --altname)" "\$(opt --eeprofile)" || exit 1 ;;
  "ra setpwd") [ -f "$T/fail.setpwd" ] && { echo "boom setpwd \$(opt --password)" >&2; exit 1; }; echo "\$(opt --password)" > "$T/pw.\$(opt --username)" ;;
  "ra setendentitystatus") python3 "$T/ee.py" setstatus "\$(opt --username)" "\$(opt -S)" ;;
  "ra delendentity") [ -f "$T/fail.del" ] && exit 1; python3 "$T/ee.py" del "\$(opt --username)" ;;
esac
exit 0
EOF
cat > "$B/systemctl" <<EOF
#!/bin/bash
case "\$1" in
  is-active) [ -f "$T/active" ] ;;
  show) date -u -d "-20 seconds" '+%a %Y-%m-%d %H:%M:%S UTC' ;;
esac
exit 0
EOF
cat > "$B/psql" <<EOF
#!/bin/bash
sql="\$(cat)"
{ echo "psql \$*"; printf '%s\n' "\$sql"; } >> "$PLOG"
n=""; d=""; s=""; u=""; p=""; t=""
while [ "\$#" -gt 0 ]; do case "\$1" in -v) shift; case "\$1" in n=*) n="\${1#n=}";; d=*) d="\${1#d=}";; s=*) s="\${1#s=}";; u=*) u="\${1#u=}";; p=*) p="\${1#p=}";; t=*) t="\${1#t=}";; esac;; esac; shift; done
export EE_FILE="$T/userdata.tsv"
case "\$sql" in
  *"pg_database where datname = 'ejbca'"*) echo exists ;;
  *information_schema.tables*) cat "$T/tables" ;;
  *"from cadata where name <> 'ManagementCA'"*) wc -l < "$T/cadb.tsv" ;;
  *"doEnforceUniqueDistinguishedName"*) [ -f "$T/dnoff.\$n" ] || echo 1 ;;
  *"select 1 from cadata where name"*) awk -F'\t' -v n="\$n" '\$1==n{f=1} END{if(f) print 1}' "$T/cadb.tsv" ;;
  *"select status from cadata"*) awk -F'\t' -v n="\$n" '\$1==n{print \$2}' "$T/cadb.tsv" ;;
  *"select subjectdn from cadata"*) awk -F'\t' -v n="\$n" '\$1==n{print \$3}' "$T/cadb.tsv" ;;
  *"select caid from cadata"*) awk -F'\t' -v n="\$n" '\$1==n{print \$4}' "$T/cadb.tsv" ;;
  *"from certificateprofiledata"*|*"from endentityprofiledata"*) [ -f "$T/prof.\$n" ] && echo 1 ;;
  *"from globalconfigurationdata"*) [ -f "$T/alias.exists" ] && echo 1 ;;
  *"select status from userdata where username"*) python3 "$T/ee.py" status "\$u" "\$p" ;;
  *"select 1 from userdata where username"*) python3 "$T/ee.py" taken "\$u" ;;
  *"select username from userdata where endentityprofileid"*) python3 "$T/ee.py" expired "\$p" "\$t" ;;
  *"from userdata u"*) python3 "$T/ee.py" publish "\$p" ;;
  *"left join certificatedata"*) cat "$T/cas.tsv" ;;
  *"from crldata"*) : ;;
esac
exit 0
EOF
cat > "$B/curl" <<EOF
#!/bin/bash
[ -f "$T/healthy" ] && { printf 'ALLOK'; exit 0; }
exit 22
EOF
printf '#!/bin/bash\n' > "$B/fw"; chmod +x "$B"/*
PKI_UID="$(id -u)"
export DDI_PKI_ALLOW_USER=1 DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_GENERATED_DIR="$T/gen" DDI_RUN_DIR="$T/run"
export DDI_PKI_ETC="$T/etc" DDI_PKI_DATA="$T/data" DDI_PKI_QUADLET_DIR="$T/quad" DDI_PKI_PODMAN="$B/podman" DDI_PKI_PROFILE_DIR="$T/profiles"
export DDI_PKI_SYSTEMCTL="$B/systemctl" DDI_PKI_CURL="$B/curl" DDI_FW_BIN="$B/fw" DDI_PKI_PSQL="$B/psql" DDI_PKI_LOCK="$T/lock" DDI_PKI_UID="$PKI_UID"
export DDI_PKI_NO_UPDATE_CHECK=1
G="$T/gen"; R="$T/run"; IN="$G/pki-in"
req() { printf '%s' "$1" > "$G/.pki-request"; "$PKI" request >"$T/req.out" 2>&1; RES_OK="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$R/pki-result.json")"; RES_MSG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["message"])' "$R/pki-result.json")"; RES_REF="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ref",""))' "$R/pki-result.json")"; [[ -z "${DEBUG_REQ:-}" ]] || { cat "$T/req.out" >&2; cat "$T/ejbca.log" >&2; }; }
reset_ee() { rm -f "$T"/fail.*; : > "$T/ejbca.log"; }
PW1="ABCDEFGHJKLMNPQRSTUVWXYZ"; PW2="23456789ABCDEFGHJKLMNPQR"; PW3="MNPQRSTUVWXYZ23456789ABC"
dep() { printf '%s' "$2" > "$IN/$1.scepw"; chmod 600 "$IN/$1.scepw"; }
OFFER() { printf '{"action":"scep_offer","id":"%s","ca":"%s","profile":"%s","cn":"%s","o":"Laboratoire","c":"FR","dns":["%s.lab.test"]}' "$1" "${2:-Lab-SubRSA}" "${3:-network}" "$4" "$4"; }
pubj() { J "$R/pki-scep.json" "$@"; }
"$PKI" status >/dev/null 2>&1
check "état publié avec les autorités de l'exemple" test -s "$R/pki-ca/Lab-SubRSA/chain.pem"
expect_eq "la clé de l'émettrice RSA est publiée comme RSA" RSA "$(J "$R/pki-cas.json" cas.2.keyAlg)"
expect_eq "la clé de l'émettrice EC est publiée comme EC" EC "$(J "$R/pki-cas.json" cas.1.keyAlg)"
check "pki-scep.json publié par « status »" test -s "$R/pki-scep.json"
expect_eq "SCEP désactivé au départ" false "$(pubj enabled)"
expect_eq "aucun équipement au départ" 0 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["offers"]))' "$R/pki-scep.json")"
expect_eq "adresse publiée" http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe "$(pubj url)"

echo "== Activation =="
reset_ee; I=aaaaaaaaaaaaaaa1; dep $I $PW1
req "$(OFFER $I Lab-SubRSA network sw1)"
expect_eq "préenregistrer sans SCEP actif : refusé" false "$RES_OK"; check "motif : SCEP pas activé" grep -qi "pas activé" <<< "$RES_MSG"
check "aucune entité créée" bash -c "! grep -q addendentity '$T/ejbca.log'"
check "le défi déposé est consommé même en cas de refus" test ! -e "$IN/$I.scepw"
reset_ee; : > "$T/imported.log"; rm -f "$T"/prof.*
req '{"action":"scep_enable"}'
expect_eq "activation acceptée" true "$RES_OK"; check "message" grep -q "SCEP activé" <<< "$RES_MSG"
check "profils importés avant tout (les équipements en dépendent)" grep -q "ca importprofiles" "$T/ejbca.log"
check "alias créé sous son nom fixe" grep -q "config scep addalias --alias ddibuntu" "$T/ejbca.log"
check "la réponse GetCACert ne contient que l'émettrice (returnCaChainInGetCaCert=false)" grep -q "config scep updatealias --alias ddibuntu --key returnCaChainInGetCaCert --value false" "$T/ejbca.log"
check "le mode RA n'est jamais demandé (absent de la Community)" bash -c "! grep -qi 'operationmode\|ra.authPwd' '$T/ejbca.log'"
expect_eq "état publié : activé" true "$(pubj enabled)"
reset_ee
req '{"action":"scep_enable"}'
expect_eq "seconde activation : acceptée" true "$RES_OK"
check "seconde activation : l'alias n'est pas recréé" bash -c "! grep -q addalias '$T/ejbca.log'"
check "seconde activation : le réglage est reposé (alias pris en main)" grep -q "updatealias --alias ddibuntu" "$T/ejbca.log"
reset_ee; touch "$T/fail.updatealias"; rm -f "$T/alias.exists"
req '{"action":"scep_enable"}'
expect_eq "mise à jour de l'alias en échec : activation refusée" false "$RES_OK"
rm -f "$T/fail.updatealias"; reset_ee; rm -f "$T/alias.exists"; touch "$T/fail.addalias"
req '{"action":"scep_enable"}'
expect_eq "création de l'alias en échec : activation refusée" false "$RES_OK"
rm -f "$T/fail.addalias"; reset_ee; rm -f "$T/healthy"
req '{"action":"scep_enable"}'
expect_eq "PKI qui ne répond pas : activation refusée" false "$RES_OK"
check "rien n'est envoyé à EJBCA" bash -c "! grep -q 'config scep' '$T/ejbca.log'"
touch "$T/healthy"; reset_ee
req '{"action":"scep_enable"}'; expect_eq "réactivation après la panne" true "$RES_OK"

echo "== Préenregistrement d'un équipement =="
reset_ee; I=aaaaaaaaaaaaaaa2; dep $I $PW1
req "$(OFFER $I Lab-SubRSA network sw1)"
expect_eq "équipement préenregistré" true "$RES_OK"; check "message : nom, autorité, profil, délai" grep -q "sw1.*Lab-SubRSA.*DDI-Network-Device.*7 jours" <<< "$RES_MSG"
expect_eq "la référence de la demande est rendue à la console" "$I" "$RES_REF"
AE="$(grep 'ra addendentity' "$T/ejbca.log" | head -n1)"
check "entité : nom d'utilisateur = nom de l'équipement" grep -q -- "--username sw1 " <<< "$AE"
check "entité : nom distinctif du formulaire" grep -q -- "--dn CN=sw1,O=Laboratoire,C=FR" <<< "$AE"
check "entité : autorité demandée" grep -q -- "--caname Lab-SubRSA" <<< "$AE"
check "entité : profil de certificat du DDI" grep -q -- "--certprofile DDI-Network-Device" <<< "$AE"
check "entité : profil d'entité du DDI" grep -q -- "--eeprofile DDI-Endentity" <<< "$AE"
check "entité : SAN du formulaire" grep -q -- "--altname dNSName=sw1.lab.test" <<< "$AE"
check "entité : jeton géré par l'équipement (la clé reste chez lui)" grep -q -- "--token USERGENERATED" <<< "$AE"
check "entité : le mot de passe est le défi déposé" grep -q -- "--password $PW1" <<< "$AE"
check "DN unique retiré sur l'autorité avant l'entité (un équipement remplacé garde son nom)" bash -c "[ \$(grep -n 'ca editca --caname Lab-SubRSA' '$T/ejbca.log' | head -1 | cut -d: -f1) -lt \$(grep -n 'ra addendentity' '$T/ejbca.log' | head -1 | cut -d: -f1) ]"
check "le dépôt du défi est consommé" test ! -e "$IN/$I.scepw"
check "le défi n'est ni dans le résultat publié ni dans la sortie de la demande" bash -c "! grep -rq '$PW1' '$R/pki-result.json' '$T/req.out'"
check "le défi n'est dans aucun fichier publié" bash -c "! grep -rq '$PW1' '$R'"
check "le défi n'est pas dans la base (requêtes envoyées à PostgreSQL)" bash -c "! grep -q '$PW1' '$PLOG'"
check "le défi n'est pas dans le journal des appels de podman (seul l'appel de la CLI le porte, pour root)" bash -c "[ \$(grep -c '$PW1' '$LOG') -le 1 ]"
expect_eq "état publié : l'équipement attend son inscription" waiting "$(J "$R/pki-scep.json" offers.0.state)"
expect_eq "état publié : nom" sw1 "$(J "$R/pki-scep.json" offers.0.cn)"
expect_eq "état publié : échéance = 7 jours après la préparation" 604800 "$(python3 -c 'import json,sys; o=json.load(open(sys.argv[1]))["offers"][0]; print(o["expiresAt"]-o["modifiedAt"])' "$R/pki-scep.json")"
check "état publié : jamais de défi, d'empreinte de mot de passe ni de mot « password »" bash -c "! grep -qi 'password\|passwd\|pwd' '$R/pki-scep.json'"
echo "-- refus"
refused() { reset_ee; dep "$1" "$2"; req "$3"; expect_eq "$4" false "$RES_OK"; check "$4 : le défi est consommé" test ! -e "$IN/$1.scepw"; check "$4 : aucune entité créée" bash -c "! grep -q addendentity '$T/ejbca.log'"; }
refused aaaaaaaaaaaaaaa3 $PW2 "$(OFFER aaaaaaaaaaaaaaa3 Lab-Sub network sw2)" "refus : émettrice ECDSA (SCEP chiffre pour une clé RSA)"
check "motif : il faut du RSA" grep -qi "RSA" <<< "$RES_MSG"
refused aaaaaaaaaaaaaaa4 $PW2 "$(OFFER aaaaaaaaaaaaaaa4 Lab-Root network sw2)" "refus : une racine ne délivre pas de certificats finaux"
refused aaaaaaaaaaaaaaa5 $PW2 "$(OFFER aaaaaaaaaaaaaaa5 Lab-Inconnue network sw2)" "refus : autorité inconnue"
refused aaaaaaaaaaaaaaa6 $PW2 "$(OFFER aaaaaaaaaaaaaaa6 Lab-SubRSA network sw1)" "refus : nom déjà enregistré"
check "motif : « Renouveler » est proposé" grep -q "Renouveler" <<< "$RES_MSG"
refused aaaaaaaaaaaaaaa7 abcdef "$(OFFER aaaaaaaaaaaaaaa7 Lab-SubRSA network sw3)" "refus : défi trop court"
reset_ee; req "$(OFFER aaaaaaaaaaaaaaa8 Lab-SubRSA network sw3)"; expect_eq "refus : défi absent" false "$RES_OK"
sed -i 's/^Lab-SubRSA\t1\t/Lab-SubRSA\t2\t/' "$T/cadb.tsv"
refused aaaaaaaaaaaaaaa9 $PW2 "$(OFFER aaaaaaaaaaaaaaa9 Lab-SubRSA network sw3)" "refus : autorité pas active"
sed -i 's/^Lab-SubRSA\t2\t/Lab-SubRSA\t1\t/' "$T/cadb.tsv"
rm -f "$T/prof.DDI-Network-Device"; mv "$T/profiles/certprofile_DDI-Network-Device-5010004.xml" "$T/x.xml"
refused aaaaaaaaaaaaaab1 $PW2 "$(OFFER aaaaaaaaaaaaaab1 Lab-SubRSA network sw3)" "refus : profil fourni absent du disque"
mv "$T/x.xml" "$T/profiles/certprofile_DDI-Network-Device-5010004.xml"
reset_ee; dep aaaaaaaaaaaaaab2 $PW2; touch "$T/fail.add"; req "$(OFFER aaaaaaaaaaaaaab2 Lab-SubRSA network sw3)"
expect_eq "EJBCA refuse l'entité : demande refusée" false "$RES_OK"
check "refus d'EJBCA : le défi n'apparaît pas dans le message" bash -c "! grep -q '$PW2' '$R/pki-result.json'"
check "refus d'EJBCA : le défi n'apparaît pas dans la sortie" bash -c "! grep -q '$PW2' '$T/req.out'"
reset_ee; dep aaaaaaaaaaaaaab3 $PW2; req '{"action":"scep_offer","id":"aaaaaaaaaaaaaab3","ca":"Lab-SubRSA","profile":"network","cn":"sw3","dns":["a.lab.test"],"mail":["x@y.test"]}'
expect_eq "refus : demande invalide (SAN non permis)" false "$RES_OK"
check "refus : le défi d'une demande invalide est tout de même consommé" test ! -e "$IN/aaaaaaaaaaaaaab3.scepw"
echo "-- autres profils"
for pr in server machine; do
  reset_ee; I="bbbbbbbbbbbbbbb$([[ "$pr" = server ]] && echo 1 || echo 2)"; dep "$I" $PW2; req "$(OFFER "$I" Lab-SubRSA $pr "dev-$pr")"; expect_eq "profil $pr : accepté" true "$RES_OK"
  check "profil $pr transmis à EJBCA" grep -q -- "--certprofile $([[ "$pr" = server ]] && echo DDI-RADIUS-Server || echo DDI-Client-Machine)" "$T/ejbca.log"
done
reset_ee; dep bbbbbbbbbbbbbbb3 $PW2; req '{"action":"scep_offer","id":"bbbbbbbbbbbbbbb3","ca":"Lab-SubRSA","profile":"user","cn":"jdupont","mail":["j.dupont@lab.test"],"upn":["jdupont@lab.test"]}'
expect_eq "profil utilisateur : accepté" true "$RES_OK"
check "profil utilisateur : SAN mail puis upn" grep -q -- "--altname rfc822Name=j.dupont@lab.test,upn=jdupont@lab.test" "$T/ejbca.log"

echo "== Réarmement =="
reset_ee; python3 "$T/ee.py" setstatus sw1 40; rm -f "$T/pw.sw1"
"$PKI" status >/dev/null 2>&1; expect_eq "équipement inscrit : état publié « délivré »" issued "$(J "$R/pki-scep.json" offers.0.state)"
dep ccccccccccccccc1 $PW3; req '{"action":"scep_rearm","id":"ccccccccccccccc1","cn":"sw1"}'
expect_eq "réarmement accepté" true "$RES_OK"; check "message" grep -q "nouvelle inscription" <<< "$RES_MSG"
check "nouveau défi posé" grep -q -- "ra setpwd --username sw1 --password $PW3" "$T/ejbca.log"
check "état remis à « nouveau » (10)" grep -q -- "ra setendentitystatus --username sw1 -S 10" "$T/ejbca.log"
check "le nouveau défi est posé AVANT la remise en état (jamais d'entité prête avec l'ancien défi)" bash -c "[ \$(grep -n 'ra setpwd' '$T/ejbca.log' | head -1 | cut -d: -f1) -lt \$(grep -n 'ra setendentitystatus' '$T/ejbca.log' | head -1 | cut -d: -f1) ]"
expect_eq "état publié : de nouveau en attente" waiting "$(J "$R/pki-scep.json" offers.0.state)"
check "le défi est consommé et n'apparaît nulle part" bash -c "[ ! -e '$IN/ccccccccccccccc1.scepw' ] && ! grep -rq '$PW3' '$R' '$T/req.out'"
reset_ee; dep ccccccccccccccc2 $PW3; req '{"action":"scep_rearm","id":"ccccccccccccccc2","cn":"inconnu"}'
expect_eq "réarmer un nom inconnu : refusé" false "$RES_OK"; check "rien n'est envoyé à EJBCA" bash -c "! grep -q 'ra set' '$T/ejbca.log'"
python3 - "$T/userdata.tsv" <<'PY'
import sys
p = sys.argv[1]
open(p, "a").write("superadmin\t10\t1\t1\tManagementCA\t1\tCN=SuperAdmin\t\t1\n")
PY
reset_ee; dep ccccccccccccccc3 $PW3; req '{"action":"scep_rearm","id":"ccccccccccccccc3","cn":"superadmin"}'
expect_eq "réarmer une entité de service d'EJBCA : refusé" false "$RES_OK"; check "le mot de passe du superadmin n'est pas touché" bash -c "! grep -q 'ra set' '$T/ejbca.log'"
reset_ee; dep ccccccccccccccc4 $PW3; touch "$T/fail.setpwd"; python3 "$T/ee.py" setstatus sw1 40; req '{"action":"scep_rearm","id":"ccccccccccccccc4","cn":"sw1"}'
expect_eq "setpwd en échec : réarmement refusé" false "$RES_OK"
check "setpwd en échec : l'état de l'entité n'est pas modifié" bash -c "! grep -q 'setendentitystatus' '$T/ejbca.log'"
check "setpwd en échec : le défi n'apparaît pas dans le message" bash -c "! grep -q '$PW3' '$R/pki-result.json'"
expect_eq "setpwd en échec : l'équipement reste « délivré »" issued "$(J "$R/pki-scep.json" offers.0.state)"
reset_ee; dep ccccccccccccccc5 $PW3; rm -f "$T/alias.exists"; req '{"action":"scep_rearm","id":"ccccccccccccccc5","cn":"sw1"}'
expect_eq "réarmer sans SCEP actif : refusé" false "$RES_OK"
reset_ee; req '{"action":"scep_enable"}'

echo "== Annulation =="
reset_ee; req '{"action":"scep_cancel","cn":"sw1"}'
expect_eq "annulation acceptée" true "$RES_OK"; check "message : les certificats restent" grep -q "certificats" <<< "$RES_MSG"
check "entité supprimée dans EJBCA (force)" grep -q -- "ra delendentity --username sw1 -force" "$T/ejbca.log"
expect_eq "l'équipement a disparu de la liste publiée" "" "$(python3 -c 'import json,sys
print(",".join(o["cn"] for o in json.load(open(sys.argv[1]))["offers"] if o["cn"] == "sw1"))' "$R/pki-scep.json")"
reset_ee; req '{"action":"scep_cancel","cn":"sw1"}'; expect_eq "annuler deux fois : refusé" false "$RES_OK"
reset_ee; req '{"action":"scep_cancel","cn":"superadmin"}'; expect_eq "annuler une entité de service : refusé" false "$RES_OK"
check "l'entité de service n'est jamais supprimée" bash -c "! grep -q 'delendentity' '$T/ejbca.log' && grep -q '^superadmin' '$T/userdata.tsv'"
python3 "$T/ee.py" add "ddi-aaaaaaaaaaaaaaaa" Lab-Sub DDI-Network-Device "CN=x" "" DDI-Endentity
reset_ee; req '{"action":"scep_cancel","cn":"ddi-aaaaaaaaaaaaaaaa"}'; expect_eq "annuler une entité d'émission : refusé (nom invalide)" false "$RES_OK"
python3 "$T/ee.py" del "ddi-aaaaaaaaaaaaaaaa"
reset_ee; python3 "$T/ee.py" add pc9 Lab-SubRSA DDI-Network-Device "CN=pc9" "" "autre-profil"; req '{"action":"scep_cancel","cn":"pc9"}'
expect_eq "annuler une entité d'un autre profil que celui du DDI : refusé" false "$RES_OK"
python3 "$T/ee.py" del pc9
reset_ee; python3 "$T/ee.py" add sw-ko Lab-SubRSA DDI-Network-Device "CN=sw-ko" "" DDI-Endentity; touch "$T/fail.del"; req '{"action":"scep_cancel","cn":"sw-ko"}'
expect_eq "EJBCA ne supprime pas : annulation refusée" false "$RES_OK"
rm -f "$T/fail.del"; python3 "$T/ee.py" del sw-ko

echo "== Désactivation =="
reset_ee; python3 "$T/ee.py" add sw-wait Lab-SubRSA DDI-Network-Device "CN=sw-wait" "" DDI-Endentity
req '{"action":"scep_disable"}'; expect_eq "désactivation acceptée" true "$RES_OK"
check "alias supprimé" grep -q "config scep removealias --alias ddibuntu" "$T/ejbca.log"
check "les équipements préenregistrés ne sont pas supprimés" bash -c "! grep -q delendentity '$T/ejbca.log'"
expect_eq "état publié : désactivé" false "$(pubj enabled)"
check "état publié : les équipements restent listés" bash -c "python3 -c 'import json,sys; sys.exit(0 if \"sw-wait\" in [o[\"cn\"] for o in json.load(open(sys.argv[1]))[\"offers\"]] else 1)' '$R/pki-scep.json'"
reset_ee; req '{"action":"scep_disable"}'; expect_eq "désactiver deux fois : accepté (idempotent)" true "$RES_OK"
check "second passage : aucune commande à EJBCA" bash -c "! grep -q 'config scep' '$T/ejbca.log'"
reset_ee; req '{"action":"scep_enable"}'; touch "$T/fail.removealias"; reset_ee; touch "$T/fail.removealias"
req '{"action":"scep_disable"}'; expect_eq "EJBCA garde l'alias : désactivation refusée" false "$RES_OK"
rm -f "$T/fail.removealias"

echo "== Péremption des équipements jamais inscrits =="
reset_ee; python3 - "$T/userdata.tsv" <<'PY'
import sys
open(sys.argv[1], "w").write("")
PY
for n in sw-old sw-new sw-fail sw-done; do python3 "$T/ee.py" add "$n" Lab-SubRSA DDI-Network-Device "CN=$n" "" DDI-Endentity; done
python3 "$T/ee.py" setstatus sw-fail 11; python3 "$T/ee.py" setstatus sw-done 40
python3 "$T/ee.py" add ddi-bbbbbbbbbbbbbbbb Lab-Sub DDI-Network-Device "CN=x" "" DDI-Endentity
python3 "$T/ee.py" add superadmin ManagementCA DDI-Network-Device "CN=SuperAdmin" "" autre
for n in sw-old sw-fail sw-done ddi-bbbbbbbbbbbbbbbb superadmin; do python3 "$T/ee.py" age "$n" $(( 9 * 86400 )); done
python3 "$T/ee.py" age sw-new $(( 6 * 86400 ))
"$PKI" maintain >/dev/null 2>&1
check "en attente depuis plus de 7 jours : supprimé" grep -q -- "ra delendentity --username sw-old -force" "$T/ejbca.log"
check "refusé (état 11) depuis plus de 7 jours : supprimé" grep -q -- "ra delendentity --username sw-fail -force" "$T/ejbca.log"
check "en attente depuis 6 jours : conservé" bash -c "grep -q '^sw-new' '$T/userdata.tsv'"
check "déjà inscrit (certificat délivré) : jamais supprimé, quel que soit son âge" bash -c "grep -q '^sw-done' '$T/userdata.tsv'"
check "entité d'émission en cours (ddi-…) : jamais touchée" bash -c "grep -q '^ddi-bbbbbbbbbbbbbbbb' '$T/userdata.tsv'"
check "entité d'un autre profil (superadmin) : jamais touchée" bash -c "grep -q '^superadmin' '$T/userdata.tsv'"
expect_eq "deux suppressions seulement" 2 "$(grep -c 'ra delendentity' "$T/ejbca.log")"
check "SQL : filtre par profil d'entité du DDI, jamais les entités d'émission" bash -c "grep -q \"endentityprofileid = :'p' and username !~ '^ddi-'\" '$PLOG'"
: > "$T/ejbca.log"; "$PKI" maintain >/dev/null 2>&1
expect_eq "second passage : rien à supprimer" 0 "$(grep -c 'ra delendentity' "$T/ejbca.log")"
: > "$T/ejbca.log"; DDI_PKI_SCEP_DAYS=0 "$PKI" maintain >/dev/null 2>&1
check "durée réglée à 0 jour : tout équipement en attente est supprimé" grep -q -- "ra delendentity --username sw-new -force" "$T/ejbca.log"
: > "$T/ejbca.log"; DDI_PKI_SCEP_DAYS=abc "$PKI" maintain >/dev/null 2>&1
expect_eq "durée invalide : rien n'est supprimé" 0 "$(grep -c 'ra delendentity' "$T/ejbca.log")"
rm -f "$T/healthy"; python3 "$T/ee.py" add sw-x Lab-SubRSA DDI-Network-Device "CN=sw-x" "" DDI-Endentity; python3 "$T/ee.py" age sw-x $(( 9 * 86400 )); : > "$T/ejbca.log"
"$PKI" maintain >/dev/null 2>&1
expect_eq "PKI qui ne répond pas : la maintenance ne supprime rien" 0 "$(grep -c 'ra delendentity' "$T/ejbca.log")"
touch "$T/healthy"

echo "== Dépôts orphelins et état publié =="
touch "$IN/dddddddddddddddd.scepw" "$IN/eeeeeeeeeeeeeeee.scepw" "$IN/quelque-chose.pem"
touch -d '-30 minutes' "$IN/dddddddddddddddd.scepw" "$IN/quelque-chose.pem"
"$PKI" maintain >/dev/null 2>&1
check "défi orphelin de plus de 10 minutes supprimé" test ! -e "$IN/dddddddddddddddd.scepw"
check "défi récent conservé" test -e "$IN/eeeeeeeeeeeeeeee.scepw"
check "fichier étranger jamais touché" test -e "$IN/quelque-chose.pem"
rm -f "$IN/eeeeeeeeeeeeeeee.scepw"
python3 "$T/ee.py" add sw-pub Lab-SubRSA DDI-Network-Device "CN=sw-pub" "" DDI-Endentity
printf '1234567\t1795001470000\t20\t0123456789abcdef0123456789abcdef01234567\n' > "$T/userdata.tsv.cert.sw-pub"
python3 "$T/ee.py" setstatus sw-pub 40
"$PKI" status >/dev/null 2>&1
check "certificat de l'équipement : série, échéance et empreinte publiées" bash -c "python3 -c 'import json,sys
o = [x for x in json.load(open(sys.argv[1]))[\"offers\"] if x[\"cn\"] == \"sw-pub\"][0]
sys.exit(0 if o[\"cert\"][\"serial\"] == \"12D687\" and o[\"cert\"][\"notAfter\"].startswith(\"2026-\") and o[\"cert\"][\"revoked\"] is False else 1)' '$R/pki-scep.json'"
rm -f "$T/healthy"; cp "$R/pki-scep.json" "$T/before.json"; python3 "$T/ee.py" del sw-pub
"$PKI" status >/dev/null 2>&1
check "PKI qui ne répond pas : l'état précédent reste publié" cmp -s "$R/pki-scep.json" "$T/before.json"
touch "$T/healthy"
mv "$T/etc/instance.json" "$T/instance.bak"
"$PKI" status >/dev/null 2>&1
check "PKI désinstallée : plus d'état SCEP publié" test ! -e "$R/pki-scep.json"
mv "$T/instance.bak" "$T/etc/instance.json"

echo "== Ligne de commande directe =="
"$PKI" status >/dev/null 2>&1; reset_ee; rm -f "$T/alias.exists"
"$PKI" scep-enable >/dev/null 2>&1; expect_eq "scep-enable : en ligne de commande" 0 $?
dep ddddddddddddddd1 $PW1; "$PKI" scep-offer ddddddddddddddd1 Lab-SubRSA network "CN=sw-cli,O=Lab" "dNSName=sw-cli.lab.test" sw-cli >/dev/null 2>&1; expect_eq "scep-offer : en ligne de commande" 0 $?
check "scep-offer : défi consommé (aussi hors de « request »)" test ! -e "$IN/ddddddddddddddd1.scepw"
dep ddddddddddddddd2 $PW2; "$PKI" scep-rearm ddddddddddddddd2 sw-cli >/dev/null 2>&1; expect_eq "scep-rearm : en ligne de commande" 0 $?
"$PKI" scep-cancel 'x;y' >/dev/null 2>&1; expect_eq "scep-cancel : nom invalide refusé" 1 $?
"$PKI" scep-cancel sw-cli >/dev/null 2>&1; expect_eq "scep-cancel : en ligne de commande" 0 $?
"$PKI" scep-offer 'x;y' Lab-SubRSA network "CN=a" "dNSName=a.lab.test" a >/dev/null 2>&1; expect_eq "scep-offer : identifiant invalide refusé" 1 $?
"$PKI" scep-offer ddddddddddddddd3 Lab-SubRSA network "CN=a b" "dNSName=a.lab.test" "a b" >/dev/null 2>&1; expect_eq "scep-offer : nom invalide refusé" 1 $?
"$PKI" scep-disable >/dev/null 2>&1; expect_eq "scep-disable : en ligne de commande" 0 $?

echo "== Sécurité du script =="
check "aucune évaluation de texte de la console (eval)" bash -c "! grep -n '\beval\b' '$PKI'"
check "aucun appel de shell construit à partir d'une variable (bash -c)" bash -c "! grep -n 'bash -c' '$PKI'"
check "le défi passe toujours par cli_secret_run (masqué dans les messages)" bash -c "[ \$(grep -c 'cli_secret_run \"\$pw\" ra ' '$PKI') -ge 2 ]"
check "aucun cli_run du bloc SCEP ne reçoit le défi" bash -c "! awk '/^scep_enable\\(\\)/,/^scep_publish\\(\\)/' '$PKI' | grep -n 'cli_run .*--password'"

finish
