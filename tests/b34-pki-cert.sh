#!/usr/bin/env bash
# Batterie 34 — certificats de la PKI du DDI (0.14.3), sans conteneur ni PostgreSQL : (1) le helper pki-helper.py avec du vrai matériel openssl
# (analyse des demandes d'émission et de révocation, dépôt et contrôle de la demande de certificat, contrôle du certificat rendu par EJBCA) ;
# (2) la logique de ddibuntu-pki avec des bouchons (podman, psql, systemctl, curl) : profils importés une fois, lignes de commande exactes envoyées
# à la CLI d'EJBCA, certificats publiés puis purgés, révocation suivie de la CRL, refus. Le vrai EJBCA est vu par la batterie 35.
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
b64() { openssl x509 -in "$1" -outform DER | base64 -w0; }
mkec() { openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null; }

echo "== Matériel de test =="
mkec "$W/root.key"
openssl req -x509 -new -key "$W/root.key" -days 3650 -subj "/C=FR/O=Laboratoire/CN=Lab Root CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/root.pem" 2>/dev/null
mkec "$W/iss.key"
openssl req -new -key "$W/iss.key" -subj "/C=FR/O=Laboratoire/CN=Emettrice" -out "$W/iss.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$W/ca.ext"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > "$W/leaf.ext"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n' > "$W/isca.ext"
openssl x509 -req -in "$W/iss.csr" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial -days 1825 -extfile "$W/ca.ext" -out "$W/iss.pem" 2>/dev/null
mkec "$W/other.key"
openssl req -x509 -new -key "$W/other.key" -days 3650 -subj "/C=FR/O=Autre/CN=Autre racine" -addext "basicConstraints=critical,CA:TRUE" -out "$W/other.pem" 2>/dev/null
cat "$W/iss.pem" "$W/root.pem" > "$W/bundle.pem"
# demandes de certificat : RSA, EC, faibles, corrompue
openssl req -newkey rsa:2048 -nodes -keyout "$W/rsa.key" -out "$W/rsa.csr" -subj "/CN=ignoré" 2>/dev/null
openssl req -newkey rsa:3072 -nodes -keyout "$W/rsa3.key" -out "$W/rsa3.csr" -subj "/CN=x" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/ec.key" -out "$W/ec.csr" -subj "/CN=x" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -keyout "$W/ec384.key" -out "$W/ec384.csr" -subj "/CN=x" 2>/dev/null
openssl req -newkey rsa:1024 -nodes -keyout "$W/rsa1k.key" -out "$W/rsa1k.csr" -subj "/CN=x" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp256k1 -nodes -keyout "$W/k1.key" -out "$W/k1.csr" -subj "/CN=x" 2>/dev/null
openssl req -newkey ed25519 -nodes -keyout "$W/ed.key" -out "$W/ed.csr" -subj "/CN=x" 2>/dev/null
openssl req -in "$W/rsa.csr" -outform DER -out "$W/rsa.csr.der"
python3 - "$W/rsa.csr.der" "$W/bad.csr.der" <<'EOF'
import sys
b = bytearray(open(sys.argv[1], "rb").read()); b[-5] ^= 0xFF
open(sys.argv[2], "wb").write(bytes(b))
EOF
for f in root.pem iss.pem other.pem bundle.pem rsa.csr rsa3.csr ec.csr ec384.csr rsa1k.csr k1.csr ed.csr bad.csr.der; do check "matériel : $f fabriqué" test -s "$W/$f"; done
mkleaf() {   # $1 = demande, $2 = sortie (certificat seul), $3 = extensions, $4 = autorité (iss | root)
  local ca="${4:-iss}" cacert cakey
  if [ "$ca" = iss ]; then cacert="$W/iss.pem"; cakey="$W/iss.key"; else cacert="$W/root.pem"; cakey="$W/root.key"; fi
  openssl x509 -req -in "$1" -CA "$cacert" -CAkey "$cakey" -CAcreateserial -days "${5:-365}" -extfile "${3:-$W/leaf.ext}" -out "$2" 2>/dev/null
}
ejbca_style() { { printf 'Subject: CN=x,O=Lab,C=FR\nIssuer: CN=Emettrice,O=Laboratoire,C=FR\n'; cat "$1"; } > "$2"; }   # le fichier rendu par la CLI d'EJBCA

echo "== Helper : demande d'émission (formulaire de la console) =="
SRV='{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"radius1.lab.test","o":"Laboratoire","c":"FR","dns":["Radius1.Lab.Test","radius.lab.test"],"ip":["10.1.2.3"]}'
out="$(pr "$SRV")"; rc=$?
expect_eq "serveur valide : acceptée" 0 "$rc"
expect_eq "serveur valide : sortie canonique (DNS en minuscules, SAN dans l'ordre dns, ip)" "action	cert_issue
id	0123456789abcdef
ca	Lab-Sub
profile	server
dn	CN=radius1.lab.test,O=Laboratoire,C=FR
altname	dNSName=radius1.lab.test,dNSName=radius.lab.test,iPAddress=10.1.2.3" "$out"
out="$(pr '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"user","cn":"Jean Dupont","ou":"Compta","o":"Lab","c":"FR","mail":["j.dupont@lab.test"],"upn":["jdupont@lab.test"]}')"
expect_eq "utilisateur : SAN rfc822Name puis upn" "altname	rfc822Name=j.dupont@lab.test,upn=jdupont@lab.test" "$(printf '%s\n' "$out" | grep ^altname)"
expect_eq "utilisateur : nom distinctif CN, OU, O, C" "dn	CN=Jean Dupont,OU=Compta,O=Lab,C=FR" "$(printf '%s\n' "$out" | grep ^dn)"
out="$(pr '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"machine","cn":"pc01","dns":["pc01.lab.test"]}')"
expect_eq "machine : un nom DNS suffit" "altname	dNSName=pc01.lab.test" "$(printf '%s\n' "$out" | grep ^altname)"
out="$(pr '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"network","cn":"sw1","ip":["::1","10.0.0.1","10.0.0.1"]}')"
expect_eq "équipement réseau : IP seule, normalisée, sans doublon" "altname	iPAddress=::1,iPAddress=10.0.0.1" "$(printf '%s\n' "$out" | grep ^altname)"
refuse() { local why="$1" json="$2"; if pr "$json" >/dev/null 2>&1; then check "REFUS ATTENDU — $why" false; else check "refusée : $why" true; fi; }
B='"ca":"Lab-Sub","profile":"server","cn":"x","dns":["a.lab.test"]'
refuse "identifiant en majuscules" '{"action":"cert_issue","id":"0123456789ABCDEF",'"$B"'}'
refuse "identifiant trop court" '{"action":"cert_issue","id":"0123456789abcde",'"$B"'}'
refuse "identifiant trop long" '{"action":"cert_issue","id":"0123456789abcdef0",'"$B"'}'
refuse "identifiant absent" '{"action":"cert_issue",'"$B"'}'
refuse "autorité avec une barre" '{"action":"cert_issue","id":"0123456789abcdef","ca":"a/b","profile":"server","cn":"x","dns":["a.lab.test"]}'
refuse "autorité ManagementCA" '{"action":"cert_issue","id":"0123456789abcdef","ca":"ManagementCA","profile":"server","cn":"x","dns":["a.lab.test"]}'
refuse "autorité racine hors ligne" '{"action":"cert_issue","id":"0123456789abcdef","ca":"ExtRoot-0a1b2c3d","profile":"server","cn":"x","dns":["a.lab.test"]}'
refuse "profil inconnu" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"EMPTY","cn":"x","dns":["a.lab.test"]}'
refuse "profil avec un nom EJBCA direct" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"DDI-RADIUS-Server","cn":"x","dns":["a.lab.test"]}'
refuse "serveur sans aucun SAN" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x"}'
refuse "serveur avec une adresse mail" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a.lab.test"],"mail":["a@b.test"]}'
refuse "utilisateur avec un nom DNS" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"user","cn":"x","dns":["a.lab.test"],"upn":["a@b.test"]}'
refuse "utilisateur sans mail ni upn" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"user","cn":"x"}'
refuse "machine avec une IP" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"machine","cn":"x","dns":["a.lab.test"],"ip":["10.0.0.1"]}'
refuse "neuf noms DNS" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a1.t","a2.t","a3.t","a4.t","a5.t","a6.t","a7.t","a8.t","a9.t"]}'
refuse "cinq IP" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a.t"],"ip":["10.0.0.1","10.0.0.2","10.0.0.3","10.0.0.4","10.0.0.5"]}'
refuse "nom DNS commençant par un tiret" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["-a.lab.test"]}'
refuse "nom DNS avec deux points" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a..lab.test"]}'
refuse "nom DNS avec une espace" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a b.lab.test"]}'
refuse "nom DNS avec un souligné" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a_b.lab.test"]}'
refuse "nom DNS injectant un autre SAN" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a.lab.test,dNSName=evil.test"]}'
refuse "nom DNS de 255 caractères" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["'"$(printf 'a%.0s' $(seq 1 63)).$(printf 'b%.0s' $(seq 1 63)).$(printf 'c%.0s' $(seq 1 63)).$(printf 'd%.0s' $(seq 1 63))"'"]}'
refuse "adresse IP invalide" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a.t"],"ip":["999.1.1.1"]}'
refuse "IP avec masque" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":["a.t"],"ip":["10.0.0.0/8"]}'
refuse "mail sans domaine" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"user","cn":"x","mail":["a@"]}'
refuse "mail injectant un SAN" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"user","cn":"x","mail":["a@b.test,dNSName=evil.test"]}'
refuse "SAN donné comme une chaîne et non une liste" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":"a.lab.test"}'
refuse "SAN contenant un nombre" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","dns":[1]}'
refuse "nom commun absent" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","dns":["a.t"]}'
refuse "nom commun avec une virgule (injection de composant)" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x,O=Evil","dns":["a.t"]}'
refuse "pays en minuscules" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"x","c":"fr","dns":["a.t"]}'
refuse "demande de plus de 4 Ko" '{"action":"cert_issue","id":"0123456789abcdef","ca":"Lab-Sub","profile":"server","cn":"'"$(head -c 5000 /dev/zero | tr '\0' 'a')"'","dns":["a.t"]}'

echo "== Helper : demande de révocation =="
out="$(pr '{"action":"cert_revoke","ca":"Lab-Sub","serial":"00ab12","reason":1}')"; rc=$?
expect_eq "révocation valide : acceptée" 0 "$rc"
expect_eq "révocation valide : série en majuscules sans zéros de tête" "action	cert_revoke
ca	Lab-Sub
serial	AB12
reason	1" "$out"
out="$(pr '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":1,"id":"0123456789abcdef"}')"; expect_eq "révocation avec référence : acceptée et recopiée" "id	0123456789abcdef" "$(printf '%s\n' "$out" | grep ^id)"
refuse "référence de révocation invalide" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":1,"id":"XYZ"}'
for r in 0 3 4 5; do out="$(pr '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":'$r'}')"; expect_eq "motif $r admis" "reason	$r" "$(printf '%s\n' "$out" | grep ^reason)"; done
refuse "motif 2 (compromission de l'autorité) interdit ici" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":2}'
refuse "motif 9" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":9}'
refuse "motif donné comme un booléen" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":true}'
refuse "motif donné comme une chaîne" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"FF","reason":"1"}'
refuse "série avec 0x" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"0xFF","reason":1}'
refuse "série décimale négative" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"-5","reason":1}'
refuse "série de 41 chiffres" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"'"$(printf 'A%.0s' $(seq 1 41))"'","reason":1}'
refuse "série vide" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"","reason":1}'
refuse "autorité ManagementCA" '{"action":"cert_revoke","ca":"ManagementCA","serial":"FF","reason":1}'
refuse "série injectant du SQL" '{"action":"cert_revoke","ca":"Lab-Sub","serial":"1; drop table x","reason":1}'

echo "== Helper : dépôt de la demande de certificat =="
D="$T/dep"; mkdir -p "$D"
out="$(ph deposit "$W/rsa.csr" "$D/rsa.pem" csr)"; expect_eq "RSA 2048 accepté" "OK	RSA	2048" "$out"
check "demande réécrite en PEM canonique" grep -q "BEGIN CERTIFICATE REQUEST" "$D/rsa.pem"
check "demande réécrite : lisible par openssl" openssl req -in "$D/rsa.pem" -noout
expect_eq "mode du dépôt réécrit" 600 "$(stat -c %a "$D/rsa.pem")"
out="$(ph deposit "$W/rsa3.csr" "$D/rsa3.pem" csr)"; expect_eq "RSA 3072 accepté" "OK	RSA	3072" "$out"
out="$(ph deposit "$W/ec.csr" "$D/ec.pem" csr)"; expect_eq "ECDSA P-256 accepté" "OK	EC	prime256v1" "$out"
out="$(ph deposit "$W/ec384.csr" "$D/ec384.pem" csr)"; expect_eq "ECDSA P-384 accepté" "OK	EC	secp384r1" "$out"
out="$(ph deposit "$W/rsa.csr.der" "$D/der.pem" csr)"; expect_eq "demande DER acceptée" "OK	RSA	2048" "$out"
out="$(ph deposit "$W/rsa1k.csr" "$D/w.pem" csr)"; expect_eq "RSA 1024 refusé" ERR "${out%%	*}"; check "motif : taille de clé" grep -q "1024" <<< "$out"
out="$(ph deposit "$W/k1.csr" "$D/k1.pem" csr)"; expect_eq "courbe secp256k1 refusée" ERR "${out%%	*}"
out="$(ph deposit "$W/ed.csr" "$D/ed.pem" csr)"; expect_eq "Ed25519 refusé" ERR "${out%%	*}"
out="$(ph deposit "$W/bad.csr.der" "$D/bad.pem" csr)"; expect_eq "signature corrompue refusée (OpenSSL 3 rend 0 : le message fait foi)" ERR "${out%%	*}"; check "motif : preuve de possession" grep -qi "possession\|signature" <<< "$out"
out="$(ph deposit "$W/rsa.key" "$D/key.pem" csr)"; expect_eq "clé privée collée par erreur refusée" ERR "${out%%	*}"
check "clé privée : rien n'est écrit" test ! -e "$D/key.pem"
cat "$W/rsa.csr" "$W/rsa.key" > "$W/csr+key.pem"; out="$(ph deposit "$W/csr+key.pem" "$D/ck.pem" csr)"; expect_eq "demande suivie d'une clé privée refusée" ERR "${out%%	*}"
cat "$W/rsa.csr" "$W/ec.csr" > "$W/two.csr"; out="$(ph deposit "$W/two.csr" "$D/two.pem" csr)"
check "deux demandes dans un fichier : ou refusées, ou une seule retenue (jamais un fichier ambigu)" bash -c "[ \"${out%%	*}\" = ERR ] || [ \"\$(grep -c 'BEGIN CERTIFICATE REQUEST' '$D/two.pem')\" = 1 ]"
out="$(ph deposit "$W/rsa.csr" "$D/x.pem" csr; ph deposit "$W/garbage-absent" "$D/y.pem" csr)"; check "dépôt absent refusé" grep -q ERR <<< "$out"
ln -sf /etc/passwd "$W/lnk.csr"; out="$(ph deposit "$W/lnk.csr" "$D/lnk.pem" csr)"; expect_eq "lien symbolique refusé" ERR "${out%%	*}"

echo "== Helper : certificat rendu par EJBCA =="
mkleaf "$W/rsa.csr" "$W/leaf.pem" "$W/leaf.ext"; ejbca_style "$W/leaf.pem" "$W/leaf.eb.pem"
LEAF_SER="$(openssl x509 -in "$W/leaf.pem" -noout -serial | cut -d= -f2 | sed "s/^0*\([0-9A-F]\)/\1/")"   # série normalisée sans zéros de tête (le helper les retire ; la série est tirée au hasard)
LEAF_SHA="$(openssl x509 -in "$W/leaf.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')"
cl() { ph check-leaf "$1" "$2" "$3" "$W/leaf.out.pem"; }
out="$(cl "$W/rsa.csr" "$W/leaf.eb.pem" "$W/bundle.pem")"; rc=$?
expect_eq "sortie d'EJBCA (lignes Subject / Issuer devant le PEM) acceptée" 0 "$rc"
expect_eq "série, empreinte et sujet extraits" "OK	$LEAF_SER	$LEAF_SHA" "$(printf '%s' "$out" | cut -f1-3)"
check "dates et sujet présents" bash -c "[ \"\$(printf '%s' '$out' | awk -F'\t' '{print NF}')\" = 6 ]"
check "certificat réécrit en PEM canonique, sans lignes parasites" bash -c "head -1 '$W/leaf.out.pem' | grep -q '^-----BEGIN CERTIFICATE-----$' && ! grep -q Subject '$W/leaf.out.pem'"
rm -f "$W/leaf.out.pem"; out="$(cl "$W/rsa.csr" "$W/leaf.pem" "$W/bundle.pem")"; expect_eq "PEM nu accepté aussi" OK "${out%%	*}"
rm -f "$W/leaf.out.pem"; out="$(cl "$W/ec.csr" "$W/leaf.eb.pem" "$W/bundle.pem")"; expect_eq "demande d'une autre clé refusée" ERR "${out%%	*}"; check "motif : clé" grep -qi "clé" <<< "$out"
mkleaf "$W/rsa.csr" "$W/isca.pem" "$W/isca.ext"; out="$(cl "$W/rsa.csr" "$W/isca.pem" "$W/bundle.pem")"; expect_eq "certificat d'autorité (CA:TRUE) refusé" ERR "${out%%	*}"
out="$(cl "$W/rsa.csr" "$W/leaf.eb.pem" "$W/root.pem")"; expect_eq "chaîne sans l'émettrice refusée" ERR "${out%%	*}"
cat "$W/other.pem" > "$W/bundle-other.pem"; out="$(cl "$W/rsa.csr" "$W/leaf.eb.pem" "$W/bundle-other.pem")"; expect_eq "autre racine refusée" ERR "${out%%	*}"
mkleaf "$W/rsa.csr" "$W/leaf-root.pem" "$W/leaf.ext" root; out="$(cl "$W/rsa.csr" "$W/leaf-root.pem" "$W/bundle.pem")"; expect_eq "certificat signé par une autre autorité que celle du lot refusé" ERR "${out%%	*}"
openssl x509 -req -in "$W/rsa.csr" -CA "$W/iss.pem" -CAkey "$W/iss.key" -CAcreateserial -days 1 -extfile "$W/leaf.ext" -out "$W/short.pem" 2>/dev/null
openssl x509 -req -in "$W/rsa.csr" -CA "$W/iss.pem" -CAkey "$W/iss.key" -CAcreateserial -days 0 -extfile "$W/leaf.ext" -out "$W/exp.pem" 2>/dev/null
if [ -s "$W/exp.pem" ]; then out="$(cl "$W/rsa.csr" "$W/exp.pem" "$W/bundle.pem")"; expect_eq "certificat déjà expiré refusé" ERR "${out%%	*}"; else note "openssl refuse de fabriquer un certificat de 0 jour : cas expiré ignoré"; fi
cat "$W/leaf.pem" "$W/iss.pem" > "$W/two-certs.pem"; out="$(cl "$W/rsa.csr" "$W/two-certs.pem" "$W/bundle.pem")"; expect_eq "deux certificats dans la sortie refusés" ERR "${out%%	*}"
{ cat "$W/leaf.eb.pem"; echo "rien à voir"; } > "$W/trail.pem"; out="$(cl "$W/rsa.csr" "$W/trail.pem" "$W/bundle.pem")"; expect_eq "texte étranger après le certificat refusé" ERR "${out%%	*}"
printf 'rien\n' > "$W/garbage"; out="$(cl "$W/rsa.csr" "$W/garbage" "$W/bundle.pem")"; expect_eq "sortie illisible refusée" ERR "${out%%	*}"
expect_eq "série hexadécimale → décimale (base d'EJBCA)" 2224595 "$(ph hex2dec 21F1D3)"
expect_eq "série à 40 chiffres → décimale exacte" "$(python3 -c 'print(int("7DEEE0F669588C73464EB0030486A7C48168D380", 16))')" "$(ph hex2dec 7DEEE0F669588C73464EB0030486A7C48168D380)"
ph hex2dec "zz" >/dev/null 2>&1; expect_eq "série invalide : code d'erreur" 1 $?
ph hex2dec "1;2" >/dev/null 2>&1; expect_eq "série avec ; refusée" 1 $?

echo "== Racine : bouchons =="
B="$T/bin"; mkdir -p "$B" "$T/etc" "$T/data/ca/Lab-Sub" "$T/data/ca/Lab-Root" "$T/quad" "$T/run" "$T/gen/pki-in" "$T/profiles"
LOG="$T/calls.log"; PLOG="$T/psql.log"; : > "$LOG"; : > "$PLOG"
WORKH="$T/data/persistent/work"
SUBDN='CN=Emettrice,O=Laboratoire,C=FR'
printf '{"kind":"root","signedBy":"self","alg":"ecp256","createdAt":1700000000}' > "$T/data/ca/Lab-Root/meta.json"
printf '{"kind":"issuing","signedBy":"Lab-Root","alg":"ecp256","createdAt":1700000100}' > "$T/data/ca/Lab-Sub/meta.json"
printf '{"hostname":"pki.lab.test","tag":"9.6.3","digest":"sha256:%s","nets":"","installedAt":1700000000}' "$(printf 'a%.0s' $(seq 1 64))" > "$T/etc/instance.json"
printf 'HTTPSERVER_HOSTNAME=pki.lab.test\n' > "$T/etc/ejbca.env"
for n in DDI-RADIUS-Server-5010001 DDI-Client-Machine-5010002 DDI-Client-User-5010003 DDI-Network-Device-5010004; do printf '<java/>' > "$T/profiles/certprofile_$n.xml"; done
printf '<java/>' > "$T/profiles/entityprofile_DDI-Endentity-5020001.xml"
{
  printf 'Lab-Root\t1\tCN=Lab Root CA,O=Laboratoire,C=FR\t1001\t%s\n' "$(b64 "$W/root.pem")"
  printf 'Lab-Sub\t1\t%s\t1002\t%s\n' "$SUBDN" "$(b64 "$W/iss.pem")"
} > "$T/cas.tsv"
printf 'Lab-Root\t1\tCN=Lab Root CA,O=Laboratoire,C=FR\t1001\nLab-Sub\t1\t%s\t1002\n' "$SUBDN" > "$T/cadb.tsv"
touch "$T/db.exists" "$T/healthy" "$T/active"; echo 9 > "$T/tables"; echo 20 > "$T/leaf.status"
cat > "$B/podman" <<EOF
#!/bin/bash
echo "podman \$*" >> "$LOG"
[ "\$1" = exec ] || exit 0
a=("\$@"); i=0; while [ "\$i" -lt "\$#" ] && [ "\${a[\$i]}" != /opt/keyfactor/bin/ejbca.sh ]; do i=\$((i+1)); done
s=("\${a[@]:\$((i+1))}")
echo "ejbca \${s[*]}" >> "$T/ejbca.log"
case "\${s[0]} \${s[1]}" in
  "ca importprofiles")
    [ -f "$T/fail.import" ] && { echo "boom import" >&2; exit 1; }
    d="\${s[3]}"; d="$WORKH/\${d#/mnt/persistent/work/}"
    for f in "\$d"/*.xml; do b="\${f##*/}"; echo "\$b" >> "$T/imported.log"; b="\${b%.xml}"; b="\${b#certprofile_}"; b="\${b#entityprofile_}"; touch "$T/prof.\${b%-*}"; done ;;
  "ra addendentity") [ -f "$T/fail.add" ] && { echo "boom add" >&2; exit 1; }; touch "$T/ee.exists" ;;
  "ra delendentity") rm -f "$T/ee.exists" ;;
  "createcert "*)
    [ -f "$T/fail.create" ] && { echo "boom createcert" >&2; exit 1; }
    csr="$WORKH/req.csr"; [ -f "$T/leaf.wrongkey" ] && csr="$W/ec.csr"
    ext="$W/leaf.ext"; [ -f "$T/leaf.isca" ] && ext="$W/isca.ext"
    openssl x509 -req -in "\$csr" -CA "$W/iss.pem" -CAkey "$W/iss.key" -CAcreateserial -days 365 -extfile "\$ext" -out "$WORKH/_leaf.pem" 2>/dev/null
    { printf 'Subject: CN=x,O=Lab,C=FR\nIssuer: CN=Emettrice,O=Laboratoire,C=FR\n'; cat "$WORKH/_leaf.pem"; } > "$WORKH/issued.pem"; rm -f "$WORKH/_leaf.pem"
    openssl x509 -in "$WORKH/issued.pem" -noout -serial | cut -d= -f2 | sed "s/^0*\([0-9A-F]\)/\1/" > "$T/leaf.serial"; python3 -c 'print(int(open("$T/leaf.serial").read().strip(), 16))' > "$T/leaf.dec"; echo 20 > "$T/leaf.status" ;;
  "ra revokecert") [ -f "$T/fail.revoke" ] || echo 40 > "$T/leaf.status" ;;
  "ca createcrl") [ -f "$T/fail.crl" ] && exit 1 ;;
  "ca editca")
    [ -f "$T/fail.editca" ] && { echo "boom editca" >&2; exit 1; }
    en=""; ef=""; ev=""; for ((j=2; j<\${#s[@]}; j++)); do case "\${s[\$j]}" in --caname) en="\${s[\$((j+1))]}";; --field) ef="\${s[\$((j+1))]}";; --value) ev="\${s[\$((j+1))]}";; esac; done
    [ "\$ef" = doEnforceUniqueDistinguishedName ] && [ "\$ev" = false ] && touch "$T/dnoff.\$en" ;;
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
n=""; d=""; s=""
while [ "\$#" -gt 0 ]; do case "\$1" in -v) shift; case "\$1" in n=*) n="\${1#n=}";; d=*) d="\${1#d=}";; s=*) s="\${1#s=}";; esac;; esac; shift; done
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
  *"select status from certificatedata"*) [ -f "$T/leaf.dec" ] && [ "\$d" = "$SUBDN" ] && [ "\$s" = "\$(cat "$T/leaf.dec")" ] && cat "$T/leaf.status" ;;
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
G="$T/gen"; R="$T/run"
req() { printf '%s' "$1" > "$G/.pki-request"; "$PKI" request >"$T/req.out" 2>&1; RES_OK="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$R/pki-result.json")"; RES_MSG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["message"])' "$R/pki-result.json")"; RES_REF="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ref",""))' "$R/pki-result.json")"; [ -z "${DEBUG_REQ:-}" ] || { cat "$T/req.out" >&2; cat "$T/ejbca.log" >&2; }; }
reset_ee() { rm -f "$T"/fail.* "$T"/leaf.wrongkey "$T"/leaf.isca "$T/ee.exists"; : > "$T/ejbca.log"; }
ISS() { printf '{"action":"cert_issue","id":"%s","ca":"%s","profile":"%s","cn":"radius1.lab.test","o":"Laboratoire","c":"FR","dns":["radius1.lab.test"],"ip":["10.1.2.3"]}' "$1" "${2:-Lab-Sub}" "${3:-server}"; }
dep() { install -m 0644 "${2:-$W/rsa.csr}" "$G/pki-in/$1.csr.pem"; }   # dépôt de la console (publié sous l'identifiant de la demande)
"$PKI" status >/dev/null 2>&1
check "état publié avec les autorités de l'exemple" test -s "$R/pki-ca/Lab-Sub/chain.pem"

echo "== Émission : première demande =="
rm -f "$T"/prof.*; : > "$T/imported.log"; reset_ee
ID1=aaaaaaaaaaaaaaa1; dep $ID1
req "$(ISS $ID1)"
expect_eq "émission acceptée" true "$RES_OK"; check "message : autorité et série" grep -q "Lab-Sub" <<< "$RES_MSG"
expect_eq "la référence de la demande est rendue à la console" "$ID1" "$RES_REF"
expect_eq "cinq profils importés (4 certificats, 1 entité finale), une seule fois" 5 "$(wc -l < "$T/imported.log")"
expect_eq "un seul import (une seule commande pour les cinq fichiers)" 1 "$(grep -c 'ca importprofiles' "$T/ejbca.log")"
AE="$(grep 'ra addendentity' "$T/ejbca.log" | head -n1)"
check "entité finale : nom ddi-<identifiant>" grep -q -- "--username ddi-$ID1" <<< "$AE"
check "entité finale : nom distinctif du formulaire" grep -q -- "--dn CN=radius1.lab.test,O=Laboratoire,C=FR" <<< "$AE"
check "entité finale : autorité demandée" grep -q -- "--caname Lab-Sub" <<< "$AE"
check "entité finale : profil de certificat du DDI" grep -q -- "--certprofile DDI-RADIUS-Server" <<< "$AE"
check "entité finale : profil d'entité du DDI" grep -q -- "--eeprofile DDI-Endentity" <<< "$AE"
check "entité finale : SAN du formulaire" grep -q -- "--altname dNSName=radius1.lab.test,iPAddress=10.1.2.3" <<< "$AE"
check "entité finale : jeton géré par l'utilisateur (clé fabriquée hors d'EJBCA)" grep -q -- "--token USERGENERATED" <<< "$AE"
check "le certificat est demandé avec le fichier déposé par root" grep -q "createcert --username ddi-$ID1 --password [A-Za-z0-9]\{40\} -c /mnt/persistent/work/req.csr" "$T/ejbca.log"
check "l'entité finale est supprimée après l'émission (mot de passe à usage unique)" bash -c "grep -q 'ra delendentity --username ddi-$ID1' '$T/ejbca.log' && [ ! -e '$T/ee.exists' ]"
check "DN unique : retiré sur l'autorité (ca editca) AVANT la création de l'entité finale" bash -c "[ \$(grep -n 'ca editca --caname Lab-Sub --field doEnforceUniqueDistinguishedName --value false' '$T/ejbca.log' | head -1 | cut -d: -f1) -lt \$(grep -n 'ra addendentity' '$T/ejbca.log' | head -1 | cut -d: -f1) ]"
check "DN unique : désactivé pour cette autorité seulement" bash -c "test -e '$T/dnoff.Lab-Sub' -a ! -e '$T/dnoff.Lab-Root'"
CD="$R/pki-cert/$ID1"
check "certificat publié (lisible par la console)" bash -c "[ \"\$(stat -c %a '$CD')\" = 755 ] && [ \"\$(stat -c %a '$CD/cert.pem')\" = 644 ] && [ \"\$(stat -c %a '$CD/chain.pem')\" = 644 ] && [ \"\$(stat -c %a '$CD/meta.json')\" = 644 ]"
check "le certificat publié est un PEM propre, vérifiable avec la chaîne publiée" openssl verify -CAfile "$CD/chain.pem" -untrusted "$R/pki-ca/Lab-Sub/cert.pem" "$CD/cert.pem"
check "aucune clé privée publiée" bash -c "! grep -rl 'PRIVATE KEY' '$R/pki-cert'"
expect_eq "meta.json : série, autorité, profil" "$(cat "$T/leaf.serial")|Lab-Sub|server" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("%s|%s|%s" % (d["serial"], d["ca"], d["profile"]))' "$CD/meta.json")"
check "le dépôt de la demande de certificat est consommé" test ! -e "$G/pki-in/$ID1.csr.pem"
check "le dossier d'échange est vidé" bash -c "[ -z \"\$(ls -A '$WORKH')\" ]"
check "le dossier d'échange ne conserve aucune demande (le mot de passe n'est jamais écrit sur le disque)" bash -c "! grep -rq 'password' '$WORKH' '$CD' 2>/dev/null"

echo "== Émission : DN unique (renouvellement du même nom) =="
reset_ee; ID1B=aaaaaaaaaaaaaa1b; dep $ID1B; req "$(ISS $ID1B)"
expect_eq "deuxième certificat de même nom sur la même autorité : accepté" true "$RES_OK"
expect_eq "DN unique déjà retiré : aucun nouveau « ca editca »" 0 "$(grep -c 'ca editca' "$T/ejbca.log")"
reset_ee; rm -f "$T/dnoff.Lab-Sub"; touch "$T/fail.editca"; ID1C=aaaaaaaaaaaaaa1c; dep $ID1C; req "$(ISS $ID1C)"
expect_eq "ca editca en échec : émission refusée (jamais d'émission sur une autorité qui refuserait un renouvellement)" false "$RES_OK"
check "ca editca en échec : aucune entité finale créée" bash -c "! grep -q addendentity '$T/ejbca.log'"
rm -f "$T/fail.editca"; reset_ee; ID1D=aaaaaaaaaaaaaa1d; dep $ID1D; req "$(ISS $ID1D)"
expect_eq "après l'échec : le réglage est retenté et l'émission réussit" true "$RES_OK"
echo "== Émission : profils déjà présents =="
: > "$T/imported.log"; reset_ee; ID2=aaaaaaaaaaaaaaa2; dep $ID2 "$W/ec.csr"
req "$(ISS $ID2)"; expect_eq "seconde émission acceptée" true "$RES_OK"
expect_eq "aucun profil réimporté (EJBCA refuse un profil existant, un administrateur a pu l'ajuster)" 0 "$(wc -l < "$T/imported.log")"
check "aucune commande d'import" bash -c "! grep -q importprofiles '$T/ejbca.log'"
: > "$T/imported.log"; rm -f "$T/prof.DDI-Client-User"; reset_ee; ID3=aaaaaaaaaaaaaaa3; dep $ID3
req "$(ISS $ID3)"; expect_eq "émission acceptée avec un profil manquant" true "$RES_OK"
expect_eq "seul le profil manquant est réimporté" "certprofile_DDI-Client-User-5010003.xml" "$(cat "$T/imported.log")"
rm -f "$T/prof.DDI-Endentity"; : > "$T/imported.log"; reset_ee; ID4=aaaaaaaaaaaaaaa4; dep $ID4
req "$(ISS $ID4)"; expect_eq "profil d'entité finale manquant : réimporté" "entityprofile_DDI-Endentity-5020001.xml" "$(cat "$T/imported.log")"
mv "$T/profiles/certprofile_DDI-Network-Device-5010004.xml" "$T/x.xml"; rm -f "$T/prof.DDI-Network-Device"; reset_ee; ID5=aaaaaaaaaaaaaaa5; dep $ID5
req "$(ISS $ID5)"; expect_eq "profil fourni absent du disque : émission refusée" false "$RES_OK"; check "motif lisible" grep -qi "profil" <<< "$RES_MSG"
check "rien n'est émis" test ! -e "$R/pki-cert/$ID5"
mv "$T/x.xml" "$T/profiles/certprofile_DDI-Network-Device-5010004.xml"
reset_ee; touch "$T/fail.import"; ID6=aaaaaaaaaaaaaaa6; dep $ID6
req "$(ISS $ID6)"; expect_eq "import des profils en échec : émission refusée" false "$RES_OK"; check "aucune entité finale créée" bash -c "! grep -q addendentity '$T/ejbca.log'"
rm -f "$T/fail.import"; touch "$T/prof.DDI-Network-Device"

echo "== Émission : refus =="
cert_refused() { reset_ee; dep "$1" "${3:-$W/rsa.csr}"; req "$2"; expect_eq "$4" false "$RES_OK"; }
cert_refused aaaaaaaaaaaaaaa7 "$(ISS aaaaaaaaaaaaaaa7 Lab-Root)" "$W/rsa.csr" "refus : une racine ne délivre pas de certificats finaux"
check "motif : émettrice" grep -qi "émettrice" <<< "$RES_MSG"
cert_refused aaaaaaaaaaaaaaa8 "$(ISS aaaaaaaaaaaaaaa8 Nope)" "$W/rsa.csr" "refus : autorité inexistante"
cert_refused aaaaaaaaaaaaaaa9 "$(ISS aaaaaaaaaaaaaaa9 Lab-Sub user)" "$W/rsa.csr" "refus : profil user sans mail ni upn"
cert_refused aaaaaaaaaaaaaab1 "$(ISS aaaaaaaaaaaaaab1)" "$W/rsa1k.csr" "refus : clé RSA 1024"; check "motif : clé" grep -qi "1024\|clé" <<< "$RES_MSG"
cert_refused aaaaaaaaaaaaaab2 "$(ISS aaaaaaaaaaaaaab2)" "$W/bad.csr.der" "refus : demande à la signature corrompue"
check "refus avant EJBCA : aucune entité finale créée" bash -c "! grep -q addendentity '$T/ejbca.log'"
reset_ee; req "$(ISS aaaaaaaaaaaaaab3)"; expect_eq "refus : aucun dépôt de demande de certificat" false "$RES_OK"
dep aaaaaaaaaaaaaab1; reset_ee; req "$(ISS aaaaaaaaaaaaaab1)"; expect_eq "une demande refusée n'est pas enregistrée : même identifiant, dépôt valide, acceptée" true "$RES_OK"
dep aaaaaaaaaaaaaab1; reset_ee; req "$(ISS aaaaaaaaaaaaaab1)"; expect_eq "refus : même identifiant déjà émis (jamais rejoué)" false "$RES_OK"; check "motif : déjà traitée" grep -qi "déjà" <<< "$RES_MSG"
check "le dépôt rejoué est consommé" test ! -e "$G/pki-in/aaaaaaaaaaaaaab1.csr.pem"
check "aucune entité finale pour un identifiant rejoué" bash -c "! grep -q addendentity '$T/ejbca.log'"
rm -f "$T/healthy"; reset_ee; dep aaaaaaaaaaaaaab5; req "$(ISS aaaaaaaaaaaaaab5)"; expect_eq "refus : PKI qui ne répond pas" false "$RES_OK"; check "motif : santé" grep -qi "répond" <<< "$RES_MSG"; touch "$T/healthy"
reset_ee; touch "$T/fail.add"; dep aaaaaaaaaaaaaab6; req "$(ISS aaaaaaaaaaaaaab6)"; expect_eq "EJBCA refuse l'entité finale : échec" false "$RES_OK"; check "rien n'est publié" test ! -e "$R/pki-cert/aaaaaaaaaaaaaab6"
reset_ee; touch "$T/fail.create"; dep aaaaaaaaaaaaaab7; req "$(ISS aaaaaaaaaaaaaab7)"; expect_eq "EJBCA refuse l'émission : échec" false "$RES_OK"
check "l'entité finale est supprimée même en cas d'échec" bash -c "grep -q 'ra delendentity --username ddi-aaaaaaaaaaaaaab7' '$T/ejbca.log' && [ ! -e '$T/ee.exists' ]"
check "rien n'est publié" test ! -e "$R/pki-cert/aaaaaaaaaaaaaab7"
reset_ee; touch "$T/leaf.wrongkey"; dep aaaaaaaaaaaaaab8; req "$(ISS aaaaaaaaaaaaaab8)"; expect_eq "certificat rendu pour une autre clé : refusé" false "$RES_OK"; check "motif : clé" grep -qi "clé" <<< "$RES_MSG"
check "rien n'est publié" test ! -e "$R/pki-cert/aaaaaaaaaaaaaab8"
reset_ee; touch "$T/leaf.isca"; dep aaaaaaaaaaaaaab9; req "$(ISS aaaaaaaaaaaaaab9)"; expect_eq "certificat d'autorité rendu à la place d'un certificat final : refusé" false "$RES_OK"
check "rien n'est publié" test ! -e "$R/pki-cert/aaaaaaaaaaaaaab9"
check "le dossier d'échange est vidé après un refus" bash -c "[ -z \"\$(ls -A '$WORKH')\" ]"
reset_ee; printf '{"action":"cert_issue","id":"aaaaaaaaaaaaaac1","ca":"Lab-Sub","profile":"user","cn":"x"}' > "$G/.pki-request"; dep aaaaaaaaaaaaaac1; "$PKI" request >/dev/null 2>&1
check "demande JSON refusée : EJBCA n'est pas appelé" bash -c "[ ! -s '$T/ejbca.log' ]"

echo "== Révocation =="
reset_ee; dep ccccccccccccccc1; req "$(ISS ccccccccccccccc1)"; expect_eq "préparation : un certificat à révoquer" true "$RES_OK"; SER="$(cat "$T/leaf.serial")"; : > "$T/ejbca.log"
REV() { printf '{"action":"cert_revoke","ca":"Lab-Sub","serial":"%s","reason":%s}' "$1" "${2:-1}"; }
req "$(REV "$SER" 1)"; expect_eq "révocation acceptée" true "$RES_OK"
check "commande de révocation : nom distinctif EJBCA, série, motif" grep -q "ra revokecert --dn $SUBDN -s $SER -r 1" "$T/ejbca.log"
check "la CRL est renouvelée tout de suite" grep -q "ca createcrl --caname Lab-Sub" "$T/ejbca.log"
check "message : CRL à jour" grep -qi "à jour" <<< "$RES_MSG"
reset_ee; echo 40 > "$T/leaf.status"; req "$(REV "$SER" 1)"; expect_eq "refus : déjà révoqué" false "$RES_OK"; check "motif lisible" grep -qi "déjà" <<< "$RES_MSG"
check "aucune commande de révocation rejouée" bash -c "! grep -q revokecert '$T/ejbca.log'"
echo 20 > "$T/leaf.status"; reset_ee; echo 20 > "$T/leaf.status"; req "$(REV ABCDEF 1)"; expect_eq "refus : série inconnue de l'autorité" false "$RES_OK"
check "série inconnue : aucune révocation" bash -c "! grep -q revokecert '$T/ejbca.log'"
req "$(REV "$SER" 1 | sed 's/Lab-Sub/Nope/')"; expect_eq "refus : autorité inexistante" false "$RES_OK"
req '{"action":"cert_revoke","ca":"Lab-Sub","serial":"'"$SER"'","reason":2}'; expect_eq "refus : motif 2 (compromission de l'autorité)" false "$RES_OK"
check "aucune révocation pour une demande refusée" bash -c "! grep -q revokecert '$T/ejbca.log'"
reset_ee; echo 20 > "$T/leaf.status"; touch "$T/fail.revoke"; req "$(REV "$SER" 4)"; expect_eq "EJBCA ne révoque pas : échec détecté (état relu dans la base)" false "$RES_OK"; check "motif : non enregistrée" grep -qi "enregistr" <<< "$RES_MSG"
reset_ee; echo 20 > "$T/leaf.status"; touch "$T/fail.crl"; req "$(REV "$SER" 5)"; expect_eq "CRL non renouvelée : la révocation reste réussie" true "$RES_OK"; check "avertissement lisible" grep -qi "AVERTISSEMENT" <<< "$RES_MSG"
reset_ee; echo 20 > "$T/leaf.status"; req "$(REV "$SER" 0)"; expect_eq "motif 0 (non précisé) admis" true "$RES_OK"
reset_ee; echo 20 > "$T/leaf.status"; req '{"action":"cert_revoke","id":"cccccccccccccc99","ca":"Lab-Sub","serial":"'"$SER"'","reason":1}'; expect_eq "révocation avec référence : acceptée" true "$RES_OK"; expect_eq "la référence est rendue à la console" cccccccccccccc99 "$RES_REF"
rm -f "$T/healthy"; reset_ee; echo 20 > "$T/leaf.status"; req "$(REV "$SER" 1)"; expect_eq "refus : PKI qui ne répond pas" false "$RES_OK"; touch "$T/healthy"

echo "== Droit de lecture de la console et purge =="
: > "$PLOG"; "$PKI" status >/dev/null 2>&1
check "droit de lecture : seulement certificatedata et base64certdata" grep -q "grant select on certificatedata, base64certdata to %I" "$PLOG"
check "droit de lecture : jamais cadata ni userdata ni un droit d'écriture" bash -c "! grep -iE 'grant [^;]*(cadata|userdata|insert|update|delete|all)' '$PLOG'"
check "droit de lecture : posé sur la base ejbca, pas sur postgres" grep -q "psql .*-d ejbca" "$PLOG"
check "droit de lecture : rôle de la console" grep -q ":'r'" "$PLOG"
mkdir -p "$R/pki-cert/dddddddddddddddd" "$R/pki-cert/eeeeeeeeeeeeeeee" "$R/pki-cert/not-an-id"; touch "$R/pki-cert/dddddddddddddddd/cert.pem" "$R/pki-cert/eeeeeeeeeeeeeeee/cert.pem"
touch -d '-3 hours' "$R/pki-cert/dddddddddddddddd" "$R/pki-cert/not-an-id"
touch "$G/pki-in/1111111111111111.csr.pem" "$G/pki-in/2222222222222222.csr.pem" "$G/pki-in/quelque-chose.pem"
touch -d '-3 hours' "$G/pki-in/1111111111111111.csr.pem" "$G/pki-in/quelque-chose.pem"
"$PKI" maintain >/dev/null 2>&1
check "maintenance : certificat relevable depuis plus d'une heure purgé" test ! -e "$R/pki-cert/dddddddddddddddd"
check "maintenance : certificat récent conservé" test -d "$R/pki-cert/eeeeeeeeeeeeeeee"
check "maintenance : dossier qui n'a pas la forme d'un identifiant jamais touché" test -d "$R/pki-cert/not-an-id"
check "maintenance : demande de certificat orpheline (plus d'une heure) supprimée" test ! -e "$G/pki-in/1111111111111111.csr.pem"
check "maintenance : demande de certificat récente conservée" test -e "$G/pki-in/2222222222222222.csr.pem"
check "maintenance : fichier étranger du dossier de dépôt jamais touché" test -e "$G/pki-in/quelque-chose.pem"

echo "== Ligne de commande directe =="
reset_ee; dep bbbbbbbbbbbbbbb1; "$PKI" cert-issue bbbbbbbbbbbbbbb1 Lab-Sub machine "CN=pc01,O=Lab,C=FR" "dNSName=pc01.lab.test" >/dev/null 2>&1; expect_eq "cert-issue : émission en ligne de commande" 0 $?
check "cert-issue : profil machine" grep -q -- "--certprofile DDI-Client-Machine" "$T/ejbca.log"
"$PKI" cert-issue 'x;y' Lab-Sub machine "CN=pc01" "" >/dev/null 2>&1; expect_eq "cert-issue : identifiant invalide refusé" 1 $?
"$PKI" cert-issue bbbbbbbbbbbbbbb2 Lab-Sub EMPTY "CN=pc01" "" >/dev/null 2>&1; expect_eq "cert-issue : profil inconnu refusé" 1 $?
"$PKI" cert-revoke Lab-Sub 'FF;rm' 1 >/dev/null 2>&1; expect_eq "cert-revoke : série invalide refusée" 1 $?

finish
