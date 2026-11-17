#!/usr/bin/env bash
# Batterie 32 — autorités de la PKI du DDI (0.14.1), sans conteneur ni PostgreSQL : (1) le helper pki-helper.py avec du vrai matériel openssl
# (analyse des demandes, dépôts, contrôle du certificat reçu, de la chaîne et de la CRL, publication des autorités, adresses publiques) ;
# (2) la logique de ddibuntu-pki avec des bouchons (podman, psql, systemctl, curl) : garde « base sans secrets », remise à zéro, état publié,
# lignes de commande exactes envoyées à la CLI d'EJBCA, renouvellement des CRL par le minuteur. Le vrai EJBCA est vu par la batterie 33.
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

echo "== Matériel de test (clés et certificats openssl) =="
mkec "$W/root.key"
openssl req -x509 -new -key "$W/root.key" -days 3650 -subj "/C=FR/O=Laboratoire/CN=Lab Root CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/root.pem" 2>/dev/null
mkec "$W/other.key"
openssl req -x509 -new -key "$W/other.key" -days 3650 -subj "/C=FR/O=Autre/CN=Autre racine" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/other.pem" 2>/dev/null
mkec "$W/iss.key"
openssl req -new -key "$W/iss.key" -subj "/C=FR/O=Laboratoire/CN=Emettrice" -out "$W/iss.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$W/ca.ext"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > "$W/leaf.ext"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n' > "$W/nocertsign.ext"
sign() { openssl x509 -req -in "$1" -CA "$2" -CAkey "$3" -CAcreateserial -days "${5:-1825}" -extfile "$4" -out "$6" 2>/dev/null; }
sign "$W/iss.csr" "$W/root.pem" "$W/root.key" "$W/ca.ext" 1825 "$W/iss.pem"
sign "$W/iss.csr" "$W/root.pem" "$W/root.key" "$W/leaf.ext" 1825 "$W/leaf.pem"
sign "$W/iss.csr" "$W/root.pem" "$W/root.key" "$W/nocertsign.ext" 1825 "$W/nocs.pem"
sign "$W/iss.csr" "$W/other.pem" "$W/other.key" "$W/ca.ext" 1825 "$W/iss-badchain.pem"
mkec "$W/iss2.key"
openssl req -new -key "$W/iss2.key" -subj "/C=FR/O=Laboratoire/CN=Emettrice" -out "$W/iss2.csr" 2>/dev/null
sign "$W/iss2.csr" "$W/root.pem" "$W/root.key" "$W/ca.ext" 1825 "$W/iss-otherkey.pem"
openssl req -new -key "$W/iss.key" -subj "/C=FR/O=Laboratoire/CN=Un autre nom" -out "$W/iss-name.csr" 2>/dev/null
sign "$W/iss-name.csr" "$W/root.pem" "$W/root.key" "$W/ca.ext" 1825 "$W/iss-othername.pem"
mkec "$W/ext.key"
openssl req -x509 -new -key "$W/ext.key" -days 3650 -subj "/C=FR/O=Hors ligne/CN=Racine hors ligne" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/ext.pem" 2>/dev/null
for f in root other iss leaf nocs iss-badchain iss-otherkey iss-othername ext; do check "matériel : $f.pem fabriqué" test -s "$W/$f.pem"; done
mkcrl() {   # $1 = clé, $2 = certificat, $3 = sortie PEM, $4 = jours
  printf '[ca]\ndefault_ca=c\n[c]\ndatabase=%s/idx\ncrlnumber=%s/crlnum\ndefault_md=sha256\ndefault_crl_days=%s\n' "$W" "$W" "${4:-30}" > "$W/crl.cnf"
  : > "$W/idx"; echo 01 > "$W/crlnum"
  openssl ca -config "$W/crl.cnf" -gencrl -keyfile "$1" -cert "$2" -out "$3" >/dev/null 2>&1
}
mkcrl "$W/root.key" "$W/root.pem" "$W/root.crl.pem" 30
mkcrl "$W/other.key" "$W/other.pem" "$W/other.crl.pem" 30
check "matériel : CRL fabriquées" test -s "$W/root.crl.pem" -a -s "$W/other.crl.pem"

echo "== Helper : analyse des demandes de la console =="
out="$(pr '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}')"; rc=$?
expect_eq "racine valide : acceptée" 0 "$rc"
expect_eq "racine valide : sortie canonique" "action	ca_root
name	Lab-Root
alg	rsa3072
days	3650
dn	CN=Lab Root CA,O=Laboratoire,C=FR" "$out"
expect_eq "unité d'organisation placée avant l'organisation" "dn	CN=X,OU=Pôle,O=Lab,C=FR" "$(pr '{"action":"ca_root","name":"R","alg":"ecp256","days":365,"cn":"X","ou":"Pôle","o":"Lab","c":"FR"}' | grep '^dn')"
expect_eq "émettrice : signeur « external » par défaut" "signedBy	external" "$(pr '{"action":"ca_issuing","name":"I","alg":"ecp384","days":1825,"cn":"X"}' | grep '^signedBy')"
expect_eq "émettrice : signeur interne nommé" "signedBy	Lab-Root" "$(pr '{"action":"ca_issuing","name":"I","alg":"rsa4096","days":1825,"cn":"X","signedBy":"Lab-Root"}' | grep '^signedBy')"
expect_eq "import accepté" "name	Lab-Sub" "$(pr '{"action":"ca_import","name":"Lab-Sub"}' | grep '^name')"
expect_eq "CRL accepté" "action	ca_crl" "$(pr '{"action":"ca_crl","name":"Lab-Sub"}' | grep '^action')"
expect_eq "CRL de racine externe acceptée" "name	ExtRoot-0a1b2c3d" "$(pr '{"action":"ca_rootcrl","name":"ExtRoot-0a1b2c3d"}' | grep '^name')"
expect_eq "remise à zéro acceptée" "action	reset" "$(pr '{"action":"reset"}')"
refuse() { local out rc; out="$(pr "$2" 2>/dev/null)"; rc=$?; if [[ "$rc" -ne 0 && -z "$out" ]]; then ok "refusée : $1"; else ko "refusée : $1" "rc=$rc sortie=[$out]"; fi; }
refuse "JSON illisible" 'pas du json'
refuse "tableau JSON" '[1,2]'
refuse "action inconnue" '{"action":"rm -rf"}'
refuse "action absente" '{}'
refuse "nom ManagementCA" '{"action":"ca_root","name":"ManagementCA","alg":"rsa3072","days":3650,"cn":"X"}'
refuse "nom ExtRoot-… réservé" '{"action":"ca_root","name":"ExtRoot-0a1b2c3d","alg":"rsa3072","days":3650,"cn":"X"}'
refuse "nom avec espace" '{"action":"ca_root","name":"a b","alg":"rsa3072","days":3650,"cn":"X"}'
refuse "nom avec retour à la ligne" '{"action":"ca_root","name":"a\nb","alg":"rsa3072","days":3650,"cn":"X"}'
refuse "nom qui remonte l'arborescence" '{"action":"ca_root","name":"../etc","alg":"rsa3072","days":3650,"cn":"X"}'
refuse "nom commençant par un point" '{"action":"ca_root","name":".caché","alg":"rsa3072","days":3650,"cn":"X"}'
refuse "nom de 49 caractères" "{\"action\":\"ca_root\",\"name\":\"$(printf 'a%.0s' $(seq 49))\",\"alg\":\"rsa3072\",\"days\":3650,\"cn\":\"X\"}"
refuse "algorithme inconnu" '{"action":"ca_root","name":"R","alg":"des","days":3650,"cn":"X"}'
refuse "durée racine trop courte" '{"action":"ca_root","name":"R","alg":"rsa3072","days":364,"cn":"X"}'
refuse "durée racine trop longue" '{"action":"ca_root","name":"R","alg":"rsa3072","days":7306,"cn":"X"}'
refuse "durée émettrice trop longue" '{"action":"ca_issuing","name":"R","alg":"rsa3072","days":3651,"cn":"X"}'
refuse "durée en texte" '{"action":"ca_root","name":"R","alg":"rsa3072","days":"3650","cn":"X"}'
refuse "durée décimale" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650.5,"cn":"X"}'
refuse "durée booléenne" '{"action":"ca_root","name":"R","alg":"rsa3072","days":true,"cn":"X"}'
refuse "CN absent" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650}'
refuse "CN avec virgule (injection d'élément)" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X,O=pirate"}'
refuse "CN avec plus" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X+UID=1"}'
refuse "CN avec égal" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X=1"}'
refuse "CN avec barre oblique inverse" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X\\Y"}'
refuse "CN avec guillemet" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X\"Y"}'
refuse "CN avec point-virgule" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X;Y"}'
refuse "CN avec barre oblique" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X/Y"}'
refuse "CN avec retour à la ligne" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X\nY"}'
refuse "CN avec tabulation" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X\tY"}'
refuse "CN avec espace en tête" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":" X"}'
refuse "CN vide" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":""}'
refuse "CN de 65 caractères" "{\"action\":\"ca_root\",\"name\":\"R\",\"alg\":\"rsa3072\",\"days\":3650,\"cn\":\"$(printf 'a%.0s' $(seq 65))\"}"
refuse "pays de trois lettres" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X","c":"FRA"}'
refuse "pays en minuscules" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X","c":"fr"}'
refuse "O non textuelle" '{"action":"ca_root","name":"R","alg":"rsa3072","days":3650,"cn":"X","o":12}'
refuse "signeur invalide" '{"action":"ca_issuing","name":"R","alg":"rsa3072","days":1825,"cn":"X","signedBy":"../x"}'
refuse "signeur ManagementCA" '{"action":"ca_issuing","name":"R","alg":"rsa3072","days":1825,"cn":"X","signedBy":"ManagementCA"}'
refuse "import d'une racine externe par son nom réservé" '{"action":"ca_import","name":"ExtRoot-0a1b2c3d"}'
refuse "CRL d'une autre autorité qu'ExtRoot" '{"action":"ca_rootcrl","name":"Lab-Root"}'
refuse "CRL de racine à empreinte invalide" '{"action":"ca_rootcrl","name":"ExtRoot-ZZZZZZZZ"}'
refuse "CRL de racine à empreinte trop courte" '{"action":"ca_rootcrl","name":"ExtRoot-0a1b2c3"}'
refuse "demande de plus de 4096 octets" "{\"action\":\"ca_root\",\"name\":\"R\",\"alg\":\"rsa3072\",\"days\":3650,\"cn\":\"X\",\"pad\":\"$(printf 'a%.0s' $(seq 4100))\"}"
refuse "installation sans image" '{"action":"apply","hostname":"pki.lab.test"}'
refuse "installation avec image d'un autre dépôt" '{"action":"apply","image":"docker.io/evil/ejbca-ce:9.6.3","hostname":"pki.lab.test"}'

echo "== Helper : dépôts de la console (certificats, chaîne, CRL) =="
D="$W/dep"; mkdir -p "$D"
cat "$W/root.pem" "$W/ext.pem" > "$W/two.pem"
out="$(ph deposit "$W/root.pem" "$D/one.pem" certs 1)"; expect_eq "un certificat PEM accepté" "OK	1" "$out"
expect_eq "dépôt réécrit en 0600" 600 "$(stat -c %a "$D/one.pem")"
check "dépôt réécrit : certificat valide pour openssl" openssl x509 -in "$D/one.pem" -noout
out="$(ph deposit "$W/two.pem" "$D/two.pem" certs 5)"; expect_eq "deux certificats acceptés (maximum 5)" "OK	2" "$out"
out="$(ph deposit "$W/two.pem" "$D/two-bad.pem" certs 1)"; expect_eq "deux certificats refusés (maximum 1)" ERR "${out%%	*}"
check "refus : rien n'a été écrit" test ! -e "$D/two-bad.pem"
openssl x509 -in "$W/root.pem" -outform DER -out "$W/root.der"
out="$(ph deposit "$W/root.der" "$D/der.pem" certs 1)"; expect_eq "certificat DER accepté" "OK	1" "$out"
check "certificat DER : réécrit en PEM" grep -q "BEGIN CERTIFICATE" "$D/der.pem"
printf 'rien de valable\n' > "$W/garbage"; out="$(ph deposit "$W/garbage" "$D/g.pem" certs 1)"; expect_eq "dépôt qui n'est pas un certificat refusé" ERR "${out%%	*}"
: > "$W/empty"; out="$(ph deposit "$W/empty" "$D/e.pem" certs 1)"; expect_eq "dépôt vide refusé" ERR "${out%%	*}"
head -c 17000 /dev/zero | tr '\0' 'A' > "$W/big"; out="$(ph deposit "$W/big" "$D/b.pem" certs 1)"; expect_eq "dépôt de plus de 16 Ko refusé" ERR "${out%%	*}"
ln -sf /etc/passwd "$W/link"; out="$(ph deposit "$W/link" "$D/l.pem" certs 1)"; expect_eq "lien symbolique refusé" ERR "${out%%	*}"
check "lien symbolique : la cible n'est pas copiée" test ! -e "$D/l.pem"
out="$(ph deposit "$W/nonexistent" "$D/n.pem" certs 1)"; expect_eq "dépôt absent refusé" ERR "${out%%	*}"
out="$(ph deposit "$W/root.pem" "$D/c.der" crl 1)"; expect_eq "un certificat n'est pas une CRL" ERR "${out%%	*}"
out="$(ph deposit "$W/root.crl.pem" "$D/crl1.der" crl 1)"; expect_eq "CRL PEM acceptée" "OK	1" "$out"
check "CRL PEM : réécrite en DER lisible" openssl crl -inform DER -in "$D/crl1.der" -noout
openssl crl -in "$W/root.crl.pem" -outform DER -out "$W/root.crl.der"
out="$(ph deposit "$W/root.crl.der" "$D/crl2.der" crl 1)"; expect_eq "CRL DER acceptée" "OK	1" "$out"
out="$(ph deposit "$W/root.crl.pem" "$D/crl3.pem" certs 1)"; expect_eq "une CRL n'est pas un certificat" ERR "${out%%	*}"

echo "== Helper : certificat reçu de la racine hors ligne =="
ci() { ph check-issued "$W/iss.csr" "$1" "$W/root.pem"; }
out="$(ci "$W/iss.pem")"; expect_eq "certificat correct accepté" OK "${out%%	*}"
out="$(ci "$W/iss-otherkey.pem")"; expect_eq "autre clé publique refusée" ERR "${out%%	*}"; check "motif : clé" grep -qi "clé" <<< "$out"
out="$(ci "$W/leaf.pem")"; expect_eq "certificat sans CA:TRUE refusé" ERR "${out%%	*}"; check "motif : CA:TRUE" grep -q "CA:TRUE" <<< "$out"
out="$(ci "$W/nocs.pem")"; expect_eq "certificat sans keyCertSign refusé" ERR "${out%%	*}"
out="$(ci "$W/iss-othername.pem")"; expect_eq "autre nom distinctif refusé" ERR "${out%%	*}"
out="$(ci "$W/iss-badchain.pem")"; expect_eq "certificat signé par une autre racine refusé" ERR "${out%%	*}"
out="$(ph check-issued "$W/iss.csr" "$W/iss.pem" "$W/other.pem")"; expect_eq "chaîne qui n'est pas celle du signataire refusée" ERR "${out%%	*}"
out="$(ph check-issued "$W/iss.csr" "$W/garbage" "$W/root.pem")"; expect_eq "certificat illisible refusé" ERR "${out%%	*}"

echo "== Helper : chaîne de la racine hors ligne =="
out="$(ph check-chain "$W/root.pem" "$W/root-out.pem")"; sha="$(openssl x509 -in "$W/root.pem" -outform DER | sha256sum | cut -c1-8)"
expect_eq "racine seule : acceptée avec son empreinte" "OK	$sha	1	CN=Lab Root CA,O=Laboratoire,C=FR" "$out"
check "racine écrite en PEM" openssl x509 -in "$W/root-out.pem" -noout
cat "$W/iss.pem" "$W/root.pem" > "$W/chain2.pem"
out="$(ph check-chain "$W/chain2.pem" "$W/root-out2.pem")"; expect_eq "chaîne émettrice + racine acceptée (2 certificats)" "OK	$sha	2" "$(printf '%s' "$out" | cut -f1-3)"
out="$(ph check-chain "$W/iss.pem" "$W/root-out3.pem")"; expect_eq "chaîne sans racine auto-signée refusée" ERR "${out%%	*}"
out="$(ph check-chain "$W/leaf.pem" "$W/root-out4.pem")"; expect_eq "certificat qui n'est pas une autorité refusé" ERR "${out%%	*}"
cat "$W/root.pem" "$W/other.pem" > "$W/chain-bad.pem"; out="$(ph check-chain "$W/chain-bad.pem" "$W/root-out5.pem")"; expect_eq "deux racines auto-signées refusées (une seule, en dernier)" ERR "${out%%	*}"
cat "$W/iss.pem" "$W/other.pem" > "$W/chain-bad2.pem"; out="$(ph check-chain "$W/chain-bad2.pem" "$W/root-out5b.pem")"; expect_eq "émettrice qui ne remonte pas à la racine finale refusée" ERR "${out%%	*}"
check "refus : aucune racine écrite" test ! -e "$W/root-out5.pem" -a ! -e "$W/root-out5b.pem"
out="$(ph check-chain "$W/garbage" "$W/root-out6.pem")"; expect_eq "chaîne illisible refusée" ERR "${out%%	*}"

echo "== Helper : CRL de la racine hors ligne =="
openssl crl -in "$W/root.crl.pem" -outform DER -out "$W/root.crl.der"; openssl crl -in "$W/other.crl.pem" -outform DER -out "$W/other.crl.der"
out="$(ph check-crl "$W/root.pem" "$W/root.crl.der")"; expect_eq "CRL signée par la racine acceptée" OK "${out%%	*}"
out="$(ph check-crl "$W/root.pem" "$W/other.crl.der")"; expect_eq "CRL signée par une autre autorité refusée" ERR "${out%%	*}"
out="$(ph check-crl "$W/root.pem" "$W/garbage")"; expect_eq "CRL illisible refusée" ERR "${out%%	*}"
printf '[ca]\ndefault_ca=c\n[c]\ndatabase=%s/idx\ncrlnumber=%s/crlnum\ndefault_md=sha256\ndefault_crl_days=1\n' "$W" "$W" > "$W/crl.cnf"; : > "$W/idx"; echo 01 > "$W/crlnum"
openssl ca -config "$W/crl.cnf" -gencrl -keyfile "$W/root.key" -cert "$W/root.pem" -crl_lastupdate 20250101000000Z -crl_nextupdate 20250102000000Z -out "$W/root.old.pem" >/dev/null 2>&1
openssl crl -in "$W/root.old.pem" -outform DER -out "$W/root.old.der"
out="$(ph check-crl "$W/root.pem" "$W/root.old.der")"; expect_eq "CRL déjà expirée refusée" ERR "${out%%	*}"; check "motif : prochaine mise à jour passée" grep -qi "expir\|périm\|nextUpdate\|prochaine" <<< "$out"

echo "== Helper : adresses publiques et conversion =="
expect_eq "adresses de CRL et de certificat (nom distinctif encodé, port 8080)" "http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DLab%20Root%20CA%2CO%3DLaboratoire%2CC%3DFR
http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3DLab%20Root%20CA%2CO%3DLaboratoire%2CC%3DFR" "$(ph urls pki.lab.test 8080 'CN=Lab Root CA,O=Laboratoire,C=FR')"
expect_eq "conversion base64 → PEM : identique au PEM d'origine" "$(openssl x509 -in "$W/root.pem")" "$(b64 "$W/root.pem" | ph b64pem)"

echo "== Helper : publication des autorités (lecture de la base) =="
now_ms=$(( $(date +%s) * 1000 ))
{
  printf 'Lab-Root\t1\tCN=Lab Root CA,O=Laboratoire,C=FR\t1001\t%s\n' "$(b64 "$W/root.pem")"
  printf 'Lab-Sub\t1\tCN=Emettrice,O=Laboratoire,C=FR\t1002\t%s\n' "$(b64 "$W/iss.pem")"
  printf 'Lab-Wait\t2\tCN=En attente,O=Laboratoire,C=FR\t1006\t\n'
  printf 'ExtRoot-0a1b2c3d\t6\tCN=Racine hors ligne,O=Hors ligne,C=FR\t1003\t%s\n' "$(b64 "$W/ext.pem")"
  printf 'ManagementCA\t1\tUID=x,CN=ManagementCA\t1\t%s\n' "$(b64 "$W/root.pem")"
  printf 'a b\t1\tCN=Nom mauvais,O=X\t1005\t%s\n' "$(b64 "$W/other.pem")"
  printf 'ligne coupée par un retour à la ligne\n'
  printf 'v6F7D4ARSA8Zh9YBXaWGPVcFcYwNVOHwQvQtjJj0ZSn7\n'
} > "$W/cas.tsv"
{
  printf 'CN=Lab Root CA,O=Laboratoire,C=FR\t3\t%s\t%s\t%s\n' "$(( now_ms - 86400000 * 2 ))" "$(( now_ms + 86400000 * 5 ))" "$(base64 -w0 "$W/root.crl.der")"
  printf 'CN=Emettrice,O=Laboratoire,C=FR\t7\t%s\t%s\t%s\n' "$now_ms" "$(( now_ms + 86400000 * 7 ))" "$(base64 -w0 "$W/other.crl.der")"
  printf 'Morceau de base64 coupé\n'
} > "$W/crls.tsv"
RUNX="$T/pub"; CAX="$T/pubca"; mkdir -p "$RUNX/pki-ca/ancien" "$CAX/Lab-Sub" "$CAX/Lab-Wait"; echo x > "$RUNX/pki-ca/ancien/cert.pem"
printf '{"kind":"issuing","signedBy":"Lab-Root","alg":"ecp256","createdAt":1700000000,"imported":true}' > "$CAX/Lab-Sub/meta.json"
printf '{"kind":"issuing","signedBy":"external","alg":"rsa3072","createdAt":1700000100,"extRoot":"ExtRoot-0a1b2c3d"}' > "$CAX/Lab-Wait/meta.json"
printf -- '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' > "$CAX/Lab-Wait/chain.pem"
openssl req -in "$W/iss.csr" -out "$CAX/Lab-Wait/csr.pem" 2>/dev/null
check "publication sans erreur (umask 077 de root)" bash -c "umask 077; python3 '$H' publish-cas '$W/cas.tsv' '$W/crls.tsv' '$CAX' '$RUNX' pki.lab.test 8080"
expect_eq "dossiers publiés lisibles par la console (755)" "755 755" "$(stat -c %a "$RUNX/pki-ca") $(stat -c %a "$RUNX/pki-ca/Lab-Root")"
expect_eq "fichiers publiés lisibles par la console (644)" "644 644 644" "$(stat -c %a "$RUNX/pki-cas.json" "$RUNX/pki-ca/Lab-Root/cert.pem" "$RUNX/pki-ca/Lab-Root/crl.der" | tr '\n' ' ' | sed 's/ $//')"
check "publication sans erreur" ph publish-cas "$W/cas.tsv" "$W/crls.tsv" "$CAX" "$RUNX" pki.lab.test 8080
J="$RUNX/pki-cas.json"
jq_() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
c = [x for x in d["cas"] if x["name"] == sys.argv[2]]
v = c[0] if c else {}
for k in sys.argv[3].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$J" "$1" "$2"; }
expect_eq "autorités publiées : sans ManagementCA ni ligne coupée" "ExtRoot-0a1b2c3d Lab-Root Lab-Sub Lab-Wait a b" "$(python3 -c 'import json,sys; print(" ".join(sorted(c["name"] for c in json.load(open(sys.argv[1]))["cas"])))' "$J")"
expect_eq "racine : sorte déduite du certificat auto-signé" root "$(jq_ Lab-Root kind)"
expect_eq "racine : auto-signée" true "$(jq_ Lab-Root selfSigned)"
expect_eq "racine : état actif" active "$(jq_ Lab-Root state)"
expect_eq "racine : clé EC de 256 bits" "EC 256 prime256v1" "$(jq_ Lab-Root keyAlg) $(jq_ Lab-Root keyBits) $(jq_ Lab-Root curve)"
expect_eq "racine : nom distinctif d'EJBCA conservé" "CN=Lab Root CA,O=Laboratoire,C=FR" "$(jq_ Lab-Root dn)"
expect_eq "racine : empreinte SHA-256 du certificat" "$(openssl x509 -in "$W/root.pem" -outform DER | sha256sum | cut -d' ' -f1)" "$(jq_ Lab-Root sha256)"
expect_eq "racine : numéro de CRL" 3 "$(jq_ Lab-Root crl.number)"
expect_eq "racine : CRL rapprochée par le nom distinctif d'EJBCA" true "$(jq_ Lab-Root files.crl)"
expect_eq "racine : adresse de CRL publiée" "http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DLab%20Root%20CA%2CO%3DLaboratoire%2CC%3DFR" "$(jq_ Lab-Root crlUrl)"
expect_eq "émettrice : sorte issuing (meta.json)" issuing "$(jq_ Lab-Sub kind)"
expect_eq "émettrice : signée par la racine du DDI (meta.json)" Lab-Root "$(jq_ Lab-Sub signedBy)"
expect_eq "émettrice : pas auto-signée" false "$(jq_ Lab-Sub selfSigned)"
expect_eq "émettrice reprise d'un PKCS#12 : drapeau « importée » publié" true "$(jq_ Lab-Sub imported)"
expect_eq "autorité créée par le DDI : pas « importée »" false "$(jq_ Lab-Root imported)"
expect_eq "émettrice : émetteur affiché avec le nom distinctif d'EJBCA de la racine" "CN=Lab Root CA,O=Laboratoire,C=FR" "$(jq_ Lab-Sub issuer)"
expect_eq "émettrice : chaîne publiée avec la racine" true "$(jq_ Lab-Sub files.chain)"
check "émettrice : le certificat se vérifie avec la chaîne publiée" openssl verify -CAfile "$RUNX/pki-ca/Lab-Sub/chain.pem" "$RUNX/pki-ca/Lab-Sub/cert.pem"
expect_eq "émettrice : numéro de CRL" 7 "$(jq_ Lab-Sub crl.number)"
expect_eq "en attente : état waiting" waiting "$(jq_ Lab-Wait state)"
expect_eq "en attente : demande de certificat publiée" true "$(jq_ Lab-Wait files.csr)"
expect_eq "en attente : racine hors ligne associée" ExtRoot-0a1b2c3d "$(jq_ Lab-Wait extRoot)"
expect_eq "autorité du DDI : pas de racine hors ligne associée" "" "$(jq_ Lab-Root extRoot)"
expect_eq "en attente : pas de certificat" false "$(jq_ Lab-Wait files.cert)"
expect_eq "racine externe : sorte extroot" extroot "$(jq_ ExtRoot-0a1b2c3d kind)"
expect_eq "racine externe : état external" external "$(jq_ ExtRoot-0a1b2c3d state)"
expect_eq "racine externe : certificat publié" true "$(jq_ ExtRoot-0a1b2c3d files.cert)"
expect_eq "nom inutilisable comme dossier : listé sans fichiers" false "$(jq_ 'a b' files.cert)"
check "nom inutilisable comme dossier : aucun dossier créé" test ! -e "$RUNX/pki-ca/a b"
expect_eq "dossier périmé supprimé" "ExtRoot-0a1b2c3d Lab-Root Lab-Sub Lab-Wait" "$(find "$RUNX/pki-ca" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
check "aucun dossier parasite issu d'une ligne coupée" test ! -e "$RUNX/pki-ca/v6F7D4ARSA8Zh9YBXaWGPVcFcYwNVOHwQvQtjJj0ZSn7"
check "la CRL publiée est lisible" openssl crl -inform DER -in "$RUNX/pki-ca/Lab-Root/crl.der" -noout
check "le certificat publié est de la bonne autorité" bash -c "openssl x509 -in '$RUNX/pki-ca/Lab-Root/cert.pem' -noout -subject | grep -q 'Lab Root CA'"
check "aucun fichier public ne contient de clé privée" bash -c "! grep -rl 'PRIVATE KEY' '$RUNX/pki-ca'"

echo "== Helper : contrôle d'un fichier PKCS#12 (0.14.4) =="
P12PW='Tést P12 pass$1'
mkec "$W/imp-root.key"; mkec "$W/impiss.key"; mkec "$W/impiss2.key"; mkec "$W/iss3.key"; mkec "$W/impiss3.key"; mkec "$W/other2.key"
openssl req -x509 -new -key "$W/imp-root.key" -days 3650 -subj "/C=FR/O=Import/CN=Import Root" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/imp-root.pem" 2>/dev/null
openssl req -x509 -new -key "$W/other2.key" -days 3650 -subj "/C=FR/O=Autre/CN=Autre racine" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/other2.pem" 2>/dev/null
openssl req -new -key "$W/impiss.key" -subj "/C=FR/O=Import/CN=Import Issuing" -out "$W/impiss.csr" 2>/dev/null
openssl req -new -key "$W/impiss2.key" -subj "/C=FR/O=Import/CN=Import Issuing 2" -out "$W/impiss2.csr" 2>/dev/null
openssl req -new -key "$W/impiss3.key" -subj "/C=FR/O=Import/CN=Import Issuing 3" -out "$W/impiss3.csr" 2>/dev/null
openssl req -new -key "$W/iss3.key" -subj "/C=FR/O=Laboratoire/CN=Import Sous Lab" -out "$W/iss3.csr" 2>/dev/null
sign "$W/impiss.csr" "$W/imp-root.pem" "$W/imp-root.key" "$W/ca.ext" 1825 "$W/impiss.pem"
sign "$W/impiss2.csr" "$W/imp-root.pem" "$W/imp-root.key" "$W/ca.ext" 1825 "$W/impiss2.pem"
sign "$W/impiss3.csr" "$W/imp-root.pem" "$W/imp-root.key" "$W/ca.ext" 1825 "$W/impiss3.pem"
sign "$W/iss3.csr" "$W/root.pem" "$W/root.key" "$W/ca.ext" 1825 "$W/iss3.pem"
sign "$W/iss.csr" "$W/root.pem" "$W/root.key" "$W/ca.ext" 0 "$W/iss-short.pem"
mkp12() {   # $1 = sortie, $2 = clé, $3 = certificat, $4 = autres certificats (facultatif), $5 = mot de passe (facultatif)
  local a=(-export -inkey "$2" -in "$3" -out "$1" -passout "pass:${5-$P12PW}" -name ca)
  [[ -n "${4:-}" ]] && a+=(-certfile "$4")
  openssl pkcs12 "${a[@]}" 2>/dev/null
}
mkp12 "$W/imp-root.p12" "$W/imp-root.key" "$W/imp-root.pem"
mkp12 "$W/impiss.p12" "$W/impiss.key" "$W/impiss.pem" "$W/imp-root.pem"
mkp12 "$W/impiss2.p12" "$W/impiss2.key" "$W/impiss2.pem" "$W/imp-root.pem"
mkp12 "$W/impiss3.p12" "$W/impiss3.key" "$W/impiss3.pem" "$W/imp-root.pem"
mkp12 "$W/iss3.p12" "$W/iss3.key" "$W/iss3.pem" "$W/root.pem"
mkp12 "$W/dup.p12" "$W/iss.key" "$W/iss.pem" "$W/root.pem"
mkp12 "$W/root.p12" "$W/root.key" "$W/root.pem"
mkp12 "$W/leaf.p12" "$W/iss.key" "$W/leaf.pem" "$W/root.pem"
mkp12 "$W/nocs.p12" "$W/iss.key" "$W/nocs.pem" "$W/root.pem"
mkp12 "$W/nochain.p12" "$W/impiss.key" "$W/impiss.pem"
mkp12 "$W/badchain.p12" "$W/iss.key" "$W/iss-badchain.pem" "$W/other2.pem"
mkp12 "$W/short.p12" "$W/iss.key" "$W/iss-short.pem" "$W/root.pem"
openssl pkcs12 -export -nokeys -in "$W/iss.pem" -certfile "$W/root.pem" -out "$W/nokey.p12" -passout "pass:$P12PW" 2>/dev/null
openssl pkcs12 -export -inkey "$W/impiss.key" -in "$W/impiss.pem" -certfile "$W/imp-root.pem" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 \
  -out "$W/old.p12" -passout "pass:$P12PW" 2>/dev/null
for f in imp-root impiss impiss2 impiss3 iss3 dup root leaf nocs nochain badchain short nokey old; do check "matériel PKCS#12 : $f.p12 fabriqué" test -s "$W/$f.p12"; done
p12c() {   # $1 = fichier, $2 = mot de passe (par défaut le bon) ; sortie du helper, fichiers dans $W/p12out
  rm -rf "$W/p12out" "$W/p12.chain"; mkdir -p "$W/p12out"; printf '%s' "${2-$P12PW}" > "$W/p12.pw"
  ph p12-check "$1" "$W/p12.pw" "$W/p12out" "$W/p12.chain" 2>&1
}
fld() { printf '%s' "$1" | cut -f"$2"; }
IMPSHA="$(openssl x509 -in "$W/imp-root.pem" -outform DER | sha256sum | cut -c1-8)"
out="$(p12c "$W/impiss.p12")"
expect_eq "émettrice : fichier accepté" OK "$(fld "$out" 1)"
check "émettrice : mot de passe à usage unique de 32 caractères alphanumériques" bash -c "[[ '$(fld "$out" 2)' =~ ^[A-Za-z0-9]{32}\$ ]]"
expect_eq "émettrice : sorte issuing" issuing "$(fld "$out" 3)"
expect_eq "émettrice : algorithme ecp256" ecp256 "$(fld "$out" 4)"
expect_eq "émettrice : empreinte (8 caractères) de la racine" "$IMPSHA" "$(fld "$out" 5)"
check "émettrice : nom distinctif rendu" grep -q 'Import Issuing' <<< "$(fld "$out" 6)"
check "émettrice : fin de validité rendue" grep -Eq '^20[0-9]{2}-' <<< "$(fld "$out" 7)"
check "émettrice : nom distinctif de la racine rendu" grep -q 'Import Root' <<< "$(fld "$out" 8)"
OT="$(fld "$out" 2)"
check "fichier rhabillé : s'ouvre avec le mot de passe à usage unique" openssl pkcs12 -in "$W/p12out/ca.p12" -passin "pass:$OT" -nokeys -noout
check "fichier rhabillé : ne s'ouvre PAS avec le mot de passe d'origine" bash -c "! openssl pkcs12 -in '$W/p12out/ca.p12' -passin 'pass:$P12PW' -nokeys -noout 2>/dev/null"
expect_eq "fichier rhabillé : une clé et deux certificats" "1 2" "$(openssl pkcs12 -in "$W/p12out/ca.p12" -passin "pass:$OT" -nodes 2>/dev/null | awk '/BEGIN (EC |RSA )?PRIVATE KEY/{k++} /BEGIN CERTIFICATE/{c++} END{print k+0, c+0}')"
check "racine extraite : celle du fichier" test "$(openssl x509 -in "$W/p12out/root.pem" -outform DER | sha256sum | cut -c1-8)" = "$IMPSHA"
check "chaîne publique : la racine seule, sans clé" bash -c "grep -c 'BEGIN CERTIFICATE' '$W/p12.chain' | grep -qx 1 && ! grep -q PRIVATE '$W/p12.chain'"
check "chaîne publique : lisible par le groupe (0640)" test "$(stat -c %a "$W/p12.chain")" = 640
out="$(p12c "$W/imp-root.p12")"
expect_eq "racine : fichier accepté" OK "$(fld "$out" 1)"
expect_eq "racine : sorte root" root "$(fld "$out" 3)"
expect_eq "racine : pas de racine supérieure" "-	-" "$(fld "$out" 5)	$(fld "$out" 8)"
check "racine : pas de root.pem extrait" test ! -e "$W/p12out/root.pem"
out="$(p12c "$W/old.p12")"; expect_eq "ancien chiffrement (3DES / SHA-1, comme l'export de Windows) : accepté" OK "$(fld "$out" 1)"
out="$(p12c "$W/impiss.p12" 'mauvais mot de passe')"
expect_eq "mauvais mot de passe : refusé" ERR "$(fld "$out" 1)"
check "mauvais mot de passe : message clair, sans le mot de passe" bash -c "grep -qi 'mot de passe' <<< '$out' && ! grep -q 'mauvais mot de passe' <<< '$out'"
check "mauvais mot de passe : aucun fichier rhabillé" test ! -e "$W/p12out/ca.p12"
p12e() { out="$(p12c "$1" "${3-$P12PW}")"; expect_eq "refusé : $2" ERR "$(fld "$out" 1)"; check "refusé : $2 (message : $4)" grep -qi "$4" <<< "$out"; }
p12e "$W/nokey.p12" "aucune clé privée" "$P12PW" "une seule clé"
p12e "$W/leaf.p12" "certificat sans CA:TRUE" "$P12PW" "CA:TRUE"
p12e "$W/nocs.p12" "autorité sans keyCertSign" "$P12PW" "keyCertSign"
p12e "$W/nochain.p12" "chaîne incomplète (racine absente du fichier)" "$P12PW" "chaîne incomplète"
p12e "$W/badchain.p12" "chaîne dont la signature ne valide pas" "$P12PW" "chaîne ne valide pas"
p12e "$W/short.p12" "validité de moins d'un jour" "$P12PW" "moins d'un jour"
p12e "$W/garbage" "fichier qui n'est pas un PKCS#12" "$P12PW" "PKCS#12"
head -c 70000 /dev/zero | tr '\0' '0' > "$W/big.p12"; printf '\x30' | dd of="$W/big.p12" bs=1 conv=notrunc 2>/dev/null
p12e "$W/big.p12" "fichier de plus de 64 Ko" "$P12PW" "64 Ko au plus"
p12e "$W/impiss.p12" "mot de passe vide" "" "mot de passe"
printf 'x\ny' > "$W/ctl.pw"; out="$(ph p12-check "$W/impiss.p12" "$W/ctl.pw" "$W/p12out" "$W/p12.chain" 2>&1)"; expect_eq "refusé : mot de passe avec caractère de contrôle" ERR "$(fld "$out" 1)"
ln -sf "$W/impiss.p12" "$W/link.p12"; printf '%s' "$P12PW" > "$W/p12.pw"
out="$(ph p12-check "$W/link.p12" "$W/p12.pw" "$W/p12out" "$W/p12.chain" 2>&1)"; expect_eq "refusé : fichier déposé par lien symbolique" ERR "$(fld "$out" 1)"
out="$(ph p12-check "$W/absent.p12" "$W/p12.pw" "$W/p12out" "$W/p12.chain" 2>&1)"; expect_eq "refusé : fichier absent" ERR "$(fld "$out" 1)"
check "aucun secret restant dans /dev/shm ni dans le dossier temporaire du helper" bash -c "! ls /dev/shm /tmp 2>/dev/null | grep -qi 'ddi-p12\|ddi-secret'"
check "refus : le mot de passe d'origine n'est jamais écrit dans un message" bash -c "! grep -rl 'Tést P12 pass' '$W/p12out' 2>/dev/null"
expect_eq "dn-find : même nom, éléments dans un autre ordre et casse différente" "A" "$(printf 'A\tCN=Test,O=Lab,C=FR\nB\tCN=Autre,O=Lab,C=FR\n' | ph dn-find 'c=fr,o=LAB,cn=test')"
expect_eq "dn-find : nom différent" "" "$(printf 'A\tCN=Test,O=Lab,C=FR\n' | ph dn-find 'CN=Test,O=Lab,C=DE')"
expect_eq "dn-find : élément supplémentaire = autre nom" "" "$(printf 'A\tCN=Test,O=Lab,C=FR\n' | ph dn-find 'CN=Test,OU=X,O=Lab,C=FR')"
expect_eq "demande ca_import_p12 acceptée" "name	Imp-Iss" "$(pr '{"action":"ca_import_p12","name":"Imp-Iss"}' | grep '^name')"
refuse "ca_import_p12 : nom ExtRoot-… réservé" '{"action":"ca_import_p12","name":"ExtRoot-0a1b2c3d"}'
refuse "ca_import_p12 : nom ManagementCA" '{"action":"ca_import_p12","name":"ManagementCA"}'
refuse "ca_import_p12 : nom qui remonte l'arborescence" '{"action":"ca_import_p12","name":"../x"}'
refuse "ca_import_p12 : mot de passe glissé dans la demande (champ inconnu ignoré, mais nom invalide)" '{"action":"ca_import_p12","name":"a b","password":"x"}'
out="$(pr '{"action":"ca_import_p12","name":"Imp-Iss","password":"secret-glisse"}')"
check "ca_import_p12 : un champ supplémentaire (mot de passe) n'est pas relayé" bash -c "! grep -q 'secret-glisse' <<< '$out'"

echo "== Racine : installation avec bouchons =="
B="$T/bin"; mkdir -p "$B" "$T/etc" "$T/data" "$T/quad" "$T/run" "$T/gen/pki-in"
LOG="$T/calls.log"; PLOG="$T/psql.log"; CADB="$T/cadb.tsv"; : > "$CADB"; : > "$T/tokens.tsv"
WORKH="$T/data/persistent/work"
cat > "$B/podman" <<EOF
#!/bin/bash
echo "podman \$*" >> "$LOG"
case "\$1" in
  image) case "\$2" in exists) [ -f "$T/image.present" ] ;; inspect) echo "sha256:$(printf 'a%.0s' $(seq 64))" ;; esac ;;
  pull) touch "$T/image.present" ;;
  exec)
    a=("\$@"); i=0; while [ "\$i" -lt "\$#" ] && [ "\${a[\$i]}" != /opt/keyfactor/bin/ejbca.sh ]; do i=\$((i+1)); done
    s=("\${a[@]:\$((i+1))}")
    name=""; dn=""; by=""; file=""
    for ((j=2; j<\${#s[@]}; j++)); do case "\${s[\$j]}" in --caname) name="\${s[\$((j+1))]}";; --dn) dn="\${s[\$((j+1))]}";; --signedby) by="\${s[\$((j+1))]}";; -f) file="\${s[\$((j+1))]}";; esac; done
    case "\${s[0]} \${s[1]}" in
      "ca init")
        [ -f "$T/fail.init" ] && { echo "boom" >&2; exit 1; }
        st=1; [ "\$by" = External ] && { st=2; cp "$W/iss.csr.der" "$WORKH/\${name}_csr.der" 2>/dev/null; }
        printf '%s\t%s\t%s\t%s\n' "\$name" "\$st" "\$dn" "\$((2000 + \$(wc -l < "$CADB")))" >> "$CADB" ;;
      "ca importcacert")
        if awk -F'\t' -v n="\$name" '\$1==n{f=1} END{exit !f}' "$CADB"; then
          awk -F'\t' -v OFS='\t' -v n="\$name" '\$1==n{\$2=1} {print}' "$CADB" > "$CADB.n" && mv "$CADB.n" "$CADB"
        else
          dn6="\$(openssl x509 -in "$WORKH/\${file##*/}" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
          printf '%s\t6\t%s\t%s\n' "\$name" "\${dn6:-CN=Racine hors ligne,O=Hors ligne,C=FR}" "\$((2000 + \$(wc -l < "$CADB")))" >> "$CADB"
        fi
        echo "importé depuis \$file" >> "$LOG" ;;
      "ca importca")
        p12=""; kspw=""
        for ((j=2; j<\${#s[@]}; j++)); do case "\${s[\$j]}" in --p12) p12="\${s[\$((j+1))]}";; -kspassword) kspw="\${s[\$((j+1))]}";; esac; done
        [ -f "$T/fail.importca" ] && { echo "échec de l'import, mot de passe \$kspw" >&2; exit 1; }
        subj="\$(openssl pkcs12 -in "$WORKH/\${p12##*/}" -passin "pass:\$kspw" -nodes -clcerts -nokeys 2>/dev/null | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
        [ -n "\$subj" ] || { echo "PKCS#12 illisible avec le mot de passe reçu" >&2; exit 1; }
        printf '%s' "\$kspw" > "$T/onetime.pw"
        printf '%s\t1\t%s\t%s\n' "\$name" "\$subj" "\$((2000 + \$(wc -l < "$CADB")))" >> "$CADB" 
        # EJBCA 9.6.3 : le jeton de clés créé par l'import est « manuel » (pas de PIN d'activation automatique)
        printf '%s\tImportedCryptoToken-%s\t0\n' "\$((7000 + \$(wc -l < "$T/tokens.tsv")))" "\$((100 + \$(wc -l < "$T/tokens.tsv")))" >> "$T/tokens.tsv" ;;
      "cryptotoken setpin")
        tk=""; oldp=""; upd=0
        for ((j=2; j<\${#s[@]}; j++)); do case "\${s[\$j]}" in --token) tk="\${s[\$((j+1))]}";; --oldpin) oldp="\${s[\$((j+1))]}";; --update) upd=1;; esac; done
        [ -f "$T/fail.setpin" ] && { echo "échec de setpin, PIN \$oldp" >&2; exit 1; }
        [ "\$oldp" = "\$(cat "$T/onetime.pw" 2>/dev/null)" ] || { echo "mauvais PIN" >&2; exit 1; }
        # sans --update : l'activation automatique est posée ; avec --update : seulement si le jeton l'avait déjà (cas réel observé)
        [ "\$upd" = 0 ] && awk -F'\t' -v OFS='\t' -v t="\$tk" '\$2==t{\$3=1} {print}' "$T/tokens.tsv" > "$T/tokens.n" && mv "$T/tokens.n" "$T/tokens.tsv" ;;
      "ca createcrl") [ -f "$T/fail.crl" ] && exit 1 ;;
    esac ;;
esac
exit 0
EOF
cat > "$B/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >> "$LOG"
case "\$1" in
  is-active) [ -f "$T/active" ] ;;
  show) date -u -d "-20 seconds" '+%a %Y-%m-%d %H:%M:%S UTC' ;;
  start|restart) touch "$T/active" ;;
  stop) rm -f "$T/active" ;;
esac
EOF
cat > "$B/psql" <<EOF
#!/bin/bash
sql="\$(cat)"
{ echo "psql \$* [PKI_DB_PW=\${PKI_DB_PW:+défini}]"; printf '%s\n' "\$sql"; } >> "$PLOG"
[ -f "$T/psql.fail" ] && exit 1
n=""; ids=""; t=""; while [ "\$#" -gt 0 ]; do case "\$1" in -v) shift; case "\$1" in n=*) n="\${1#n=}";; ids=*) ids="\${1#ids=}";; t=*) t="\${1#t=}";; esac;; esac; shift; done
case "\$sql" in
  *"pg_database where datname = 'ejbca'"*) [ -f "$T/db.exists" ] && echo exists ;;
  *information_schema.tables*) cat "$T/tables" 2>/dev/null || echo 0 ;;
  *"select id from cryptotokendata"*) cut -f1 "$T/tokens.tsv" 2>/dev/null ;;
  *"tokenname like 'ImportedCryptoToken%'"*) awk -F'\t' -v ids="\$ids" 'BEGIN{n=split(ids,a,","); for(i=1;i<=n;i++) k[a[i]]=1} !(\$1 in k){print \$2}' "$T/tokens.tsv" 2>/dev/null ;;
  *"from cryptotokendata where tokenname = "*) awk -F'\t' -v t="\$t" '\$2==t && \$3==1{f=1} END{if(f) print 1}' "$T/tokens.tsv" 2>/dev/null ;;
  *"select name, subjectdn from cadata"*) awk -F'\t' '{print \$1 "\t" \$3}' "$CADB" ;;
  *"from cadata where name <> 'ManagementCA'"*) awk -F'\t' '\$1!="ManagementCA" && \$2!=6' "$CADB" | wc -l ;;
  *"select 1 from cadata where name"*) awk -F'\t' -v n="\$n" '\$1==n{f=1} END{if(f) print 1}' "$CADB" ;;
  *"select status from cadata"*) awk -F'\t' -v n="\$n" '\$1==n{print \$2}' "$CADB" ;;
  *"select subjectdn from cadata"*) awk -F'\t' -v n="\$n" '\$1==n{print \$3}' "$CADB" ;;
  *"select caid from cadata"*) awk -F'\t' -v n="\$n" '\$1==n{print \$4}' "$CADB" ;;
  *"left join certificatedata"*) cat "$T/cas.tsv" 2>/dev/null ;;
  *"from crldata"*) cat "$T/crls.tsv" 2>/dev/null ;;
  *"coalesce(b.base64cert, d.base64cert)"*) cat "$T/rootcert.b64" 2>/dev/null ;;
  *"drop database"*) rm -f "$T/db.exists" ;;
esac
exit 0
EOF
cat > "$B/curl" <<EOF
#!/bin/bash
if [ -f "$T/healthy" ]; then printf 'ALLOK'; exit 0; fi
exit 22
EOF
printf '#!/bin/bash\necho "fw $*" >> "%s"\n' "$LOG" > "$B/fw"
chmod +x "$B"/*
# demande de certificat au format DER, telle que la CLI d'EJBCA l'écrit
openssl req -in "$W/iss.csr" -outform DER -out "$W/iss.csr.der"
PKI_UID="$(id -u)"
export DDI_PKI_ALLOW_USER=1 DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_GENERATED_DIR="$T/gen" DDI_RUN_DIR="$T/run"
export DDI_PKI_ETC="$T/etc" DDI_PKI_DATA="$T/data" DDI_PKI_QUADLET_DIR="$T/quad" DDI_PKI_PODMAN="$B/podman"
export DDI_PKI_SYSTEMCTL="$B/systemctl" DDI_PKI_CURL="$B/curl" DDI_FW_BIN="$B/fw" DDI_PKI_PSQL="$B/psql" DDI_PKI_LOCK="$T/lock" DDI_PKI_UID="$PKI_UID"
IMG=docker.io/keyfactor/ejbca-ce:9.6.3; HOST=pki.lab.test
G="$T/gen"; R="$T/run"
req() { printf '%s' "$1" > "$G/.pki-request"; "$PKI" request >"$T/req.out" 2>&1; RES_OK="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$R/pki-result.json")"; RES_MSG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["message"])' "$R/pki-result.json")"; }
st() { python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1])).get(sys.argv[2])).lower())' "$R/pki-status.json" "$1"; }
cas_n() { grep -c "podman exec" "$LOG" 2>/dev/null || true; }

echo "== Garde : base existante sans ses secrets =="
touch "$T/db.exists"; echo 7 > "$T/tables"
"$PKI" apply "$IMG" "$HOST" "10.0.0.0/8" > "$T/apply1.out" 2>&1; rc=$?
expect_eq "installation refusée : une base avec des données existe et le fichier de secrets est absent" 1 "$rc"
check "motif lisible : secrets" grep -qi "secrets" "$T/apply1.out"
check "aucun fichier de secrets créé" test ! -e "$T/etc/ejbca.env"
check "aucune instance enregistrée" test ! -e "$T/etc/instance.json"
check "aucune unité Quadlet écrite" test ! -e "$T/quad/ddibuntu-ejbca.container"
touch "$T/psql.fail"; "$PKI" apply "$IMG" "$HOST" "10.0.0.0/8" > "$T/apply2.out" 2>&1; rc=$?
expect_eq "installation refusée : PostgreSQL injoignable et secrets absents (impossible de savoir)" 1 "$rc"
check "toujours aucun fichier de secrets" test ! -e "$T/etc/ejbca.env"
rm -f "$T/psql.fail"; echo 0 > "$T/tables"
"$PKI" apply "$IMG" "$HOST" "10.0.0.0/8" > "$T/apply3.out" 2>&1; rc=$?
expect_eq "installation acceptée sur une base vide" 0 "$rc"
check "secrets créés (0600)" test "$(stat -c %a "$T/etc/ejbca.env")" = 600
OLDSUM="$(sha256sum "$T/etc/ejbca.env" | cut -c1-16)"
echo 9 > "$T/tables"; "$PKI" apply "$IMG" "$HOST" "10.0.0.0/8" > "$T/apply4.out" 2>&1
expect_eq "réinstallation : secrets inchangés" "$OLDSUM" "$(sha256sum "$T/etc/ejbca.env" | cut -c1-16)"

echo "== État publié : données, autorités, remise à zéro permise =="
"$PKI" status >/dev/null 2>&1
expect_eq "données présentes" true "$(st dataPresent)"
expect_eq "nom public des données" "$HOST" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("dataHostname"))' "$R/pki-status.json")"
expect_eq "aucune autorité" 0 "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("casCount"))' "$R/pki-status.json")"
expect_eq "remise à zéro permise sans autorité" true "$(st resetAllowed)"
expect_eq "secrets présents" true "$(st secretsPresent)"

echo "== Demandes d'autorité : refusées si la PKI ne répond pas =="
: > "$LOG"
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}'
expect_eq "racine refusée tant que la PKI n'est pas en service" false "$RES_OK"
check "motif lisible (santé)" grep -qi "ne répond pas" <<< "$RES_MSG"
expect_eq "aucune commande envoyée à EJBCA" 0 "$(cas_n)"
touch "$T/healthy" "$T/active"

echo "== Racine auto-signée =="
: > "$LOG"
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}'
expect_eq "racine acceptée" true "$RES_OK"
expect_grep "init : arguments exacts (RSA 3072, SHA256WithRSA, 3650 jours, clé logicielle)" 'ca init --caname Lab-Root --dn CN=Lab Root CA,O=Laboratoire,C=FR --tokenType soft --tokenPass null --keyspec 3072 -v 3650 --policy null -s SHA256WithRSA$' "$LOG"
expect_grep "réglages : adresse de CRL publiée" "ca editca --caname Lab-Root --field defaultCRLDistPoint --value http://$HOST:8080/ejbca/publicweb/webdist/certdist\?cmd=crl&issuer=CN%3DLab%20Root%20CA%2CO%3DLaboratoire%2CC%3DFR\$" "$LOG"
expect_grep "réglages : adresse du certificat d'autorité" "ca editca --caname Lab-Root --field certificateAiaDefaultCaIssuerUri --value http://$HOST:8080/ejbca/publicweb/webdist/certdist\?cmd=cacert&issuer=" "$LOG"
expect_grep "réglages : période de CRL de 7 jours" 'ca editca --caname Lab-Root --field CRLPeriod --value 604800000$' "$LOG"
expect_grep "réglages : recouvrement de CRL d'un jour" 'ca editca --caname Lab-Root --field CRLOverlapTime --value 86400000$' "$LOG"
check "mémoire de l'autorité : sorte racine" grep -q '"kind": "root"' "$T/data/ca/Lab-Root/meta.json"
check "le dossier de travail partagé avec le conteneur est vidé" test -z "$(ls -A "$WORKH" 2>/dev/null)"
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Autre"}'
expect_eq "même nom refusé" false "$RES_OK"
: > "$LOG"; req '{"action":"ca_root","name":"Boum","alg":"rsa3072","days":3650,"cn":"X,O=pirate"}'
expect_eq "DN piégé refusé" false "$RES_OK"; expect_eq "DN piégé : aucune commande envoyée" 0 "$(cas_n)"
touch "$T/fail.init"; req '{"action":"ca_root","name":"Echec","alg":"ecp256","days":3650,"cn":"X"}'; rm -f "$T/fail.init"
expect_eq "échec de la CLI : demande en échec" false "$RES_OK"
check "échec de la CLI : motif lisible" grep -qi "échec de « ca init »" <<< "$RES_MSG"
check "échec de la CLI : dossier de travail vidé" test -z "$(ls -A "$WORKH" 2>/dev/null)"

echo "== Émettrice signée par la racine du DDI =="
: > "$LOG"
req '{"action":"ca_issuing","name":"Lab-Sub","alg":"ecp256","days":1825,"cn":"Lab Sub CA","signedBy":"Lab-Root"}'
expect_eq "émettrice interne acceptée" true "$RES_OK"
expect_grep "init : signée par l'identifiant de la racine (2000)" 'ca init --caname Lab-Sub --dn CN=Lab Sub CA --tokenType soft --tokenPass null --keyspec prime256v1 -v 1825 --policy null -s SHA256withECDSA --signedby 2000$' "$LOG"
check "mémoire : signée par Lab-Root" grep -q '"signedBy": "Lab-Root"' "$T/data/ca/Lab-Sub/meta.json"
req '{"action":"ca_issuing","name":"X1","alg":"ecp256","days":1825,"cn":"X","signedBy":"Inconnue"}'
expect_eq "signeur inexistant refusé" false "$RES_OK"
req '{"action":"ca_issuing","name":"X2","alg":"ecp256","days":1825,"cn":"X","signedBy":"Lab-Sub"}'
expect_eq "une émettrice ne signe pas (seule une racine créée par le DDI le peut)" false "$RES_OK"

echo "== Émettrice sous une racine hors ligne =="
: > "$LOG"
req '{"action":"ca_issuing","name":"Lab-Ext","alg":"rsa3072","days":1825,"cn":"Emettrice","o":"Laboratoire","c":"FR","signedBy":"external"}'
expect_eq "sans chaîne déposée : refusée" false "$RES_OK"; expect_eq "sans chaîne : aucune commande" 0 "$(cas_n)"
cp "$W/garbage" "$G/pki-in/Lab-Ext.chain.pem"; req '{"action":"ca_issuing","name":"Lab-Ext","alg":"rsa3072","days":1825,"cn":"Emettrice","signedBy":"external"}'
expect_eq "chaîne illisible refusée" false "$RES_OK"; expect_eq "chaîne illisible : aucune commande" 0 "$(cas_n)"
check "chaîne illisible : dépôt consommé" test ! -e "$G/pki-in/Lab-Ext.chain.pem"
check "chaîne illisible : pas de dossier laissé" test ! -e "$T/data/ca/Lab-Ext"
cp "$W/iss.pem" "$G/pki-in/Lab-Ext.chain.pem"; req '{"action":"ca_issuing","name":"Lab-Ext","alg":"rsa3072","days":1825,"cn":"Emettrice","signedBy":"external"}'
expect_eq "chaîne sans racine auto-signée refusée" false "$RES_OK"
cp "$W/root.pem" "$G/pki-in/Lab-Ext.chain.pem"; : > "$LOG"
req '{"action":"ca_issuing","name":"Lab-Ext","alg":"rsa3072","days":1825,"cn":"Emettrice","o":"Laboratoire","c":"FR","signedBy":"external"}'
expect_eq "racine hors ligne + demande : acceptée" true "$RES_OK"
expect_grep "racine hors ligne importée comme autorité externe (ExtRoot-<empreinte>)" "ca importcacert --caname ExtRoot-$sha -f /mnt/persistent/work/root.pem\$" "$LOG"
expect_grep "init externe : chaîne fournie à la CLI" 'ca init --caname Lab-Ext --dn CN=Emettrice,O=Laboratoire,C=FR --tokenType soft --tokenPass null --keyspec 3072 -v 1825 --policy null -s SHA256WithRSA --signedby External -externalcachain /mnt/persistent/work/chain.pem$' "$LOG"
check "demande de certificat conservée (PEM valide)" openssl req -in "$T/data/ca/Lab-Ext/csr.pem" -noout -verify
expect_eq "mémoire : racine hors ligne associée à l'émettrice" "ExtRoot-$sha" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("extRoot"))' "$T/data/ca/Lab-Ext/meta.json")"
check "dépôt de la console consommé" test ! -e "$G/pki-in/Lab-Ext.chain.pem"
expect_eq "racine externe enregistrée une seule fois" 1 "$(grep -c "^ExtRoot-$sha	" "$CADB")"
cp "$W/root.pem" "$G/pki-in/Lab-Ext2.chain.pem"; : > "$LOG"
req '{"action":"ca_issuing","name":"Lab-Ext2","alg":"ecp256","days":1825,"cn":"Autre emettrice","signedBy":"external"}'
expect_eq "deuxième émettrice sous la même racine : acceptée" true "$RES_OK"
expect_nogrep "la racine hors ligne n'est pas réimportée" "importcacert --caname ExtRoot" "$LOG"

echo "== Import du certificat signé =="
: > "$LOG"
cp "$W/iss.pem" "$G/pki-in/Lab-Ext.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "certificat d'une autre clé... (ici : celui de la demande) accepté" true "$RES_OK"
expect_grep "import : certificat transmis à la CLI" 'ca importcacert --caname Lab-Ext -f /mnt/persistent/work/issued.pem$' "$LOG"
expect_grep "import : première CRL créée" 'ca createcrl --caname Lab-Ext$' "$LOG"
check "dépôt consommé" test ! -e "$G/pki-in/Lab-Ext.cert.pem"
req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "second import refusé : l'autorité n'attend plus de certificat" false "$RES_OK"
cp "$W/iss-otherkey.pem" "$G/pki-in/Lab-Ext2.cert.pem"; : > "$LOG"; req '{"action":"ca_import","name":"Lab-Ext2"}'
expect_eq "certificat d'une autre clé refusé" false "$RES_OK"; expect_eq "refus : aucune commande envoyée" 0 "$(cas_n)"
cp "$W/leaf.pem" "$G/pki-in/Lab-Ext2.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext2"}'
expect_eq "certificat sans CA:TRUE refusé" false "$RES_OK"
ln -sf /etc/passwd "$G/pki-in/Lab-Ext2.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext2"}'
expect_eq "dépôt par lien symbolique refusé" false "$RES_OK"
check "lien symbolique retiré, cible intacte" test ! -e "$G/pki-in/Lab-Ext2.cert.pem" -a -s /etc/passwd
req '{"action":"ca_import","name":"Lab-Root"}'
expect_eq "import refusé pour une autorité active" false "$RES_OK"

echo "== CRL des autorités =="
: > "$LOG"; req '{"action":"ca_crl","name":"Lab-Sub"}'
expect_eq "CRL renouvelée" true "$RES_OK"; expect_grep "createcrl envoyé" 'ca createcrl --caname Lab-Sub$' "$LOG"
req '{"action":"ca_crl","name":"Lab-Wait"}'; expect_eq "CRL d'une autorité inconnue refusée" false "$RES_OK"
req '{"action":"ca_crl","name":"Lab-Ext2"}'; expect_eq "CRL d'une autorité en attente refusée" false "$RES_OK"
touch "$T/fail.crl"; req '{"action":"ca_crl","name":"Lab-Sub"}'; rm -f "$T/fail.crl"; expect_eq "échec de la CLI rapporté" false "$RES_OK"

echo "== CRL de la racine hors ligne =="
EXTN="ExtRoot-$sha"; openssl x509 -in "$W/root.pem" -outform DER | base64 -w0 > "$T/rootcert.b64"
: > "$LOG"; cp "$W/root.crl.pem" "$G/pki-in/$EXTN.crl"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXTN\"}"
expect_eq "CRL de la racine importée" true "$RES_OK"
expect_grep "importcrl : mode adaptatif" "ca importcrl --caname $EXTN -f /mnt/persistent/work/root.crl -o ADAPTIVE\$" "$LOG"
cp "$W/other.crl.pem" "$G/pki-in/$EXTN.crl"; : > "$LOG"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXTN\"}"
expect_eq "CRL signée par une autre autorité refusée" false "$RES_OK"; expect_eq "refus : aucune commande envoyée" 0 "$(cas_n)"
cp "$W/garbage" "$G/pki-in/$EXTN.crl"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXTN\"}"; expect_eq "CRL illisible refusée" false "$RES_OK"
req '{"action":"ca_rootcrl","name":"ExtRoot-ffffffff"}'; expect_eq "racine externe inconnue refusée" false "$RES_OK"
echo 'MIIB' > "$T/rootcert.b64"; cp "$W/root.crl.pem" "$G/pki-in/$EXTN.crl"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXTN\"}"
expect_eq "certificat de racine illisible en base : refusé" false "$RES_OK"

echo "== Minuteur : état publié et renouvellement des CRL =="
cp "$W/cas.tsv" "$T/cas.tsv"; cp "$W/crls.tsv" "$T/crls.tsv"
: > "$LOG"; DDI_PKI_CRL_RENEW_AFTER=43200 "$PKI" maintain >/dev/null 2>&1
expect_eq "autorités publiées depuis la base" true "$(test -s "$R/pki-cas.json" && echo true || echo false)"
expect_grep "CRL vieille de 2 jours : renouvelée" 'ca createcrl --caname Lab-Root$' "$LOG"
expect_nogrep "CRL toute fraîche : non renouvelée" 'ca createcrl --caname Lab-Sub$' "$LOG"
expect_nogrep "autorité en attente : jamais renouvelée" 'ca createcrl --caname Lab-Wait$' "$LOG"
expect_nogrep "racine externe : jamais renouvelée" 'ca createcrl --caname ExtRoot' "$LOG"
: > "$LOG"; DDI_PKI_CRL_RENEW_AFTER=0 "$PKI" maintain >/dev/null 2>&1
expect_grep "seuil à 0 : l'émettrice est renouvelée aussi" 'ca createcrl --caname Lab-Sub$' "$LOG"
: > "$LOG"; DDI_PKI_CRL_RENEW_AFTER=99999999 "$PKI" maintain >/dev/null 2>&1
expect_eq "seuil très haut : aucune CRL renouvelée" 0 "$(grep -c 'createcrl' "$LOG")"
rm -f "$T/healthy"; : > "$LOG"; DDI_PKI_CRL_RENEW_AFTER=0 "$PKI" maintain >/dev/null 2>&1
expect_eq "PKI qui ne répond pas : aucune commande envoyée" 0 "$(cas_n)"
touch "$T/healthy"

echo "== Reprise d'une autorité depuis un PKCS#12 (0.14.4) =="
openssl req -x509 -new -key "$W/iss3.key" -days 3650 -subj "/C=FR/O=Import/CN=Import Root 2" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$W/imp-root2.pem" 2>/dev/null
mkp12 "$W/imp-root2.p12" "$W/iss3.key" "$W/imp-root2.pem"
dep() { rm -f "$G/pki-in/$2.p12" "$G/pki-in/$2.p12pw"; cp "$1" "$G/pki-in/$2.p12"; printf '%s' "${3-$P12PW}" > "$G/pki-in/$2.p12pw"; chmod 600 "$G/pki-in/$2.p12" "$G/pki-in/$2.p12pw"; }
nodep() { check "$1 : dépôts consommés (fichier et mot de passe)" test ! -e "$G/pki-in/$2.p12" -a ! -e "$G/pki-in/$2.p12pw"; }
clean() { check "$1 : dossier de travail partagé vidé" test -z "$(ls -A "$WORKH" 2>/dev/null)"; check "$1 : aucun dossier d'autorité laissé" test ! -e "$T/data/ca/$2"; }
nosecret() { check "$1 : le mot de passe du fichier n'apparaît ni dans la réponse, ni dans le résultat, ni dans les appels" bash -c "! grep -qF -- 'Tést P12 pass' '$T/req.out' '$R/pki-result.json' '$LOG' 2>/dev/null"; }
echo "-- refus --"
: > "$LOG"; dep "$W/impiss.p12" Imp-Bad 'mauvais mot de passe'; req '{"action":"ca_import_p12","name":"Imp-Bad"}'
expect_eq "mauvais mot de passe : refusé" false "$RES_OK"; check "mauvais mot de passe : motif lisible" grep -qi "mot de passe" <<< "$RES_MSG"
expect_eq "mauvais mot de passe : aucune commande envoyée à EJBCA" 0 "$(cas_n)"; nodep "mauvais mot de passe" Imp-Bad; clean "mauvais mot de passe" Imp-Bad
check "mauvais mot de passe : le mot de passe essayé n'est pas répété dans le résultat" bash -c "! grep -qF 'mauvais mot de passe' '$R/pki-result.json'"
dep "$W/garbage" Imp-Bad; req '{"action":"ca_import_p12","name":"Imp-Bad"}'
expect_eq "fichier qui n'est pas un PKCS#12 : refusé" false "$RES_OK"; nodep "fichier illisible" Imp-Bad; clean "fichier illisible" Imp-Bad
rm -f "$G/pki-in/Imp-Bad".*; req '{"action":"ca_import_p12","name":"Imp-Bad"}'
expect_eq "aucun dépôt : refusé" false "$RES_OK"; clean "aucun dépôt" Imp-Bad
dep "$W/dup.p12" Imp-Dup; : > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-Dup"}'
expect_eq "nom distinctif déjà porté par une autorité : refusé" false "$RES_OK"; check "doublon : l'autorité en place est nommée" grep -q "Lab-Ext" <<< "$RES_MSG"
expect_eq "doublon : aucune commande envoyée à EJBCA" 0 "$(cas_n)"; nodep "doublon" Imp-Dup; clean "doublon" Imp-Dup
dep "$W/imp-root.p12" Lab-Root; : > "$LOG"; req '{"action":"ca_import_p12","name":"Lab-Root"}'
expect_eq "nom d'autorité déjà utilisé : refusé" false "$RES_OK"; expect_eq "nom déjà utilisé : aucune commande envoyée" 0 "$(cas_n)"; nodep "nom déjà utilisé" Lab-Root
check "nom déjà utilisé : l'autorité existante est intacte" grep -q '"kind": "root"' "$T/data/ca/Lab-Root/meta.json"
req '{"action":"ca_import_p12","name":"ExtRoot-0a1b2c3d"}'; expect_eq "nom réservé aux racines hors ligne : refusé" false "$RES_OK"
dep "$W/leaf.p12" Imp-Leaf; req '{"action":"ca_import_p12","name":"Imp-Leaf"}'
expect_eq "certificat sans CA:TRUE : refusé" false "$RES_OK"; nodep "sans CA:TRUE" Imp-Leaf; clean "sans CA:TRUE" Imp-Leaf
dep "$W/nochain.p12" Imp-Nochain; req '{"action":"ca_import_p12","name":"Imp-Nochain"}'
expect_eq "chaîne incomplète : refusé" false "$RES_OK"; nodep "chaîne incomplète" Imp-Nochain; clean "chaîne incomplète" Imp-Nochain
echo "-- émettrice sous une racine nouvelle --"
dep "$W/impiss.p12" Imp-Iss; : > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-Iss"}'
expect_eq "émettrice : importée" true "$RES_OK"
check "émettrice : message de réussite (sorte et validité)" grep -q "reprise du fichier PKCS#12 (émettrice, valable jusqu" <<< "$RES_MSG"
check "émettrice : le message rappelle que la clé est dans la base du DDI" grep -q "base du DDI" <<< "$RES_MSG"
expect_grep "émettrice : sa racine est d'abord importée comme autorité externe sans clé" "ca importcacert --caname ExtRoot-$IMPSHA -f /mnt/persistent/work/root.pem\$" "$LOG"
expect_grep "émettrice : ca importca avec le fichier rhabillé et un mot de passe à usage unique de 32 caractères" 'ca importca --caname Imp-Iss --p12 /mnt/persistent/work/ca.p12 -kspassword [A-Za-z0-9]{32}$' "$LOG"
check "émettrice : la racine est importée AVANT l'autorité" bash -c "[ \$(grep -n 'importcacert --caname ExtRoot-$IMPSHA' '$LOG' | head -1 | cut -d: -f1) -lt \$(grep -n 'ca importca ' '$LOG' | head -1 | cut -d: -f1) ]"
expect_grep "émettrice : adresse de CRL publiée" 'ca editca --caname Imp-Iss --field defaultCRLDistPoint ' "$LOG"
expect_grep "émettrice : première CRL créée" 'ca createcrl --caname Imp-Iss$' "$LOG"
M="$T/data/ca/Imp-Iss/meta.json"; mj() { python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1])).get(sys.argv[2])).lower())' "$M" "$1"; }
expect_eq "mémoire : sorte issuing" issuing "$(mj kind)"; expect_eq "mémoire : signée par une racine externe" external "$(mj signedBy)"
expect_eq "mémoire : racine hors ligne associée" "extroot-$IMPSHA" "$(mj extRoot)"; expect_eq "mémoire : drapeau importée" true "$(mj imported)"; expect_eq "mémoire : algorithme" ecp256 "$(mj alg)"
check "mémoire : l'autorité du DDI n'a pas le drapeau importée" bash -c "! grep -q imported '$T/data/ca/Lab-Sub/meta.json'"
expect_eq "mémoire de la racine importée : sorte extroot" extroot "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("kind"))' "$T/data/ca/ExtRoot-$IMPSHA/meta.json")"
check "chaîne publique de l'autorité conservée (la racine, sans clé)" bash -c "grep -c 'BEGIN CERTIFICATE' '$T/data/ca/Imp-Iss/chain.pem' | grep -qx 1"
check "la chaîne se vérifie : racine du fichier" openssl x509 -in "$T/data/ca/Imp-Iss/chain.pem" -noout -subject
nodep "import réussi" Imp-Iss; clean "import réussi" ExtRoot-none; check "import réussi : dossier de l'autorité présent" test -d "$T/data/ca/Imp-Iss"
nosecret "import réussi"
OT="$(cat "$T/onetime.pw")"
check "mot de passe à usage unique : jamais celui du fichier" test "$OT" != "$P12PW"
check "mot de passe à usage unique : absent du résultat et de la sortie de la demande" bash -c "! grep -qF -- '$OT' '$R/pki-result.json' '$T/req.out'"
check "aucune clé privée dans la mémoire des autorités ni dans les dépôts publics" bash -c "! grep -rl 'PRIVATE KEY' '$T/data' '$G/pki-in' '$R' 2>/dev/null"
TK1="$(awk -F'\t' 'NR==1{print $2}' "$T/tokens.tsv")"
expect_grep "jeton de clés : PIN d'activation automatique posé (setpin SANS --update, avec le mot de passe à usage unique)" "cryptotoken setpin --token $TK1 --oldpin [A-Za-z0-9]{32} --newpin [A-Za-z0-9]{32}\$" "$LOG"
expect_nogrep "jeton de clés : jamais --update (il n'active pas un jeton resté manuel)" "setpin .*--update" "$LOG"
check "jeton de clés : PIN ancien et nouveau identiques au mot de passe à usage unique" bash -c "grep -E 'cryptotoken setpin' '$LOG' | head -1 | grep -qF -- '--oldpin $OT --newpin $OT'"
expect_eq "jeton de clés : devenu automatique" 1 "$(awk -F'\t' 'NR==1{print $3}' "$T/tokens.tsv")"
check "jeton de clés : setpin passe après l'import et avant la première CRL" bash -c "[ \$(grep -n 'ca importca ' '$LOG' | head -1 | cut -d: -f1) -lt \$(grep -n 'cryptotoken setpin' '$LOG' | head -1 | cut -d: -f1) ] && [ \$(grep -n 'cryptotoken setpin' '$LOG' | head -1 | cut -d: -f1) -lt \$(grep -n 'ca createcrl --caname Imp-Iss' '$LOG' | head -1 | cut -d: -f1) ]"
check "jeton de clés : le PIN n'apparaît ni dans le résultat ni dans la sortie de la demande" bash -c "! grep -qF -- '$OT' '$R/pki-result.json' '$T/req.out'"
check "jeton de clés : message de réussite sans avertissement" bash -c '! grep -q AVERTISSEMENT <<< "$0"' "$RES_MSG"
echo "-- échec de la CLI d'EJBCA --"
dep "$W/impiss2.p12" Imp-Iss2; : > "$LOG"; touch "$T/fail.importca"; req '{"action":"ca_import_p12","name":"Imp-Iss2"}'; rm -f "$T/fail.importca"
expect_eq "échec de ca importca : demande en échec" false "$RES_OK"
check "échec : le mot de passe à usage unique est masqué dans le message" bash -c "! grep -qF -- '$(cat "$T/onetime.pw")' '$R/pki-result.json' '$T/req.out'; ! grep -q 'mot de passe [A-Za-z0-9]\{32\}' '$R/pki-result.json'"
nodep "échec CLI" Imp-Iss2; clean "échec CLI" Imp-Iss2; nosecret "échec CLI"
expect_nogrep "échec : la racine déjà importée n'est pas réimportée" "importcacert --caname ExtRoot" "$LOG"
echo "-- échec de l'activation automatique du jeton --"
dep "$W/impiss3.p12" Imp-Sub0; : > "$LOG"; touch "$T/fail.setpin"; req '{"action":"ca_import_p12","name":"Imp-Sub0"}'; rm -f "$T/fail.setpin"
expect_eq "setpin en échec : l'autorité reste importée (elle fonctionne jusqu'au redémarrage)" true "$RES_OK"
check "setpin en échec : AVERTISSEMENT explicite" grep -q "AVERTISSEMENT" <<< "$RES_MSG"
check "setpin en échec : l'avertissement dit que l'autorité sera hors ligne au prochain redémarrage" grep -qi "hors ligne au prochain redémarrage" <<< "$RES_MSG"
check "setpin en échec : le PIN est masqué dans le message" bash -c '! grep -qF -- "$0" <<< "$1"' "$(cat "$T/onetime.pw")" "$RES_MSG"
expect_grep "setpin en échec : deux essais" "cryptotoken setpin --token" "$LOG"
expect_eq "setpin en échec : deux tentatives exactement" 2 "$(grep -c 'cryptotoken setpin' "$LOG")"
check "setpin en échec : le PIN n'est écrit nulle part (journal de la PKI, résultat)" bash -c "! grep -qF -- '$(cat "$T/onetime.pw")' '$R/pki-result.json' '$T/req.out' 2>/dev/null"
expect_eq "setpin en échec : le jeton reste manuel" 0 "$(awk -F'\t' 'END{print $3}' "$T/tokens.tsv")"
check "setpin en échec : mémoire écrite (l'autorité est gérée)" test -s "$T/data/ca/Imp-Sub0/meta.json"
nodep "setpin en échec" Imp-Sub0
echo "-- émettrice sous une racine déjà connue --"
dep "$W/impiss2.p12" Imp-Iss2; : > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-Iss2"}'
expect_eq "deuxième émettrice sous la même racine : importée" true "$RES_OK"
expect_nogrep "racine déjà connue : non réimportée" "importcacert" "$LOG"
M="$T/data/ca/Imp-Iss2/meta.json"; expect_eq "mémoire : même racine hors ligne réutilisée" "extroot-$IMPSHA" "$(mj extRoot)"
dep "$W/iss3.p12" Imp-Sub; : > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-Sub"}'
expect_eq "émettrice sous la racine du DDI (même nom distinctif que Lab-Root) : importée" true "$RES_OK"
expect_nogrep "racine du DDI : rien à importer" "importcacert" "$LOG"
M="$T/data/ca/Imp-Sub/meta.json"; expect_eq "mémoire : signée par la racine du DDI" lab-root "$(mj signedBy)"; expect_eq "mémoire : drapeau importée" true "$(mj imported)"
echo "-- racine seule --"
dep "$W/imp-root.p12" Imp-RootDup; : > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-RootDup"}'
expect_eq "racine déjà connue comme racine hors ligne : refusée (pas de promotion)" false "$RES_OK"; check "refus : l'autorité qui porte ce nom est nommée" grep -q "ExtRoot-$IMPSHA" <<< "$RES_MSG"
nodep "racine déjà connue" Imp-RootDup; clean "racine déjà connue" Imp-RootDup
dep "$W/imp-root2.p12" Imp-Root; : > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-Root"}'
expect_eq "racine : importée" true "$RES_OK"; check "racine : message" grep -q "reprise du fichier PKCS#12 (racine" <<< "$RES_MSG"
expect_nogrep "racine : aucune autre racine importée" "importcacert" "$LOG"
expect_grep "racine : ca importca" 'ca importca --caname Imp-Root --p12 /mnt/persistent/work/ca.p12 -kspassword [A-Za-z0-9]{32}$' "$LOG"
M="$T/data/ca/Imp-Root/meta.json"; expect_eq "mémoire : sorte root" root "$(mj kind)"; expect_eq "mémoire : auto-signée" self "$(mj signedBy)"; expect_eq "mémoire : drapeau importée" true "$(mj imported)"
check "racine : pas de chaîne publique à conserver" test ! -s "$T/data/ca/Imp-Root/chain.pem"
nodep "racine" Imp-Root; nosecret "racine"
echo "-- émission depuis une autorité reprise --"
: > "$LOG"; req '{"action":"ca_import_p12","name":"Imp-Root"}'
expect_eq "second import du même nom : refusé" false "$RES_OK"
check "aucune clé privée nulle part dans la mémoire des autorités" bash -c "! grep -rl 'PRIVATE KEY' '$T/data' 2>/dev/null"
check "purge : un dépôt orphelin de plus de 10 minutes est supprimé" bash -c "cp '$W/impiss.p12' '$G/pki-in/Orphelin.p12'; printf x > '$G/pki-in/Orphelin.p12pw'; touch -d '-30 minutes' '$G/pki-in/Orphelin.p12' '$G/pki-in/Orphelin.p12pw'; DDI_PKI_CRL_RENEW_AFTER=99999999 '$PKI' maintain >/dev/null 2>&1; test ! -e '$G/pki-in/Orphelin.p12' -a ! -e '$G/pki-in/Orphelin.p12pw'"
check "purge : un dépôt récent est conservé" bash -c "cp '$W/impiss.p12' '$G/pki-in/Recent.p12'; DDI_PKI_CRL_RENEW_AFTER=99999999 '$PKI' maintain >/dev/null 2>&1; test -e '$G/pki-in/Recent.p12'; rm -f '$G/pki-in/Recent.p12'"

echo "== Remise à zéro =="
"$PKI" status >/dev/null 2>&1
expect_eq "état : autorités avec clé comptées (racine, interne, 2 externes + 5 reprises d'un PKCS#12)" 9 "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("casCount"))' "$R/pki-status.json")"
expect_eq "état : remise à zéro interdite" false "$(st resetAllowed)"
: > "$PLOG"; req '{"action":"reset"}'
expect_eq "remise à zéro refusée tant qu'il existe des autorités" false "$RES_OK"
check "motif lisible (autorités)" grep -qi "autorité" <<< "$RES_MSG"
check "la base n'a pas été supprimée" bash -c "! grep -q 'drop database' '$PLOG'"
check "les secrets sont conservés" test -s "$T/etc/ejbca.env"
touch "$T/psql.fail"; req '{"action":"reset"}'; rm -f "$T/psql.fail"
expect_eq "PostgreSQL injoignable : remise à zéro refusée" false "$RES_OK"
check "les secrets sont conservés (PostgreSQL injoignable)" test -s "$T/etc/ejbca.env"
: > "$CADB"
req '{"action":"reset"}'
expect_eq "sans autorité : remise à zéro acceptée" true "$RES_OK"
check "base supprimée" grep -q 'drop database if exists ejbca' "$PLOG"
check "rôle supprimé" grep -q 'drop role if exists ejbca' "$PLOG"
check "secrets effacés" test ! -e "$T/etc/ejbca.env"
"$PKI" status >/dev/null 2>&1
expect_eq "état après remise à zéro : plus de secrets" false "$(st secretsPresent)"
expect_eq "état après remise à zéro : plus de données" false "$(st dataPresent)"
check "instance effacée" test ! -e "$T/etc/instance.json"
check "volume et mémoire des autorités effacés" test ! -e "$T/data"
check "unité Quadlet retirée" test ! -e "$T/quad/ddibuntu-ejbca.container"
check "publication des autorités retirée" test ! -e "$R/pki-cas.json" -a ! -e "$R/pki-ca"
req '{"action":"reset"}'; expect_eq "seconde remise à zéro : rien à effacer" false "$RES_OK"
rm -f "$T/db.exists"; echo 0 > "$T/tables"
"$PKI" apply "$IMG" other.lab.test "10.0.0.0/8" > "$T/apply5.out" 2>&1; expect_eq "nouvelle installation possible avec un autre nom public" 0 "$?"
expect_grep "nom public choisi" '^HTTPSERVER_HOSTNAME=other.lab.test$' "$T/etc/ejbca.env"

finish
