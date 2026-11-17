#!/usr/bin/env bash
# Batterie 33 — autorités de la PKI du DDI (0.14.1) sur le VRAI conteneur EJBCA Community (Podman, unité Quadlet relue par le vrai générateur, vraie
# base PostgreSQL) : installation réelle, racine auto-signée, émettrice signée par une racine du DDI, émettrice sous une racine « hors ligne »
# (demande de certificat → signature openssl avec les adresses CDP / AIA publiées → import), CRL servies en HTTP et vérifiées par openssl, CRL de
# la racine hors ligne, renouvellement des CRL, refus (clé qui ne correspond pas, certificat sans CA:TRUE, dépôt piégé, noms piégés), remise à zéro.
# DESTRUCTIVE : supprime la base « ejbca » et le conteneur « ddibuntu-ejbca » de la machine ; exige DDI_TEST_PKI_LIVE=1.
# Prérequis : root, podman + image docker.io/keyfactor/ejbca-ce:9.6.3 déjà présente (aucun tirage), PostgreSQL local (runuser postgres), openssl,
# curl, port 8080 libre, ~2 Go de mémoire libre ; sinon la batterie est ignorée. Durée : environ 7 minutes (chaque commande de la CLI d'EJBCA
# démarre une JVM).
# DDI_TEST_PODMAN_ARGS permet de viser un autre stockage Podman (ex. « --root /tmp/podman-root --runroot /tmp/podman-run »).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

PKI="$RFS/usr/local/sbin/ddibuntu-pki"
IMG="docker.io/keyfactor/ejbca-ce:9.6.3"
read -r -a PARGS <<< "${DDI_TEST_PODMAN_ARGS:-}"
if [ "${DDI_TEST_PKI_LIVE:-}" != 1 ]; then note "DDI_TEST_PKI_LIVE=1 absent (la batterie supprime la base « ejbca » et le conteneur « ddibuntu-ejbca ») : ignorée"; finish; exit $?; fi
if [ "$(id -u)" -ne 0 ] || ! command -v podman >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null || ! command -v runuser >/dev/null \
   || [ ! -x /usr/lib/systemd/system-generators/podman-system-generator ]; then
  note "prérequis absents (root, podman et son générateur Quadlet, openssl, curl, runuser) : batterie ignorée"; finish; exit $?
fi
if ! podman "${PARGS[@]}" image exists "$IMG" >/dev/null 2>&1; then note "image $IMG absente (la batterie ne tire rien) : ignorée"; finish; exit $?; fi
if curl -s --noproxy '*' -m 2 -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; then note "le port 8080 est déjà utilisé : batterie ignorée"; finish; exit $?; fi
if ! runuser -u postgres -- psql -X -q -At -d postgres -c 'select 1' >/dev/null 2>&1; then note "PostgreSQL local injoignable : batterie ignorée"; finish; exit $?; fi

D="$T_TMP"; chmod 0755 "$D"
mkdir -p "$D/bin" "$D/etc" "$D/data" "$D/quad" "$D/run" "$D/gen/pki-in" "$D/w"
GEN="$D/gen"; RUNP="$D/run"
# podman : même stockage que celui qui contient l'image
cat > "$D/bin/podman" <<EOF
#!/bin/bash
exec /usr/bin/podman ${PARGS[*]} "\$@"
EOF
# systemctl : « start » exécute la commande que le VRAI générateur Quadlet produit pour l'unité (ni systemd ni cgroups ici)
cat > "$D/bin/systemctl" <<EOF
#!/bin/bash
P="$D/bin/podman"
case "\$1" in
  daemon-reload) exit 0 ;;
  start|restart)
    [ "\$1" = restart ] && "\$P" stop -t 60 ddibuntu-ejbca >/dev/null 2>&1
    cmd="\$(QUADLET_UNIT_DIRS="$D/quad" /usr/lib/systemd/system-generators/podman-system-generator --dryrun 2>/dev/null | sed -n 's/^ExecStart=//p' | head -n1)"
    [ -n "\$cmd" ] || exit 1
    cmd="\${cmd/\\/usr\\/bin\\/podman/\$P}"; cmd="\${cmd//%t/$D/run}"; cmd="\${cmd//%N/ddibuntu-ejbca}"; cmd="\${cmd/--cgroups=split/--cgroups=enabled}"
    eval "\$cmd" >"$D/start.out" 2>&1 9>&- || { cat "$D/start.out" >&2; exit 1; } ;;
  stop) "\$P" stop -t 90 ddibuntu-ejbca >/dev/null 2>&1; exit 0 ;;
  is-active) [ "\$("\$P" inspect -f '{{.State.Running}}' ddibuntu-ejbca 2>/dev/null)" = true ] ;;
  show) "\$P" inspect -f '{{.State.StartedAt}}' ddibuntu-ejbca 2>/dev/null | sed 's/ +0000 UTC//' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$D/bin/podman" "$D/bin/systemctl"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_PKI_ETC="$D/etc" DDI_PKI_DATA="$D/data" DDI_PKI_QUADLET_DIR="$D/quad"
export DDI_PKI_PODMAN="$D/bin/podman" DDI_PKI_SYSTEMCTL="$D/bin/systemctl" DDI_PKI_LOCK="$D/lock" DDI_FW_BIN="$D/nofw" DDI_PKI_UID=10001
export DDI_GENERATED_DIR="$GEN" DDI_RUN_DIR="$RUNP"
unset DDI_PKI_PSQL DDI_PKI_ALLOW_USER

psql_pg() { runuser -u postgres -- psql -X -q -At -d postgres "$@"; }
reset_all() {
  "$D/bin/podman" rm -f ddibuntu-ejbca >/dev/null 2>&1
  psql_pg -c 'drop database if exists ejbca with (force)' -c 'drop role if exists ejbca' >/dev/null 2>&1
}
if [ "${DDI_TEST_PKI_KEEP:-}" = 1 ]; then
  # mise au point : on garde la base, le conteneur et les fichiers ; env.sh recrée l'environnement de la batterie pour rejouer des commandes à la main
  { for v in DDI_LIBDIR DDI_PKI_ETC DDI_PKI_DATA DDI_PKI_QUADLET_DIR DDI_PKI_PODMAN DDI_PKI_SYSTEMCTL DDI_PKI_LOCK DDI_FW_BIN DDI_PKI_UID DDI_GENERATED_DIR DDI_RUN_DIR; do printf 'export %s=%q\n' "$v" "${!v}"; done; printf 'export PKI=%q D=%q\n' "$PKI" "$D"; } > /tmp/b33-keep.env
  trap 'note "état conservé : . /tmp/b33-keep.env"' EXIT
else
  trap 'reset_all; rm -rf "$T_TMP"' EXIT
fi
reset_all

jget() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d[int(k)] if isinstance(d, list) else d.get(k) if isinstance(d, dict) else None
    if d is None: break
print("" if d is None else (str(d).lower() if isinstance(d, bool) else d))' "$1" "$2" 2>/dev/null; }
ca_get() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
c = [x for x in d["cas"] if x["name"] == sys.argv[2]]
v = c[0] if c else {}
for k in sys.argv[3].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$RUNP/pki-cas.json" "$1" "$2" 2>/dev/null; }
req() {   # $1 = JSON de la demande ; la demande passe par le vrai « request » (celui que déclenche l'unité .path)
  printf '%s' "$1" > "$GEN/.pki-request"
  "$PKI" request > "$D/req.out" 2>&1 || true
  RES_OK="$(jget "$RUNP/pki-result.json" ok)"; RES_MSG="$(jget "$RUNP/pki-result.json" message)"
}
wait_health() {
  local h
  for _ in $(seq 1 60); do
    h="$(curl -s --noproxy '*' -m 4 http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null | head -c 20)"
    [ "$h" = ALLOK ] && return 0; sleep 6
  done
  return 1
}
fetch_url() { curl -s --noproxy '*' -m 15 -o "$2" -w '%{http_code}' "$(printf '%s' "$1" | sed 's#//pki\.lab\.test:8080#//127.0.0.1:8080#')"; }

echo "== Installation réelle (vrai conteneur, base vierge) =="
"$PKI" apply "$IMG" pki.lab.test 10.0.0.0/8 > "$D/apply.out" 2>&1; expect_eq "installation acceptée" 0 "$?"
check "le conteneur répond « ALLOK » (premier démarrage, quelques minutes)" wait_health
"$PKI" status >/dev/null 2>&1
expect_eq "état publié : en service" healthy "$(jget "$RUNP/pki-status.json" state)"
expect_eq "état publié : données présentes" true "$(jget "$RUNP/pki-status.json" dataPresent)"
expect_eq "état publié : aucune autorité" 0 "$(jget "$RUNP/pki-status.json" casCount)"
expect_eq "état publié : remise à zéro permise sans autorité" true "$(jget "$RUNP/pki-status.json" resetAllowed)"
check "le fichier de secrets n'est lisible que par root" test "$(stat -c %a "$D/etc/ejbca.env")" = 600

echo "== Demandes piégées (refusées avant toute commande) =="
for bad in \
  '{"action":"ca_root","name":"ManagementCA","alg":"rsa3072","days":3650,"cn":"X"}' \
  '{"action":"ca_root","name":"a b","alg":"rsa3072","days":3650,"cn":"X"}' \
  '{"action":"ca_root","name":"R1","alg":"rsa3072","days":3650,"cn":"X,O=pirate"}' \
  '{"action":"ca_root","name":"R1","alg":"rsa3072","days":3650,"cn":"X+UID=1"}' \
  '{"action":"ca_root","name":"R1","alg":"rsa3072","days":3650,"cn":"X","c":"FRA"}' \
  '{"action":"ca_root","name":"R1","alg":"des","days":3650,"cn":"X"}' \
  '{"action":"ca_root","name":"R1","alg":"rsa3072","days":10,"cn":"X"}' \
  '{"action":"ca_root","name":"R1","alg":"rsa3072","days":"3650","cn":"X"}' \
  '{"action":"ca_root","name":"../etc","alg":"rsa3072","days":3650,"cn":"X"}' \
  '{"action":"ca_issuing","name":"I1","alg":"rsa3072","days":1825,"cn":"X","signedBy":"../x"}' \
  '{"action":"ca_rootcrl","name":"ExtRoot-zzzzzzzz"}' \
  '{"action":"ca_crl","name":"ExtRoot-12345678"}' ; do
  req "$bad"; expect_eq "refusée : ${bad:0:78}" false "$RES_OK"
done
expect_eq "aucune autorité n'a été créée par les demandes piégées" "" "$(ca_get R1 name)"

echo "== Racine auto-signée (laboratoire) =="
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}'
expect_eq "racine créée" true "$RES_OK"
expect_eq "racine : active" active "$(ca_get Lab-Root state)"
expect_eq "racine : sorte « root »" root "$(ca_get Lab-Root kind)"
expect_eq "racine : auto-signée" true "$(ca_get Lab-Root selfSigned)"
expect_eq "racine : RSA 3072" "RSA 3072" "$(ca_get Lab-Root keyAlg) $(ca_get Lab-Root keyBits)"
expect_eq "racine : nom distinctif" "CN=Lab Root CA,O=Laboratoire,C=FR" "$(ca_get Lab-Root dn)"
check "racine : certificat publié" test -s "$RUNP/pki-ca/Lab-Root/cert.pem"
check "racine : CRL publiée" test -s "$RUNP/pki-ca/Lab-Root/crl.der"
check "racine : certificat auto-signé valide pour openssl" openssl verify -CAfile "$RUNP/pki-ca/Lab-Root/cert.pem" "$RUNP/pki-ca/Lab-Root/cert.pem"
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Autre"}'
expect_eq "même nom refusé" false "$RES_OK"
check "la raison du refus est lisible" grep -qi "existe déjà" <<< "$RES_MSG"

echo "== Émettrice signée par la racine du DDI =="
req '{"action":"ca_issuing","name":"Lab-Sub","alg":"ecp256","days":1825,"cn":"Lab Sub CA","o":"Laboratoire","c":"FR","signedBy":"Lab-Root"}'
expect_eq "émettrice créée" true "$RES_OK"
expect_eq "émettrice : active" active "$(ca_get Lab-Sub state)"
expect_eq "émettrice : signée par la racine du DDI" Lab-Root "$(ca_get Lab-Sub signedBy)"
expect_eq "émettrice : courbe P-256" prime256v1 "$(ca_get Lab-Sub curve)"
check "émettrice : chaîne publiée" test -s "$RUNP/pki-ca/Lab-Sub/chain.pem"
check "émettrice : le certificat se vérifie par la racine" openssl verify -CAfile "$RUNP/pki-ca/Lab-Root/cert.pem" "$RUNP/pki-ca/Lab-Sub/cert.pem"
req '{"action":"ca_issuing","name":"Lab-Sub2","alg":"rsa3072","days":1825,"cn":"X","signedBy":"Inexistante"}'
expect_eq "signeur inexistant refusé" false "$RES_OK"
req '{"action":"ca_issuing","name":"Lab-Sub3","alg":"rsa3072","days":1825,"cn":"X","signedBy":"Lab-Sub"}'
expect_eq "une émettrice ne peut pas signer (seule une racine du DDI le peut)" false "$RES_OK"

echo "== Émettrice sous une racine hors ligne =="
W="$D/w"
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$W/root.key" -out "$W/root.pem" -days 3650 -subj "/C=FR/O=Hors ligne/CN=Racine hors ligne" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
cp "$W/root.pem" "$GEN/pki-in/Lab-Ext.chain.pem"
req '{"action":"ca_issuing","name":"Lab-Ext","alg":"rsa3072","days":1825,"cn":"Emettrice externe","o":"Laboratoire","c":"FR","signedBy":"external"}'
expect_eq "émettrice externe créée (en attente)" true "$RES_OK"
expect_eq "externe : en attente du certificat" waiting "$(ca_get Lab-Ext state)"
check "externe : demande de certificat publiée" test -s "$RUNP/pki-ca/Lab-Ext/csr.pem"
check "externe : la demande a une signature valide" openssl req -in "$RUNP/pki-ca/Lab-Ext/csr.pem" -noout -verify
check "le dépôt de la console a été consommé" test ! -e "$GEN/pki-in/Lab-Ext.chain.pem"
EXT="$(python3 -c 'import json,sys
for c in json.load(open(sys.argv[1]))["cas"]:
    if c["kind"] == "extroot": print(c["name"])' "$RUNP/pki-cas.json" | head -n1)"
check "la racine hors ligne est connue comme racine externe (ExtRoot-…)" test -n "$EXT"
expect_eq "racine externe : sorte" extroot "$(ca_get "$EXT" kind)"
ROOT_CRL_URL="$(ca_get "$EXT" crlUrl)"; ROOT_CERT_URL="$(ca_get "$EXT" certUrl)"
check "adresse de CRL de la racine construite avec le nom public et le port 8080" grep -q '^http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=' <<< "$ROOT_CRL_URL"
# la racine signe : extensions CDP / AIA = adresses que le DDI publie pour la racine
cat > "$W/ext.cnf" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:$ROOT_CRL_URL
authorityInfoAccess=caIssuers;URI:$ROOT_CERT_URL
EOF
openssl x509 -req -in "$RUNP/pki-ca/Lab-Ext/csr.pem" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial -out "$W/ext.pem" -days 1825 -sha256 -extfile "$W/ext.cnf" 2>/dev/null
check "le certificat signé par la racine hors ligne existe" test -s "$W/ext.pem"
# refus avant toute commande : mauvais certificats
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/other.key" -out "$W/other.pem" -days 30 -subj "/CN=Emettrice externe/O=Laboratoire/C=FR" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
cp "$W/other.pem" "$GEN/pki-in/Lab-Ext.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "certificat d'une autre clé refusé" false "$RES_OK"; check "motif : clé qui ne correspond pas" grep -qi "clé publique" <<< "$RES_MSG"
openssl x509 -req -in "$RUNP/pki-ca/Lab-Ext/csr.pem" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial -out "$W/leaf.pem" -days 30 -sha256 2>/dev/null
cp "$W/leaf.pem" "$GEN/pki-in/Lab-Ext.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "certificat sans CA:TRUE refusé" false "$RES_OK"; check "motif : pas un certificat d'autorité" grep -qi "CA:TRUE" <<< "$RES_MSG"
printf 'pas un certificat' > "$GEN/pki-in/Lab-Ext.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "dépôt qui n'est pas un certificat refusé" false "$RES_OK"
ln -s /etc/passwd "$GEN/pki-in/Lab-Ext.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "dépôt par lien symbolique refusé" false "$RES_OK"; check "le lien symbolique a été retiré, la cible intacte" test ! -e "$GEN/pki-in/Lab-Ext.cert.pem" -a -s /etc/passwd
req '{"action":"ca_import","name":"Lab-Root"}'
expect_eq "import refusé pour une autorité qui n'attend pas de certificat" false "$RES_OK"
# le bon certificat
cp "$W/ext.pem" "$GEN/pki-in/Lab-Ext.cert.pem"; req '{"action":"ca_import","name":"Lab-Ext"}'
expect_eq "certificat signé importé" true "$RES_OK"
expect_eq "externe : active" active "$(ca_get Lab-Ext state)"
check "externe : le certificat porte l'adresse de CRL de la racine" bash -c "openssl x509 -in '$RUNP/pki-ca/Lab-Ext/cert.pem' -noout -text | grep -q 'cmd=crl'"
check "externe : chaîne publiée avec la racine hors ligne" bash -c "openssl verify -CAfile '$W/root.pem' -untrusted '$RUNP/pki-ca/Lab-Ext/chain.pem' '$RUNP/pki-ca/Lab-Ext/cert.pem'"
check "externe : CRL publiée" test -s "$RUNP/pki-ca/Lab-Ext/crl.der"

echo "== CRL servies en HTTP et signées par leur autorité =="
for n in Lab-Root Lab-Sub Lab-Ext; do
  code="$(fetch_url "$(ca_get "$n" crlUrl)" "$W/$n.crl")"
  expect_eq "$n : CRL en HTTP (200)" 200 "$code"
  check "$n : CRL signée par l'autorité" bash -c "openssl crl -inform DER -in '$W/$n.crl' -CAfile '$RUNP/pki-ca/$n/cert.pem' -noout -verify 2>&1 | grep -q 'verify OK'"
done
code="$(fetch_url "$(ca_get Lab-Sub certUrl)" "$W/sub-cert.out")"; expect_eq "certificat d'autorité en HTTP (200)" 200 "$code"
check "le certificat servi contient celui de l'autorité" bash -c "grep -q BEGIN '$W/sub-cert.out'"

expect_eq "seules les autorités du DDI sont publiées (aucun répertoire parasite)" "$EXT Lab-Ext Lab-Root Lab-Sub" "$(find "$RUNP/pki-ca" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
expect_eq "la publication ne contient ni ManagementCA ni autre autorité inconnue" 4 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["cas"]))' "$RUNP/pki-cas.json")"

echo "== CRL de la racine hors ligne =="
cat > "$W/ca.cnf" <<EOF
[ca]
default_ca=CA_default
[CA_default]
database=$W/index.txt
crlnumber=$W/crlnumber
default_md=sha256
default_crl_days=365
EOF
: > "$W/index.txt"; echo 01 > "$W/crlnumber"
openssl ca -config "$W/ca.cnf" -gencrl -keyfile "$W/root.key" -cert "$W/root.pem" -out "$W/root.crl.pem" >/dev/null 2>&1
check "CRL de la racine fabriquée par openssl" test -s "$W/root.crl.pem"
cp "$W/root.crl.pem" "$GEN/pki-in/$EXT.crl"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXT\"}"
expect_eq "CRL de la racine importée (PEM accepté)" true "$RES_OK"
code="$(fetch_url "$ROOT_CRL_URL" "$W/root-served.crl")"; expect_eq "CRL de la racine servie en HTTP par le DDI" 200 "$code"
check "la CRL servie est bien celle de la racine" bash -c "openssl crl -inform DER -in '$W/root-served.crl' -CAfile '$W/root.pem' -noout -verify 2>&1 | grep -q 'verify OK'"
check "la chaîne de l'émettrice se vérifie CRL de la racine comprise" bash -c "openssl crl -inform DER -in '$W/root-served.crl' -outform PEM -out '$W/root-served.pem' && cat '$W/root-served.pem' > '$W/crls.pem' && openssl verify -crl_check -CAfile '$W/root.pem' -CRLfile '$W/crls.pem' '$W/ext.pem'"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/o2.key" -out "$W/o2.pem" -days 30 -subj "/CN=Autre racine" 2>/dev/null
printf 'x' > "$W/bad.crl"; cp "$W/bad.crl" "$GEN/pki-in/$EXT.crl"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXT\"}"
expect_eq "CRL illisible refusée" false "$RES_OK"
cat > "$W/ca2.cnf" <<EOF
[ca]
default_ca=CA_default
[CA_default]
database=$W/index2.txt
crlnumber=$W/crlnumber2
default_md=sha256
default_crl_days=30
EOF
: > "$W/index2.txt"; echo 01 > "$W/crlnumber2"
openssl ca -config "$W/ca2.cnf" -gencrl -keyfile "$W/o2.key" -cert "$W/o2.pem" -out "$W/o2.crl.pem" >/dev/null 2>&1
cp "$W/o2.crl.pem" "$GEN/pki-in/$EXT.crl"; req "{\"action\":\"ca_rootcrl\",\"name\":\"$EXT\"}"
expect_eq "CRL signée par une autre autorité refusée" false "$RES_OK"

echo "== Renouvellement des CRL =="
n1="$(ca_get Lab-Sub crl.number)"
req '{"action":"ca_crl","name":"Lab-Sub"}'
expect_eq "CRL renouvelée à la demande" true "$RES_OK"
n2="$(ca_get Lab-Sub crl.number)"
check "le numéro de CRL a augmenté ($n1 → $n2)" test "$n2" -gt "$n1"
req '{"action":"ca_crl","name":"Lab-Inexistante"}'; expect_eq "CRL d'une autorité inconnue refusée" false "$RES_OK"
DDI_PKI_CRL_RENEW_AFTER=0 "$PKI" maintain >/dev/null 2>&1
n3="$(ca_get Lab-Sub crl.number)"
check "le minuteur renouvelle les CRL trop anciennes ($n2 → $n3)" test "$n3" -gt "$n2"
n4="$(ca_get Lab-Ext crl.number)"; DDI_PKI_CRL_RENEW_AFTER=99999 "$PKI" maintain >/dev/null 2>&1
expect_eq "le minuteur ne renouvelle pas une CRL récente" "$n4" "$(ca_get Lab-Ext crl.number)"

echo "== Remise à zéro =="
req '{"action":"reset"}'
expect_eq "remise à zéro refusée tant qu'une autorité existe" false "$RES_OK"
check "motif lisible" grep -qi "autorité" <<< "$RES_MSG"
"$PKI" status >/dev/null 2>&1
expect_eq "état publié : remise à zéro interdite" false "$(jget "$RUNP/pki-status.json" resetAllowed)"
check "les secrets sont toujours là" test -s "$D/etc/ejbca.env"
OLD_ENV="$(sha256sum "$D/etc/ejbca.env" | cut -c1-16)"
req '{"action":"uninstall"}'; expect_eq "désinstallation acceptée" true "$RES_OK"
check "après désinstallation les autorités restent listées (lues dans la base)" test -n "$(ca_get Lab-Root name)"
mv "$D/etc/ejbca.env" "$D/ejbca.env.saved"
"$PKI" apply "$IMG" pki.lab.test 10.0.0.0/8 > "$D/apply2.out" 2>&1; rc=$?
expect_eq "installation refusée : base existante sans ses secrets" 1 "$rc"
check "motif lisible (secrets absents)" grep -qi "secrets" "$D/apply2.out"
check "aucun nouveau fichier de secrets n'a été créé" test ! -e "$D/etc/ejbca.env"
mv "$D/ejbca.env.saved" "$D/etc/ejbca.env"
expect_eq "les secrets restaurés sont inchangés" "$OLD_ENV" "$(sha256sum "$D/etc/ejbca.env" | cut -c1-16)"
"$PKI" apply "$IMG" pki.lab.test 10.0.0.0/8 > "$D/apply3.out" 2>&1; expect_eq "réinstallation avec les mêmes secrets" 0 "$?"
check "les autorités sont de nouveau servies (santé « ALLOK »)" wait_health
check "la racine est toujours là après réinstallation" bash -c "$PKI status >/dev/null 2>&1; test -n \"\$(python3 -c 'import json,sys; print([c for c in json.load(open(sys.argv[1]))[\"cas\"] if c[\"name\"]==\"Lab-Root\"] and 1 or \"\")' '$RUNP/pki-cas.json')\""
code="$(fetch_url "$(ca_get Lab-Sub crlUrl)" "$W/after.crl")"; expect_eq "la CRL est servie après réinstallation" 200 "$code"

finish
