#!/usr/bin/env bash
# Batterie 39 — SCEP de la PKI du DDI (0.14.8) sur le VRAI conteneur : alias créé par la CLI d'EJBCA, équipement préenregistré (mode « CA » : le seul de la Community),
# inscription RÉELLE avec sscep (la clé reste chez l'équipement ; nom et noms alternatifs viennent de l'entité, jamais de sa demande), certificat vérifié (clé, nom, SAN, CDP/AIA du DDI,
# chaîne), défi à usage unique (réutilisation, mauvais défi), nouveau défi, annulation, expiration, désactivation/réactivation, et SURVIE de l'alias à une mise à jour 9.3.7 → 9.6.3
# puis à un retour arrière. Le défi ne doit apparaître dans aucun fichier publié ni dans la sortie de root.
# DESTRUCTIVE : supprime la base « ejbca » et le conteneur « ddibuntu-ejbca » de la machine ; exige DDI_TEST_PKI_LIVE=1.
# Prérequis : ceux de la batterie 37 (root, podman + images docker.io/keyfactor/ejbca-ce:9.3.7 ET :9.6.3 présentes, PostgreSQL local, openssl, curl, port 8080 libre, ~2 Go de mémoire)
# et un client SCEP : « sscep » (https://github.com/certnanny/sscep) dans le PATH ou désigné par DDI_TEST_SSCEP ; sans lui, les inscriptions sont ignorées (le reste est vérifié).
# Durée : une vingtaine de minutes (chaque commande de la CLI d'EJBCA démarre une JVM).
# DDI_TEST_PODMAN_ARGS permet de viser un autre stockage Podman (ex. « --root /tmp/podman-root --runroot /tmp/podman-run »). DDI_TEST_PKI_KEEP=1 garde l'état (/tmp/b39-keep.env).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

PKI="$RFS/usr/local/sbin/ddibuntu-pki"
OLD="docker.io/keyfactor/ejbca-ce:9.3.7"
NEW="docker.io/keyfactor/ejbca-ce:9.6.3"
read -r -a PARGS <<< "${DDI_TEST_PODMAN_ARGS:-}"
if [ "${DDI_TEST_PKI_LIVE:-}" != 1 ]; then note "DDI_TEST_PKI_LIVE=1 absent (la batterie supprime la base « ejbca » et le conteneur « ddibuntu-ejbca ») : ignorée"; finish; exit $?; fi
if [ "$(id -u)" -ne 0 ] || ! command -v podman >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null || ! command -v runuser >/dev/null \
   || [ ! -x /usr/lib/systemd/system-generators/podman-system-generator ]; then
  note "prérequis absents (root, podman et son générateur Quadlet, openssl, curl, runuser) : batterie ignorée"; finish; exit $?
fi
for im in "$OLD" "$NEW"; do
  if ! podman "${PARGS[@]}" image exists "$im" >/dev/null 2>&1; then note "image $im absente (la batterie ne tire rien) : ignorée"; finish; exit $?; fi
done
if curl -s --noproxy '*' -m 2 -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; then note "le port 8080 est déjà utilisé : batterie ignorée"; finish; exit $?; fi
if ! runuser -u postgres -- psql -X -q -At -d postgres -c 'select 1' >/dev/null 2>&1; then note "PostgreSQL local injoignable : batterie ignorée"; finish; exit $?; fi
SSCEP="${DDI_TEST_SSCEP:-$(command -v sscep || true)}"
[ -n "$SSCEP" ] && [ -x "$SSCEP" ] || { SSCEP=""; note "sscep absent : les inscriptions réelles sont ignorées"; }

D="$T_TMP"; chmod 0755 "$D"
mkdir -p "$D/bin" "$D/etc" "$D/data" "$D/quad" "$D/run" "$D/gen/pki-in" "$D/w"
GEN="$D/gen"; RUNP="$D/run"
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
unset DDI_PKI_PSQL DDI_PKI_ALLOW_USER DDI_PKI_PGDUMP DDI_PKI_PGRESTORE DDI_PKI_HUB_URL

psql_pg() { runuser -u postgres -- psql -X -q -At -d postgres "$@"; }
reset_all() {
  "$D/bin/podman" rm -f ddibuntu-ejbca >/dev/null 2>&1
  psql_pg -c 'drop database if exists ejbca with (force)' -c 'drop role if exists ejbca' >/dev/null 2>&1
}
if [ "${DDI_TEST_PKI_KEEP:-}" = 1 ]; then
  { for v in DDI_LIBDIR DDI_PKI_ETC DDI_PKI_DATA DDI_PKI_QUADLET_DIR DDI_PKI_PODMAN DDI_PKI_SYSTEMCTL DDI_PKI_LOCK DDI_FW_BIN DDI_PKI_UID DDI_GENERATED_DIR DDI_RUN_DIR; do printf 'export %s=%q\n' "$v" "${!v}"; done; printf 'export PKI=%q D=%q\n' "$PKI" "$D"; } > /tmp/b39-keep.env
  trap 'note "état conservé : . /tmp/b39-keep.env"' EXIT
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
req() {   # $1 = JSON de la demande ; la demande passe par le vrai « request » (celui que déclenche l'unité .path)
  printf '%s' "$1" > "$GEN/.pki-request"
  "$PKI" request > "$D/req.out" 2>&1 || true
  RES_OK="$(jget "$RUNP/pki-result.json" ok)"
  [ "$RES_OK" = true ] || note "demande refusée : $(jget "$RUNP/pki-result.json" message | cut -c1-300)"
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
ca_get() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
c = [x for x in d["cas"] if x["name"] == sys.argv[2]]
v = c[0] if c else {}
for k in sys.argv[3].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$RUNP/pki-cas.json" "$1" "$2" 2>/dev/null; }
ejpsql() { runuser -u postgres -- psql -X -q -At -d ejbca "$@"; }
inst_tag() { jget "$D/etc/instance.json" tag; }
img_of() { "$D/bin/podman" image inspect -f '{{.Digest}}' "$1" 2>/dev/null; }   # empreinte de l'image locale désignée par son étiquette
img_run() { "$D/bin/podman" inspect -f '{{.ImageName}}' ddibuntu-ejbca 2>/dev/null | sed 's/.*@//'; }   # empreinte de l'image du conteneur
certs_in_db() { ejpsql -c "select count(*) from certificatedata" 2>/dev/null; }

# ---- Aides propres à SCEP ----
W="$D/w"
mkpw() { python3 -c 'import secrets;print("".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(24)))'; }
newid() { python3 -c 'import secrets;print(secrets.token_hex(8))'; }
scep_url() { jget "$RUNP/pki-scep.json" url | sed 's#//pki\.lab\.test:8080#//127.0.0.1:8080#'; }
offer_state() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
o = [x for x in d["offers"] if x["cn"] == sys.argv[2]]
v = o[0] if o else {}
for k in sys.argv[3].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$RUNP/pki-scep.json" "$1" "$2" 2>/dev/null; }
offer() {   # $1 nom, $2 profil (défaut network), $3 autorité (défaut Lab-SubRSA) : dépose le défi comme la console, demande le préenregistrement ; le défi est dans OFFER_PW
  local id; id="$(newid)"; OFFER_PW="$(mkpw)"
  printf '%s' "$OFFER_PW" > "$GEN/pki-in/$id.scepw"; chmod 600 "$GEN/pki-in/$id.scepw"
  req "$(printf '{"action":"scep_offer","id":"%s","ca":"%s","profile":"%s","cn":"%s","o":"Laboratoire","c":"FR","dns":["%s.lab.test"]}' "$id" "${3:-Lab-SubRSA}" "${2:-network}" "$1" "$1")"
  OFFER_ID="$id"
}
rearm() {   # $1 nom : nouveau défi dans OFFER_PW
  local id; id="$(newid)"; OFFER_PW="$(mkpw)"
  printf '%s' "$OFFER_PW" > "$GEN/pki-in/$id.scepw"; chmod 600 "$GEN/pki-in/$id.scepw"
  req "$(printf '{"action":"scep_rearm","id":"%s","cn":"%s"}' "$id" "$1")"
  OFFER_ID="$id"
}
getca() {   # certificat de l'émettrice tel que l'équipement le reçoit (GetCACert), en PEM dans $W/ca.pem
  local code; code="$(curl -s --noproxy '*' -m 20 -o "$W/ca.der" -w '%{http_code}' "$(scep_url)?operation=GetCACert&message=${1:-Lab-SubRSA}")"
  [ "$code" = 200 ] && openssl x509 -inform DER -in "$W/ca.der" -out "$W/ca.pem" 2>/dev/null
}
enrol() {   # $1 nom, $2 défi, $3 fichier de clé (défaut : $W/<nom>.key, créée si absente), $4 certificat obtenu (défaut $W/<nom>.crt) ; le sujet de la demande est VOLONTAIREMENT faux
  local cn="$1" pw="$2" key="${3:-$W/$1.key}" out="${4:-$W/$1.crt}"
  [ -f "$key" ] || openssl genrsa -out "$key" 2048 2>/dev/null
  cat > "$W/$cn.cnf" <<EOC
[req]
distinguished_name = dn
attributes = attrs
prompt = no
[dn]
CN = $cn
O = Pirate
C = ZZ
[attrs]
challengePassword = $pw
EOC
  openssl req -new -key "$key" -out "$W/$cn.csr" -config "$W/$cn.cnf" 2>/dev/null
  rm -f "$out"
  "$SSCEP" enroll -u "$(scep_url)" -c "$W/ca.pem" -k "$key" -r "$W/$cn.csr" -l "$out" -E 3des -S sha1 > "$W/$cn.out" 2>&1
  [ -s "$out" ]
}
pubkey_of_cert() { openssl x509 -in "$1" -noout -pubkey 2>/dev/null | sha256sum | cut -d' ' -f1; }
pubkey_of_key() { openssl pkey -in "$1" -pubout 2>/dev/null | sha256sum | cut -d' ' -f1; }
ejbca_cli() { "$D/bin/podman" exec ddibuntu-ejbca /opt/keyfactor/bin/ejbca.sh "$@" 2>&1; }
alias_listed() { ejbca_cli config scep listalias | grep -q ddibuntu; }
alias_nochain() { ejbca_cli config scep dumpalias --alias ddibuntu | grep -qi 'returnCaChainInGetCaCert.*false'; }
ca_single() { getca Lab-SubRSA && openssl x509 -in "$W/ca.pem" -noout -subject | grep -q 'Lab SubRSA CA' && [ "$(grep -c 'BEGIN CERTIFICATE' "$W/ca.pem")" = 1 ]; }
exp7() { python3 -c 'import json,sys
o = [x for x in json.load(open(sys.argv[1]))["offers"] if x["cn"] == sys.argv[2]][0]
sys.exit(0 if o["expiresAt"] - o["modifiedAt"] == 7 * 86400 else 1)' "$RUNP/pki-scep.json" "$1"; }
hashed_only() { [ "$(ejpsql -c "select count(*) from userdata where username = '$1' and (clearpassword is null or clearpassword = '')")" = 1 ]; }
in_db() { [ "$(ejpsql -c "select count(*) from userdata where username = '$1'")" = "$2" ]; }
reactivated_enrol() { getca Lab-SubRSA && enrol sw-reactive "$PW_RE"; }
leak_free() {   # $1 défi : nulle part dans ce que root publie, dans sa sortie ni dans la base d'EJBCA
  local pw="$1"
  ! grep -rqs "$pw" "$RUNP" "$D/req.out" "$GEN" 2>/dev/null && [ "$(ejpsql -c "select count(*) from userdata where endentityprofileid = 5020001 and clearpassword is not null and clearpassword <> ''" 2>/dev/null)" = 0 ]
}

echo "== Installation réelle de la 9.3.7 (base vierge) =="
"$PKI" apply "$OLD" pki.lab.test 10.0.0.0/8 > "$D/apply.out" 2>&1; expect_eq "installation acceptée" 0 "$?"
check "le conteneur répond « ALLOK » (premier démarrage, quelques minutes)" wait_health
expect_eq "version installée : 9.3.7" 9.3.7 "$(inst_tag)"
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}'; expect_eq "racine créée" true "$RES_OK"
req '{"action":"ca_issuing","name":"Lab-Sub","alg":"ecp256","days":1825,"cn":"Lab Sub CA","o":"Laboratoire","c":"FR","signedBy":"Lab-Root"}'; expect_eq "émettrice ECDSA créée" true "$RES_OK"
req '{"action":"ca_issuing","name":"Lab-SubRSA","alg":"rsa3072","days":1825,"cn":"Lab SubRSA CA","o":"Laboratoire","c":"FR","signedBy":"Lab-Root"}'; expect_eq "émettrice RSA créée" true "$RES_OK"
"$PKI" status >/dev/null 2>&1
expect_eq "avant activation : SCEP désactivé dans l'état publié" false "$(jget "$RUNP/pki-scep.json" enabled)"
expect_eq "avant activation : aucun équipement" 0 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["offers"]))' "$RUNP/pki-scep.json")"

echo "== Préenregistrer sans SCEP actif : refusé =="
offer sw-trop-tot; expect_eq "refus tant que l'alias n'existe pas" false "$RES_OK"
check "…le défi déposé est consommé" test ! -e "$GEN/pki-in/$OFFER_ID.scepw"

echo "== Activation (CLI d'EJBCA : « config scep addalias ») sous la 9.3.7 =="
req '{"action":"scep_enable"}'; expect_eq "SCEP activé sous la 9.3.7" true "$RES_OK"
"$PKI" status >/dev/null 2>&1
expect_eq "état publié : activé" true "$(jget "$RUNP/pki-scep.json" enabled)"
expect_eq "adresse publiée" "http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe" "$(jget "$RUNP/pki-scep.json" url)"
check "l'alias figure dans la liste d'EJBCA" alias_listed
check "la réponse GetCACert ne porte que l'émettrice (returnCaChainInGetCaCert=false)" alias_nochain
req '{"action":"scep_enable"}'; expect_eq "activer deux fois : accepté" true "$RES_OK"
check "GetCACert répond et rend UN certificat : l'émettrice RSA" ca_single

echo "== Refus de préenregistrement =="
offer sw-ec network Lab-Sub; expect_eq "émettrice ECDSA refusée (SCEP chiffre pour une clé RSA)" false "$RES_OK"
offer sw-racine network Lab-Root; expect_eq "une racine ne délivre pas de certificats finaux" false "$RES_OK"
offer superadmin; expect_eq "entité de service d'EJBCA : refusée" false "$RES_OK"
offer ejbca; expect_eq "autre entité de service : refusée" false "$RES_OK"
check "…rien n'a été créé dans EJBCA" in_db sw-ec 0
check "…ni sw-racine" in_db sw-racine 0

echo "== Équipement préenregistré, inscription RÉELLE sous la 9.3.7 =="
offer sw-old; expect_eq "sw-old préenregistré" true "$RES_OK"; PW_OLD="$OFFER_PW"
"$PKI" status >/dev/null 2>&1
expect_eq "publié : en attente" waiting "$(offer_state sw-old state)"
expect_eq "publié : profil réseau" network "$(offer_state sw-old profile)"
expect_eq "publié : autorité" Lab-SubRSA "$(offer_state sw-old ca)"
check "publié : échéance à sept jours de la préparation" exp7 sw-old
check "le défi n'est nulle part : ni publié, ni dans la sortie de root, ni en clair dans EJBCA" leak_free "$PW_OLD"
check "le dépôt du défi est consommé" test ! -e "$GEN/pki-in/$OFFER_ID.scepw"
offer sw-old; expect_eq "même nom une seconde fois : refusé" false "$RES_OK"
if [ -n "$SSCEP" ]; then
  check "GetCACert (émettrice)" getca Lab-SubRSA
  enrol sw-old "$(mkpw)"; expect_eq "mauvais défi : l'inscription échoue" 1 "$?"
  check "…aucun certificat n'a été délivré" test ! -s "$W/sw-old.crt"
  check "inscription avec le bon défi (la clé reste chez l'équipement)" enrol sw-old "$PW_OLD"
  CRT="$W/sw-old.crt"
  check "le certificat porte la clé publique DE L'ÉQUIPEMENT" test "$(pubkey_of_cert "$CRT")" = "$(pubkey_of_key "$W/sw-old.key")"
  check "nom distinctif : celui de l'entité (CN, O, C du DDI), jamais celui de la demande (« Pirate », ZZ)" bash -c "s=\"\$(openssl x509 -in '$CRT' -noout -subject)\"; echo \"\$s\" | grep -q 'sw-old' && echo \"\$s\" | grep -q 'Laboratoire' && ! echo \"\$s\" | grep -qi 'pirate\\|ZZ'"
  check "noms alternatifs : ceux de l'entité" bash -c "openssl x509 -in '$CRT' -noout -ext subjectAltName | grep -q 'DNS:sw-old.lab.test'"
  check "usages : serveur ET client (profil équipement réseau)" bash -c "e=\"\$(openssl x509 -in '$CRT' -noout -ext extendedKeyUsage)\"; echo \"\$e\" | grep -q 'TLS Web Server' && echo \"\$e\" | grep -q 'TLS Web Client'"
  CRLURL="$(ca_get Lab-SubRSA crlUrl)"
  check "adresse de CRL : celle de l'émettrice publiée par le DDI" bash -c "openssl x509 -in '$CRT' -noout -ext crlDistributionPoints | grep -qF '$CRLURL'"
  check "chaîne : émettrice puis racine du DDI" bash -c "openssl verify -CAfile '$RUNP/pki-ca/Lab-SubRSA/chain.pem' -untrusted '$RUNP/pki-ca/Lab-SubRSA/cert.pem' '$CRT' | grep -q ': OK'"
  "$PKI" status >/dev/null 2>&1
  expect_eq "publié : inscrit" issued "$(offer_state sw-old state)"
  expect_eq "publié : série du certificat (hexadécimal)" "$(openssl x509 -in "$CRT" -noout -serial | cut -d= -f2 | sed 's/^0*//')" "$(offer_state sw-old cert.serial)"
  expect_eq "publié : certificat non révoqué" false "$(offer_state sw-old cert.revoked)"
  SER_OLD="$(offer_state sw-old cert.serial)"
  enrol sw-old "$PW_OLD" "$W/sw-old2.key" "$W/sw-old.reuse.crt"; expect_eq "défi déjà utilisé : refusé (usage unique)" 1 "$?"
  check "…aucun second certificat" test ! -s "$W/sw-old.reuse.crt"
  check "la base d'EJBCA ne garde pas le défi en clair" hashed_only sw-old
fi

echo "== Inscription ratée puis réussie : le mauvais essai n'use pas le défi =="
offer sw-retry; expect_eq "sw-retry préenregistré" true "$RES_OK"; PW_RETRY="$OFFER_PW"
if [ -n "$SSCEP" ]; then
  enrol sw-retry "$(mkpw)"; expect_eq "défi faux : refusé" 1 "$?"
  check "défi juste ensuite : accepté" enrol sw-retry "$PW_RETRY"
fi

echo "== Les autres profils =="
offer pc-lab machine; expect_eq "profil machine préenregistré" true "$RES_OK"; PW_PC="$OFFER_PW"
if [ -n "$SSCEP" ]; then
  check "inscription du poste (profil machine)" enrol pc-lab "$PW_PC"
  check "…usage client seulement" bash -c "e=\"\$(openssl x509 -in '$W/pc-lab.crt' -noout -ext extendedKeyUsage)\"; echo \"\$e\" | grep -q 'TLS Web Client' && ! echo \"\$e\" | grep -q 'TLS Web Server'"
fi

echo "== Mise à jour 9.3.7 → 9.6.3 : l'alias et les équipements survivent =="
"$PKI" update-apply "$NEW" > "$D/upd1.out" 2>&1; expect_eq "mise à jour acceptée" 0 "$?"
check "le conteneur répond « ALLOK » après la migration" wait_health
"$PKI" status >/dev/null 2>&1
expect_eq "version installée : 9.6.3" 9.6.3 "$(inst_tag)"
expect_eq "l'alias SCEP est toujours là" true "$(jget "$RUNP/pki-scep.json" enabled)"
check "…et son réglage aussi (réponse GetCACert sans chaîne)" alias_nochain
[ -z "$SSCEP" ] || expect_eq "sw-old est toujours inscrit" issued "$(offer_state sw-old state)"
offer sw-new; expect_eq "sous la 9.6.3 : nouvel équipement préenregistré" true "$RES_OK"; PW_NEW="$OFFER_PW"
if [ -n "$SSCEP" ]; then
  check "GetCACert sous la 9.6.3" getca Lab-SubRSA
  check "inscription réelle sous la 9.6.3" enrol sw-new "$PW_NEW"
  check "…avec la clé de l'équipement" test "$(pubkey_of_cert "$W/sw-new.crt")" = "$(pubkey_of_key "$W/sw-new.key")"
  cp "$W/sw-old.crt" "$W/sw-old.v1.crt"
  rearm sw-old; expect_eq "nouveau défi pour sw-old (renouvellement)" true "$RES_OK"; PW_REN="$OFFER_PW"
  "$PKI" status >/dev/null 2>&1
  expect_eq "publié : de nouveau en attente" waiting "$(offer_state sw-old state)"
  check "le nouveau défi n'est nulle part" leak_free "$PW_REN"
  enrol sw-old "$PW_OLD" "$W/sw-old3.key" "$W/sw-old.stale.crt"; expect_eq "l'ancien défi ne sert plus" 1 "$?"
  openssl genrsa -out "$W/sw-old-ren.key" 2048 2>/dev/null
  check "renouvellement avec une NOUVELLE clé" enrol sw-old "$PW_REN" "$W/sw-old-ren.key"
  check "…le nouveau certificat porte la nouvelle clé" test "$(pubkey_of_cert "$W/sw-old.crt")" = "$(pubkey_of_key "$W/sw-old-ren.key")"
  "$PKI" status >/dev/null 2>&1
  check "…et une autre série que le premier" test "$(offer_state sw-old cert.serial)" != "$SER_OLD" -a -n "$(offer_state sw-old cert.serial)"
  check "l'ancien certificat reste valable (non révoqué) jusqu'à décision de l'administrateur" bash -c "openssl verify -CAfile '$RUNP/pki-ca/Lab-SubRSA/chain.pem' -untrusted '$RUNP/pki-ca/Lab-SubRSA/cert.pem' '$W/sw-old.v1.crt' | grep -q ': OK'"
fi

echo "== Retour arrière réel : l'alias revient avec la base d'avant =="
"$PKI" update-rollback > "$D/rb.out" 2>&1; expect_eq "retour arrière accepté" 0 "$?"
check "le conteneur répond « ALLOK » après le retour arrière" wait_health
"$PKI" status >/dev/null 2>&1
expect_eq "version installée : 9.3.7" 9.3.7 "$(inst_tag)"
expect_eq "l'alias SCEP est là (il était dans la base d'avant)" true "$(jget "$RUNP/pki-scep.json" enabled)"
expect_eq "sw-new (préenregistré après la sauvegarde) a disparu" "" "$(offer_state sw-new state)"
[ -z "$SSCEP" ] || expect_eq "sw-old est revenu à l'état d'avant (inscrit une fois)" issued "$(offer_state sw-old state)"
[ -z "$SSCEP" ] || expect_eq "…avec le premier certificat" "$SER_OLD" "$(offer_state sw-old cert.serial)"
offer sw-apres; expect_eq "la 9.3.7 préenregistre de nouveau" true "$RES_OK"; PW_AP="$OFFER_PW"
if [ -n "$SSCEP" ]; then
  check "GetCACert après le retour arrière" getca Lab-SubRSA
  check "inscription réelle après le retour arrière" enrol sw-apres "$PW_AP"
fi

echo "== Seconde mise à jour, puis validation =="
"$PKI" update-apply "$NEW" > "$D/upd2.out" 2>&1; expect_eq "seconde mise à jour acceptée" 0 "$?"
check "le conteneur répond « ALLOK »" wait_health
"$PKI" update-validate > "$D/val.out" 2>&1; expect_eq "validation acceptée" 0 "$?"
"$PKI" status >/dev/null 2>&1
expect_eq "l'alias survit aussi à la validation" true "$(jget "$RUNP/pki-scep.json" enabled)"

echo "== Annulation, expiration, désactivation =="
offer sw-annule; expect_eq "sw-annule préenregistré" true "$RES_OK"
req '{"action":"scep_cancel","cn":"sw-annule"}'; expect_eq "annulation acceptée" true "$RES_OK"
"$PKI" status >/dev/null 2>&1
expect_eq "…l'équipement a disparu de la liste" "" "$(offer_state sw-annule state)"
req '{"action":"scep_cancel","cn":"sw-annule"}'; expect_eq "annuler un nom inconnu : refusé" false "$RES_OK"
req '{"action":"scep_cancel","cn":"superadmin"}'; expect_eq "annuler une entité de service : refusé" false "$RES_OK"
check "…superadmin est intact" in_db superadmin 1
offer sw-expire; expect_eq "sw-expire préenregistré" true "$RES_OK"
sleep 2; DDI_PKI_SCEP_DAYS=0 "$PKI" maintain >/dev/null 2>&1
"$PKI" status >/dev/null 2>&1
expect_eq "délai dépassé : l'équipement jamais inscrit est supprimé par la maintenance" "" "$(offer_state sw-expire state)"
[ -z "$SSCEP" ] || expect_eq "…mais un équipement déjà inscrit n'est jamais supprimé" issued "$(offer_state sw-apres state)"
req '{"action":"scep_disable"}'; expect_eq "désactivation acceptée" true "$RES_OK"
"$PKI" status >/dev/null 2>&1
expect_eq "état publié : désactivé" false "$(jget "$RUNP/pki-scep.json" enabled)"
check_fail "l'alias n'est plus dans EJBCA" alias_listed
[ -z "$SSCEP" ] || expect_eq "les équipements inscrits restent listés" issued "$(offer_state sw-apres state)"
offer sw-desactive; expect_eq "préenregistrer SCEP désactivé : refusé" false "$RES_OK"
req '{"action":"scep_enable"}'; expect_eq "réactivation" true "$RES_OK"
if [ -n "$SSCEP" ]; then
  offer sw-reactive; PW_RE="$OFFER_PW"; expect_eq "préenregistrement après réactivation" true "$RES_OK"
  check "inscription après réactivation" reactivated_enrol
fi

finish
