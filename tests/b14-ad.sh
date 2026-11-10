#!/usr/bin/env bash
# Batterie 14 — Active Directory, Kerberos / GSS-TSIG (sans démon) : ddibuntu-ad (validation du domaine et du keytab, demandes de la console) et
# recomposition des « update-policy » par ddibuntu-reload (root seul ajoute tkey-gssapi-keytab ; la console ne peut ni le déclarer ni changer de domaine).
# Les keytabs sont fabriqués octet par octet (format MIT) : aucun KDC n'est nécessaire ici (essai réel avec un vrai KDC : b14-ad-live.sh).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
AD="$RFS/usr/local/sbin/ddibuntu-ad"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"
for t in klist named-checkconf tsig-keygen python3 openssl shred; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }

W="$T_TMP/w"; R="$W/root"; GEN="$R/var/lib/ddibuntu/generated"; RUN="$R/run/ddibuntu"
mkdir -p "$GEN" "$R/etc/bind" "$R/etc" "$RUN"
KT="$R/etc/bind/krb5.keytab"; KRB="$R/etc/krb5.conf"
DDNS_CREATED=0
if [ ! -f /etc/bind/ddi-ddns.key ]; then mkdir -p /etc/bind; tsig-keygen -a hmac-sha256 ddi-ddns > /etc/bind/ddi-ddns.key; DDNS_CREATED=1; fi
trap '[ "$DDNS_CREATED" = 1 ] && rm -f /etc/bind/ddi-ddns.key; rm -rf "$T_TMP"' EXIT

# Fabrique un keytab MIT : mkkt FICHIER ENCTYPE_ID PRINCIPAL[@REALM] [kvno]
mkkt() {
  python3 - "$@" <<'PY'
import struct, sys
path, enc, princ = sys.argv[1], int(sys.argv[2]), sys.argv[3]
kvno = int(sys.argv[4]) if len(sys.argv) > 4 else 2
name, realm = princ.rsplit("@", 1)
comps = name.split("/")
def cs(b): return struct.pack(">H", len(b)) + b
klen = {18: 32, 17: 16, 1: 8, 23: 16}[enc]
body = struct.pack(">H", len(comps)) + cs(realm.encode()) + b"".join(cs(c.encode()) for c in comps)
body += struct.pack(">IIB", 1, 1700000000, kvno) + struct.pack(">HH", enc, klen) + b"\x11" * klen + struct.pack(">I", kvno)
open(path, "wb").write(b"\x05\x02" + struct.pack(">i", len(body)) + body)
PY
}
ad() { env DDI_TEST=1 DDI_ROOT="$R" DDI_KEYTAB_GROUP=root DDI_RELOAD_CMD="$W/fake-reload" bash "$AD" "$@"; }
printf '#!/bin/sh\necho "$@" >> "%s/reload.calls"\n' "$W" > "$W/fake-reload"; chmod +x "$W/fake-reload"

echo "== ddibuntu-ad : domaine Kerberos =="
printf '[libdefaults]\n default_realm = ATHENA.MIT.EDU\n' > "$KRB"
check_fail "sans argument : usage" ad
check_fail "domaine en minuscules refusé" ad configure --realm corp.test
check_fail "domaine avec espace refusé" ad configure --realm "CORP TEST"
check_fail "domaine avec injection refusé" ad configure --realm 'CORP.TEST
 kdc = evil'
check_fail "domaine absent refusé" ad configure
check_fail "KDC avec point-virgule refusé" ad configure --realm CORP.TEST --kdc 'dc1;rm'
check_fail "KDC avec espace refusé" ad configure --realm CORP.TEST --kdc 'dc 1'
check_fail "port de KDC hors plage refusé" ad configure --realm CORP.TEST --kdc dc1:99999
check_fail "argument inconnu refusé" ad configure --realm CORP.TEST --evil x
check "configuration valide (deux KDC)" ad configure --realm CORP.TEST --kdc dc1.corp.test --kdc dc2.corp.test:88
expect_grep "ad.conf : domaine" '^REALM=CORP.TEST$' "$R/etc/ddibuntu-ad/ad.conf"
expect_grep "ad.conf : contrôleurs" '^KDCS=dc1.corp.test dc2.corp.test:88$' "$R/etc/ddibuntu-ad/ad.conf"
expect_grep "krb5.conf : domaine par défaut" 'default_realm = CORP.TEST' "$KRB"
expect_grep "krb5.conf : KDC explicites, pas de recherche DNS" 'dns_lookup_kdc = false' "$KRB"
expect_grep "krb5.conf : KDC listés" 'kdc = dc2.corp.test:88' "$KRB"
expect_grep "krb5.conf : en-tête de gestion" 'Géré par DDI-Buntu' "$KRB"
expect_grep "krb5.conf d'origine conservé une fois" 'ATHENA.MIT.EDU' "$KRB.ddibuntu-orig"
check "reconfiguration (sans KDC : recherche DNS)" ad configure --realm CORP.TEST
expect_grep "…dns_lookup_kdc activé" 'dns_lookup_kdc = true' "$KRB"
expect_grep "…l'original n'est pas écrasé par le fichier géré" 'ATHENA.MIT.EDU' "$KRB.ddibuntu-orig"

echo "== ddibuntu-ad : keytab =="
mkkt "$W/ok.kt" 18 DNS/ns1.corp.test@CORP.TEST 3
mkkt "$W/other-realm.kt" 18 DNS/ns1.corp.test@OTHER.TEST
mkkt "$W/host.kt" 18 host/pc1.corp.test@CORP.TEST
mkkt "$W/user.kt" 18 admin@CORP.TEST
mkkt "$W/des.kt" 1 DNS/ns1.corp.test@CORP.TEST
mkkt "$W/rc4.kt" 23 DNS/ns1.corp.test@CORP.TEST
printf 'ceci n est pas un keytab\n' > "$W/text.kt"; : > "$W/empty.kt"
head -c 70000 /dev/zero | tr '\0' '\5' > "$W/big.kt"
ln -sf "$W/ok.kt" "$W/link.kt"
check_fail "keytab d'un autre domaine refusé" ad install-keytab "$W/other-realm.kt"
check_fail "principal host/… refusé (seuls DNS/… sont admis)" ad install-keytab "$W/host.kt"
check_fail "principal utilisateur refusé" ad install-keytab "$W/user.kt"
check_fail "chiffrement DES refusé" ad install-keytab "$W/des.kt"
check_fail "texte quelconque refusé" ad install-keytab "$W/text.kt"
check_fail "fichier vide refusé" ad install-keytab "$W/empty.kt"
check_fail "fichier trop gros refusé" ad install-keytab "$W/big.kt"
check_fail "lien symbolique refusé" ad install-keytab "$W/link.kt"
check_fail "fichier absent refusé" ad install-keytab "$W/nexiste.kt"
[ ! -e "$KT" ] && ok "aucun keytab installé après ces refus" || ko "un keytab refusé a été installé"
check "keytab valide installé" ad install-keytab "$W/ok.kt"
expect_eq "keytab : droits 0640" "640" "$(stat -c %a "$KT")"
check "keytab conforme à la source" cmp "$W/ok.kt" "$KT"
mkkt "$W/rc4.kt" 23 DNS/ns2.corp.test@CORP.TEST 4
check "RC4 admis (domaines AD anciens), avec un second principal par stdin" bash -c "DDI_TEST=1 DDI_ROOT='$R' DDI_KEYTAB_GROUP=root DDI_RELOAD_CMD='$W/fake-reload' bash '$AD' install-keytab - < '$W/rc4.kt'"
check "état publié" test -s "$RUN/ad-status.json"
check "état = JSON valide" python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$RUN/ad-status.json"
expect_eq "état : domaine" "CORP.TEST" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["realm"])' "$RUN/ad-status.json")"
expect_eq "état : principal du keytab" "DNS/ns2.corp.test@CORP.TEST" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["keytab"]["principals"][0])' "$RUN/ad-status.json")"
expect_eq "état : numéro de version de clé" "4" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["keytab"]; print(d["kvno"][d["principals"][0]])' "$RUN/ad-status.json")"
expect_nogrep "état : aucune clé secrète publiée" '1111|secret|password' "$RUN/ad-status.json"
check "changer de domaine retire le keytab de l'ancien domaine" ad configure --realm NEW.TEST
[ ! -e "$KT" ] && ok "…keytab retiré" || ko "keytab de l'ancien domaine conservé"
check "retour au domaine d'origine" ad configure --realm CORP.TEST
check "remove : configuration retirée" ad remove
[ ! -e "$R/etc/ddibuntu-ad/ad.conf" ] && ok "…ad.conf supprimé" || ko "ad.conf encore présent"
expect_grep "…krb5.conf d'origine restauré" 'ATHENA.MIT.EDU' "$KRB"
[ ! -e "$KRB.ddibuntu-orig" ] && ok "…sauvegarde consommée" || ko "sauvegarde conservée"
check_fail "install-keytab sans domaine refusé" ad install-keytab "$W/ok.kt"
check_fail "test sans keytab refusé" ad test

echo "== ddibuntu-ad : demandes de la console (non fiables, revalidées) =="
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["ok"], d["action"])' "$RUN/ad-result.json"; }
req() { printf '%s' "$1" > "$GEN/.ad-request"; }
: > "$W/reload.calls"
req '{"action":"configure","realm":"CORP.TEST","kdcs":["dc1.corp.test"]}'
check "demande configure traitée" ad request
expect_eq "…résultat publié (ok)" "True configure" "$(res)"
[ ! -e "$GEN/.ad-request" ] && ok "…demande consommée" || ko "demande non supprimée"
expect_grep "…domaine enregistré" '^REALM=CORP.TEST$' "$R/etc/ddibuntu-ad/ad.conf"
expect_eq "…BIND relu (ddibuntu-reload appelé)" "1" "$(wc -l < "$W/reload.calls" | tr -d ' ')"
cp "$W/ok.kt" "$GEN/.ad-keytab"; req '{"action":"install-keytab"}'
check "demande install-keytab traitée" ad request
expect_eq "…résultat publié (ok)" "True install-keytab" "$(res)"
[ ! -e "$GEN/.ad-keytab" ] && ok "…keytab déposé supprimé après usage" || ko "keytab déposé encore sur le disque"
check "…keytab en place" cmp "$W/ok.kt" "$KT"
cp "$W/host.kt" "$GEN/.ad-keytab"; req '{"action":"install-keytab"}'
check_fail "keytab refusé : la demande échoue" ad request
expect_eq "…résultat publié (refus)" "False install-keytab" "$(res)"
[ ! -e "$GEN/.ad-keytab" ] && ok "…keytab refusé supprimé aussi" || ko "keytab refusé laissé sur le disque"
check "…l'ancien keytab valide est intact" cmp "$W/ok.kt" "$KT"
req '{"action":"install-keytab"}'
check_fail "install-keytab sans fichier déposé" ad request
ln -sf "$W/ok.kt" "$GEN/.ad-keytab"; req '{"action":"install-keytab"}'
check_fail "keytab déposé sous forme de lien symbolique refusé" ad request
[ ! -e "$GEN/.ad-keytab" ] && [ ! -L "$GEN/.ad-keytab" ] && ok "…lien supprimé" || ko "lien symbolique laissé"
req 'ceci n est pas du json'; check_fail "JSON invalide refusé" ad request
req '{"action":"rm -rf /"}'; check_fail "action inconnue refusée" ad request
req '{"action":"configure","realm":"corp.test"}'; check_fail "domaine invalide refusé" ad request
req '{"action":"configure","realm":"CORP.TEST","kdcs":[1,2]}'; check_fail "KDC non textuels refusés" ad request
req '{"action":"configure","realm":"CORP.TEST","kdcs":["dc1; evil"]}'; check_fail "KDC hostile refusé" ad request
req '[1,2]'; check_fail "tableau JSON refusé" ad request
expect_grep "…aucun KDC hostile enregistré" '^KDCS=dc1.corp.test$' "$R/etc/ddibuntu-ad/ad.conf"
ln -sf /etc/passwd "$GEN/.ad-request"; check_fail "demande sous forme de lien symbolique refusée" ad request
[ ! -L "$GEN/.ad-request" ] && ok "…lien supprimé sans être suivi" || ko "lien symbolique laissé"
check "sans demande : rien à faire" ad request
req '{"action":"remove"}'; check "demande remove traitée" ad request
[ ! -e "$KT" ] && ok "…keytab supprimé" || ko "keytab présent"
expect_nogrep "résultat : aucun secret" 'secret|password|1111' "$RUN/ad-result.json"

echo "== ddibuntu-reload : politiques Kerberos recomposées par root =="
W2="$W/r"; G="$W2/gen"; BE="$R/etc/bind"; KE="$W2/kea"; ST="$W2/state"; CD="$W2/cl"; ZN="$W2/zones"; ADD="$R/etc/ddibuntu-ad"
mkdir -p "$G/zones" "$KE" "$ST" "$CD/pki" "$ZN"
printf 'include "%s/named.conf.options";\ninclude "%s/named.conf.local";\n' "$BE" "$BE" > "$BE/named.conf"
for z in lan.test ext.test; do printf '$ORIGIN %s.\n$TTL 300\n@ IN SOA ns.%s. root.%s. ( 1 3600 600 86400 300 )\n@ IN NS ns.%s.\nns IN A 10.0.0.1\n' "$z" "$z" "$z" "$z" > "$G/zones/db.$z"; done
printf '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"subnet4":[]}}' > "$G/kea-dhcp4.conf"
mkopts() { # mkopts [ligne supplémentaire dans options]
  cat > "$G/named.conf.options" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
include "/etc/bind/ddi-ddns.key";
options {
  directory "/var/cache/bind";
  listen-on { any; };
  recursion yes;
  allow-recursion { 127.0.0.0/8; };
  allow-query { any; };
  allow-transfer { none; };
  dnssec-validation auto;
  ${1:-}
};
CONF
}
mkzones() { # mkzones "propriétés de lan.test"
  cat > "$G/named.conf.zones" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
zone "lan.test" { type primary; file "$ZN/db.lan.test"; notify yes; $1 };
zone "ext.test" { type primary; file "$ZN/db.ext.test"; notify yes; allow-update { key "ddi-ddns"; }; };
CONF
}
# shellcheck disable=SC2120  # les arguments éventuels sont transmis tels quels à ddibuntu-reload
rl() { env DDI_GENERATED_DIR="$G" DDI_BIND_ETC="$BE" DDI_ZONES_RUNTIME_DIR="$ZN" DDI_KEA_ETC="$KE" DDI_STATE_DIR="$ST" DDI_CLUSTER_DIR="$CD" DDI_AD_DIR="$ADD" DDI_RELOAD_NOSERVICES=1 DDI_LOCK_FILE="$W2/lock" bash "$RELOAD" "$@" 2>&1; }
OPT="$BE/named.conf.options"; LOC="$BE/named.conf.local"
POL='update-policy { grant ddi-ddns zonesub ANY; grant CORP.TEST ms-self . A AAAA; grant CORP.TEST krb5-self . A AAAA; };'
mkopts; mkzones "$POL"
rm -f "$CD/cluster.conf"

rm -rf "$ADD" "$KT"
check "sans domaine configuré : le dépôt est accepté" rl
expect_grep "…octrois Kerberos retirés, clé DDNS conservée" 'update-policy \{ grant ddi-ddns zonesub ANY; \};' "$LOC"
expect_nogrep "…aucun octroi Kerberos" 'ms-self|krb5-self' "$LOC"
expect_nogrep "…pas de tkey-gssapi-keytab" 'tkey-gssapi-keytab' "$OPT"
check "…named-checkconf" named-checkconf "$BE/named.conf"
rl >/dev/null; rl | grep -q 'AVERTISSEMENT\|configuré' ; ok "…le reload ne bloque pas un nœud sans domaine (promotion possible)"
mkzones 'update-policy { grant CORP.TEST ms-self . A AAAA; };'
check "sans domaine, politique 100 % Kerberos : accepté" rl
expect_nogrep "…la zone retombe sans mise à jour dynamique" 'update-policy' <(grep '^zone "lan.test"' "$LOC")
mkzones "$POL"

ad configure --realm CORP.TEST >/dev/null; ad install-keytab "$W/ok.kt" >/dev/null
check "domaine et keytab présents : dépôt accepté" rl
expect_grep "…tkey-gssapi-keytab ajouté par root, chemin imposé" "^  tkey-gssapi-keytab \"$BE/krb5.keytab\";$" "$OPT"
expect_eq "…une seule directive tkey" "1" "$(grep -c tkey-gssapi-keytab "$OPT")"
expect_grep "…juste après « options { »" 'options \{' "$OPT"
expect_eq "…placée dans le bloc options" "options {" "$(grep -B1 tkey-gssapi-keytab "$OPT" | head -n1)"
expect_grep "…politique complète conservée" 'update-policy \{ grant ddi-ddns zonesub ANY; grant CORP.TEST ms-self \. A AAAA; grant CORP.TEST krb5-self \. A AAAA; \};' "$LOC"
expect_grep "…zone à clé DDNS seule inchangée" 'zone "ext.test" .* allow-update \{ key "ddi-ddns"; \};' "$LOC"
check "…named-checkconf accepte le résultat" named-checkconf "$BE/named.conf"
cp "$OPT" "$W/opt.good"; cp "$LOC" "$W/loc.good"

rm -f "$KT"
check "keytab absent : dépôt accepté avec avertissement" rl
expect_nogrep "…sans keytab, pas de tkey" 'tkey-gssapi-keytab' "$OPT"
ad install-keytab "$W/ok.kt" >/dev/null
check "keytab réinstallé : dépôt accepté, tkey de retour" rl
expect_grep "…tkey-gssapi-keytab de retour" 'tkey-gssapi-keytab' "$OPT"
cp "$OPT" "$W/opt.good"; cp "$LOC" "$W/loc.good"

echo "== ddibuntu-reload : ce que la console ne peut pas faire =="
mkopts '  tkey-gssapi-keytab "/etc/shadow";'; mkzones "$POL"
check_fail "tkey-gssapi-keytab dans les options : refusé" rl
mkopts '  tkey-domain "evil.test";'
check_fail "tkey-domain : refusé" rl
mkopts '  tkey-gssapi-credential "DNS/x@Y";'
check_fail "tkey-gssapi-credential : refusé" rl
mkopts
mkzones 'update-policy { grant OTHER.TEST ms-self . A AAAA; };'
check_fail "domaine Kerberos différent de celui de root : refusé" rl
mkzones 'update-policy { grant * wildcard * ANY; };'
check_fail "octroi « wildcard * ANY » : refusé" rl
mkzones 'update-policy { grant CORP.TEST krb5-subdomain . ANY; };'
check_fail "krb5-subdomain : refusé" rl
mkzones 'update-policy { grant CORP.TEST ms-self . A AAAA PTR; };'
check_fail "types au-delà de A/AAAA : refusés" rl
mkzones 'update-policy { grant CORP.TEST ms-self . ANY; };'
check_fail "ms-self sur ANY : refusé" rl
mkzones 'update-policy { grant ddi-ddns zonesub ANY; deny CORP.TEST ms-self . A; };'
check_fail "deny : refusé" rl
mkzones 'update-policy { grant ddi-ddns name evil.test. ANY; };'
check_fail "octroi de clé DDNS autre que zonesub : refusé" rl
mkzones "allow-update { any; }; $POL"
check_fail "allow-update ouvert à tous : refusé" rl
check "…les fichiers installés sont restés ceux du dernier dépôt valide" cmp "$W/opt.good" "$OPT"
check "…zones inchangées aussi" cmp "$W/loc.good" "$LOC"

printf 'options { directory "/var/cache/bind"; };\n' > "$G/named.conf.options"; mkzones "$POL"
check_fail "options sur une ligne + tkey nécessaire : refusé (on ne devine pas où l'insérer)" rl
rm -rf "$ADD"; check "options sur une ligne sans Kerberos configuré : accepté comme avant" rl
ad configure --realm CORP.TEST >/dev/null; ad install-keytab "$W/ok.kt" >/dev/null; mkopts

echo "== ddibuntu-reload : cluster (primaire / secondaire) =="
mkopts; mkzones "$POL"
openssl ecparam -name prime256v1 -genkey -noout -out "$CD/ca.key" 2>/dev/null
openssl req -x509 -new -key "$CD/ca.key" -subj /CN=test-ca -days 2 -out "$CD/pki/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$CD/pki/node.key" 2>/dev/null
openssl req -new -key "$CD/pki/node.key" -subj /CN=n -out "$CD/n.csr" 2>/dev/null
openssl x509 -req -in "$CD/n.csr" -CA "$CD/pki/ca.crt" -CAkey "$CD/ca.key" -CAcreateserial -days 2 -out "$CD/pki/node.crt" 2>/dev/null
tsig-keygen -a hmac-sha256 ddi-xfr > "$BE/ddi-xfr.key"
printf 'CLUSTER_NAME=lab\nNODE_NAME=n1\nNODE_ROLE=data\nNODE_IP=10.9.0.1\nREPL_NET=10.9.0.0/24\nPEERS=n1=10.9.0.1:data n2=10.9.0.2:data\nCA_NODE=0\n' > "$CD/cluster.conf"
check "primaire du cluster : reload complet" rl
expect_grep "…politique conservée sur le primaire" 'zone "lan.test" .*update-policy \{ grant ddi-ddns zonesub ANY; grant CORP.TEST ms-self \. A AAAA; grant CORP.TEST krb5-self \. A AAAA; \};' "$LOC"
expect_grep "…avec la clé de transfert du cluster" 'key "ddi-xfr"' "$LOC"
expect_grep "…tkey-gssapi-keytab présent sur le primaire" 'tkey-gssapi-keytab' "$OPT"
check "…named-checkconf" named-checkconf "$BE/named.conf"
check "secondaire : reload --replica" rl --replica
expect_nogrep "…aucune mise à jour dynamique sur le secondaire" 'update-policy|allow-update' "$LOC"
expect_nogrep "…pas de tkey sur le secondaire" 'tkey-gssapi-keytab' "$OPT"
expect_grep "…zones devenues secondaires" 'zone "lan.test" \{ type secondary;' "$LOC"
check "…named-checkconf" named-checkconf "$BE/named.conf"
rm -rf "$ADD"
check "secondaire sans domaine configuré : réplication acceptée (pas de blocage)" rl --replica
mkzones 'update-policy { grant OTHER.TEST ms-self . A AAAA; };'
check "secondaire : un domaine différent n'empêche pas de répliquer" rl --replica
mkzones 'update-policy { grant * wildcard * ANY; };'
check_fail "secondaire : une politique hors grammaire est tout de même refusée" rl --replica

echo "== ddibuntu-reload : promotion du secondaire (le nœud redevient primaire avec les mêmes politiques) =="
ad configure --realm CORP.TEST >/dev/null; ad install-keytab "$W/ok.kt" >/dev/null
mkopts; mkzones "$POL"
for z in lan.test ext.test; do cp "$G/zones/db.$z" "$ZN/db.$z"; done     # zones « reçues par transfert » (texte : repli de la conversion)
check "promotion : ddibuntu-reload --promote" rl --promote
expect_grep "…politique Kerberos rétablie sur le nouveau primaire" 'zone "lan.test" .*update-policy \{ grant ddi-ddns zonesub ANY; grant CORP.TEST ms-self \. A AAAA; grant CORP.TEST krb5-self \. A AAAA; \};' "$LOC"
expect_grep "…tkey-gssapi-keytab de retour" 'tkey-gssapi-keytab' "$OPT"
check "…named-checkconf" named-checkconf "$BE/named.conf"
rm -rf "$ADD"
check "promotion sur un nœud sans domaine configuré : acceptée (aucun blocage du basculement)" rl --promote
expect_nogrep "…sans octroi Kerberos" 'ms-self|krb5-self' "$LOC"

finish
