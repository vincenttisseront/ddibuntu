#!/usr/bin/env bash
# Batterie 14 (réel) — un vrai KDC MIT (domaine CORP.TEST), un vrai « named » configuré par ddibuntu-reload avec le keytab installé par ddibuntu-ad,
# et de vraies mises à jour GSS-TSIG (nsupdate -g, tickets obtenus avec kinit) : chaque machine ne peut modifier que son propre nom, les autres sont
# refusées, la clé DDNS de Kea continue de fonctionner, une zone sans politique Kerberos refuse tout client GSS, et le retrait de la configuration
# coupe l'accès. Ce n'est PAS un Active Directory : les comptes machine « PC2$ » imitent leur forme, mais aucun contrôleur Windows/Samba n'est testé.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"; AD="$RFS/usr/local/sbin/ddibuntu-ad"
for t in named named-checkconf dig nsupdate kinit kdb5_util kadmin.local krb5kdc klist tsig-keygen rndc python3 ip; do
  command -v "$t" >/dev/null 2>&1 || { note "batterie Kerberos réelle non exécutable ici (outil absent : $t ; paquets krb5-kdc krb5-admin-server krb5-user)"; finish; exit; }
done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }
getent passwd bind >/dev/null || { note "compte « bind » absent : batterie non exécutable"; finish; exit; }

W="$(mktemp -d /srv/ddikrb.XXXXXX)"; chmod 755 "$W"
IP=127.0.5.1
PIDS=""; DDNS_CREATED=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 1; for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
  ip addr del $IP/32 dev lo 2>/dev/null
  [ "$DDNS_CREATED" = 1 ] && rm -f /etc/bind/ddi-ddns.key
  rm -rf "$W" "$T_TMP"
}
trap cleanup EXIT
ip addr add $IP/32 dev lo 2>/dev/null
if [ ! -f /etc/bind/ddi-ddns.key ]; then mkdir -p /etc/bind; tsig-keygen -a hmac-sha256 ddi-ddns > /etc/bind/ddi-ddns.key; DDNS_CREATED=1; fi

R="$W/root"; BE="$R/etc/bind"; GEN="$W/gen"; ZN="$W/zones"; ST="$W/state"; KE="$W/kea"; KRB="$W/krb5.conf"
mkdir -p "$BE" "$GEN/zones" "$ZN" "$ST" "$KE" "$W/cache" "$W/run" "$W/kdc" "$R/run" "$R/var/lib/ddibuntu/generated"
chown bind:bind "$ZN" "$W/cache" "$W/run"

# ---- KDC ----
cat > "$W/kdc.conf" <<EOF
[kdcdefaults]
 kdc_ports = 8888
 kdc_tcp_ports = 8888
[realms]
 CORP.TEST = {
  database_name = $W/kdc/principal
  key_stash_file = $W/kdc/stash
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }
EOF
export KRB5_KDC_PROFILE="$W/kdc.conf"
kdb5_util create -s -r CORP.TEST -P masterpw >/dev/null 2>&1 || { ko "création de la base KDC"; finish; exit; }
kadm() { kadmin.local -r CORP.TEST -q "$1" 2>&1; }
for p in DNS/ns1.corp.test host/pc1.corp.test host/pc3.corp.test 'PC2$'; do kadm "addprinc -randkey $p@CORP.TEST" >/dev/null; done
kadm "ktadd -k $W/dns.keytab DNS/ns1.corp.test@CORP.TEST" >/dev/null
kadm "ktadd -k $W/pc1.keytab host/pc1.corp.test@CORP.TEST" >/dev/null
kadm "ktadd -k $W/pc3.keytab host/pc3.corp.test@CORP.TEST" >/dev/null
kadm "ktadd -k $W/pc2.keytab PC2\$@CORP.TEST" >/dev/null
krb5kdc -r CORP.TEST -n >"$W/kdc.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 20); do ss -ltn 2>/dev/null | grep -q ":8888 " && break; sleep 0.5; done

ad() { env DDI_ROOT="$R" DDI_KRB5_CONFIG="$KRB" DDI_RELOAD_CMD=/bin/true bash "$AD" "$@"; }
echo "== ddibuntu-ad : domaine et keytab du serveur DNS =="
check "configure : domaine et KDC" ad configure --realm CORP.TEST --kdc 127.0.0.1:8888
check "install-keytab : keytab du serveur DNS (vrai keytab du KDC)" ad install-keytab "$W/dns.keytab"
expect_eq "keytab : propriétaire root:bind, 0640" "root:bind 640" "$(stat -c '%U:%G %a' "$BE/krb5.keytab")"
check "test : un ticket est obtenu avec le keytab (KDC joignable, clé à jour)" ad test
export KRB5_CONFIG="$KRB"
expect_grep "…le keytab porte le principal DNS/…" 'DNS/ns1.corp.test@CORP.TEST' <(klist -k "$BE/krb5.keytab" 2>&1)

echo "== ddibuntu-reload : named configuré avec le keytab =="
cat > "$GEN/named.conf.options" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
include "/etc/bind/ddi-ddns.key";
options {
  directory "/var/cache/bind";
  listen-on { $IP; };
  listen-on-v6 { none; };
  recursion no;
  allow-query { any; };
  allow-transfer { none; };
  dnssec-validation no;
  check-names primary warn;
  querylog no;
};
CONF
cat > "$GEN/named.conf.zones" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
zone "corp.test" { type primary; file "$ZN/db.corp.test"; notify yes; update-policy { grant ddi-ddns zonesub ANY; grant CORP.TEST ms-self . A AAAA; grant CORP.TEST krb5-self . A AAAA; }; };
zone "ms.test" { type primary; file "$ZN/db.ms.test"; notify yes; update-policy { grant CORP.TEST ms-self . A AAAA; }; };
zone "key.test" { type primary; file "$ZN/db.key.test"; notify yes; allow-update { key "ddi-ddns"; }; };
CONF
for z in corp.test ms.test key.test; do
  printf '$ORIGIN %s.\n$TTL 300\n@ IN SOA ns1.corp.test. root.corp.test. ( 1 3600 600 86400 300 )\n@ IN NS ns1.corp.test.\n' "$z" > "$GEN/zones/db.$z"
done
printf 'ns1.corp.test.\n' >/dev/null
printf 'ns1 IN A %s\npc1 IN A 10.0.0.5\n' "$IP" >> "$GEN/zones/db.corp.test"
printf '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"subnet4":[]}}' > "$GEN/kea-dhcp4.conf"
rl() { env DDI_GENERATED_DIR="$GEN" DDI_BIND_ETC="$BE" DDI_ZONES_RUNTIME_DIR="$ZN" DDI_KEA_ETC="$KE" DDI_STATE_DIR="$ST" DDI_CLUSTER_DIR="$W/nocl" DDI_AD_DIR="$R/etc/ddibuntu-ad" \
    DDI_RELOAD_NOSERVICES=1 DDI_LOCK_FILE="$W/lock" bash "$RELOAD" "$@"; }
printf 'include "%s/named.conf.options";\ninclude "%s/named.conf.local";\nkey "rndc-key" { algorithm hmac-sha256; secret "cm5kY2tleXJuZGNrZXlybmRja2V5cm5kY2tleTEyMzQ="; };\ncontrols { inet 127.0.0.1 port 9540 allow { 127.0.0.1; } keys { "rndc-key"; }; };\n' "$BE" "$BE" > "$BE/named.conf"
check "ddibuntu-reload complet" rl
expect_grep "options : tkey-gssapi-keytab posé par root" "tkey-gssapi-keytab \"$BE/krb5.keytab\"" "$BE/named.conf.options"
sed -i "s|directory \"/var/cache/bind\";|directory \"$W/cache\"; pid-file \"$W/run/named.pid\"; session-keyfile \"$W/run/session.key\";|" "$BE/named.conf.options"
check "named-checkconf" named-checkconf "$BE/named.conf"
# named démarre SANS KRB5_CONFIG : seul le keytab compte côté serveur
( unset KRB5_CONFIG KRB5_KDC_PROFILE; named -u bind -c "$BE/named.conf" -g >"$W/named.log" 2>&1 & echo $! > "$W/named.pid" )
PIDS="$PIDS $(cat "$W/named.pid")"
q() { dig +short +tries=1 +time=3 "$@" 2>&1; }
wait_cond() { local s="$1" d="$2" e="$3" i=0; while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
wait_cond 20 "named répond" '[ -n "$(q @$IP pc1.corp.test A)" ]'
expect_grep "named : GSS-API (TKEY mode 3) disponible" 'TKEY mode 3 support \(GSS-API\): yes' "$W/named.log"

# ---- mises à jour GSS-TSIG ----
upd() { # upd KEYTAB PRINCIPAL ZONE NOM IP  → code de nsupdate -g
  local kt="$1" pr="$2" zone="$3" name="$4" ip="$5" cc="$W/cc.$$.$RANDOM"
  KRB5CCNAME="FILE:$cc" kinit -k -t "$kt" "$pr" >/dev/null 2>&1 || { echo "kinit-failed"; return 99; }
  printf 'server %s\nzone %s\nupdate delete %s A\nupdate add %s 300 A %s\nsend\n' "$IP" "$zone" "$name" "$name" "$ip" > "$cc.upd"
  KRB5CCNAME="FILE:$cc" nsupdate -g "$cc.upd" >"$cc.out" 2>&1; local rc=$?
  cat "$cc.out"; rm -f "$cc" "$cc.upd" "$cc.out"; return $rc
}
echo "== krb5-self : un hôte Kerberos ne modifie que son propre nom =="
check "host/pc1 met à jour pc1.corp.test" upd "$W/pc1.keytab" host/pc1.corp.test corp.test pc1.corp.test 10.0.0.61
expect_eq "…la nouvelle adresse est servie" "10.0.0.61" "$(q @$IP pc1.corp.test A)"
check_fail "host/pc1 ne peut PAS modifier pc3.corp.test" upd "$W/pc1.keytab" host/pc1.corp.test corp.test pc3.corp.test 10.0.0.99
expect_eq "…pc3 n'existe pas" "" "$(q @$IP pc3.corp.test A)"
check_fail "host/pc1 ne peut PAS modifier le nom du serveur (ns1.corp.test)" upd "$W/pc1.keytab" host/pc1.corp.test corp.test ns1.corp.test 10.66.0.1
expect_eq "…ns1 inchangé" "$IP" "$(q @$IP ns1.corp.test A)"
check "host/pc3 met à jour pc3.corp.test" upd "$W/pc3.keytab" host/pc3.corp.test corp.test pc3.corp.test 10.0.0.63
expect_eq "…pc3 servi" "10.0.0.63" "$(q @$IP pc3.corp.test A)"

echo "== ms-self : compte machine de style AD (PC2\$) =="
check "PC2\$ met à jour pc2.corp.test" upd "$W/pc2.keytab" 'PC2$' corp.test pc2.corp.test 10.0.0.62
expect_eq "…servi" "10.0.0.62" "$(q @$IP pc2.corp.test A)"
check_fail "PC2\$ ne peut PAS modifier pc1.corp.test" upd "$W/pc2.keytab" 'PC2$' corp.test pc1.corp.test 10.66.6.6
expect_eq "…pc1 conserve son adresse" "10.0.0.61" "$(q @$IP pc1.corp.test A)"
check_fail "ms-self n'agit que dans la zone du domaine : PC2\$ refusé pour pc2.ms.test (BIND le lit comme pc2.corp.test)" upd "$W/pc2.keytab" 'PC2$' ms.test pc2.ms.test 10.1.0.62
check_fail "zone ms-self seul : un hôte host/pc1 (krb5-self) est refusé" upd "$W/pc1.keytab" host/pc1.corp.test ms.test pc1.ms.test 10.1.0.61
expect_eq "…pas d'enregistrement créé" "" "$(q @$IP pc1.ms.test A)"
note "constaté : ms-self associe PC1\$@CORP.TEST au nom pc1.corp.test ; la console refuse donc ms-self hors de la zone portant le nom du domaine (ms_self_zone_mismatch)"

echo "== zone sans politique Kerberos =="
check_fail "key.test (clé DDNS seule) refuse un client GSS" upd "$W/pc1.keytab" host/pc1.corp.test key.test pc1.key.test 10.2.0.61
printf 'server %s\nzone key.test\nupdate add kea.key.test 300 A 10.2.0.9\nsend\n' "$IP" > "$W/upd.key"
check "key.test accepte la clé DDNS (Kea)" nsupdate -k /etc/bind/ddi-ddns.key "$W/upd.key"
expect_eq "…enregistrement servi" "10.2.0.9" "$(q @$IP kea.key.test A)"
printf 'server %s\nzone corp.test\nupdate add kea.corp.test 300 A 10.0.0.9\nsend\n' "$IP" > "$W/upd.key2"
check "corp.test : la clé DDNS reste acceptée à côté de Kerberos (grant ddi-ddns zonesub)" nsupdate -k /etc/bind/ddi-ddns.key "$W/upd.key2"
printf 'server %s\nzone corp.test\nupdate add anon.corp.test 300 A 10.0.0.8\nsend\n' "$IP" > "$W/upd.anon"
check_fail "mise à jour anonyme (sans clé ni ticket) refusée" nsupdate "$W/upd.anon"
expect_eq "…rien créé" "" "$(q @$IP anon.corp.test A)"

echo "== clé du serveur périmée =="
kadm "ktadd -k $W/dns-rotated.keytab DNS/ns1.corp.test@CORP.TEST" >/dev/null       # rotation de la clé au KDC : l'ancien keytab n'est plus valide
check_fail "test : l'ancien keytab est détecté comme périmé (kvno)" ad test
check "le nouveau keytab est accepté" ad install-keytab "$W/dns-rotated.keytab"
check "test : de nouveau valide" ad test

echo "== retrait de la configuration =="
check "ddibuntu-ad remove" ad remove
[ ! -e "$BE/krb5.keytab" ] && ok "keytab supprimé" || ko "keytab encore présent"
check "ddibuntu-reload après retrait" rl
expect_nogrep "…plus de tkey-gssapi-keytab" 'tkey-gssapi-keytab' "$BE/named.conf.options"
expect_nogrep "…plus d'octroi Kerberos" 'ms-self|krb5-self' "$BE/named.conf.local"
expect_grep "…la clé DDNS reste autorisée" 'grant ddi-ddns zonesub ANY' "$BE/named.conf.local"

finish
