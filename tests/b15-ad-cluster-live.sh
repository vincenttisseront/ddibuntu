#!/usr/bin/env bash
# Batterie 15b — keytab AD dans le cluster, avec de VRAIS etcd (TLS mutuel) : 3 nœuds simulés sur 127.0.1.1-3 (deux de données, un arbitre).
# Vérifie : publication chiffrée (l'arbitre ne peut rien lire), application sur l'autre nœud, idempotence, modification, retrait,
# changement d'origine, premier contact, etcd injoignable, valeurs hostiles (illisible, altérée, chiffrée avec une autre clé, état invalide),
# reprise après une valeur hostile, exécution concurrente, absence de secret résiduel sur le disque.
# Les keytabs sont fabriqués octet par octet (aucun KDC) ; Patroni/PostgreSQL ne sont pas nécessaires (« ad-sync » ne les utilise pas).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
AD="$RFS/usr/local/sbin/ddibuntu-ad"
PY=python3.12
PGBIN=/usr/lib/postgresql/16/bin
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl openssl gpg runuser python3 patroni patronictl curl; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
command -v "$PY" >/dev/null 2>&1 || PY=python3
getent passwd etcd >/dev/null && getent passwd postgres >/dev/null || missing="$missing comptes-etcd/postgres"
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
if [ -n "$missing" ]; then note "batterie cluster réel (AD) non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() { pkill -u etcd -f "$B/" 2>/dev/null; pkill -9 -u postgres -f "$B/n" 2>/dev/null; sleep 1; rm -rf "$B"; rm -rf "$T_TMP"; }
trap cleanup EXIT

ip() { echo "127.0.1.$1"; }
R() { echo "$B/n$1"; }
# cl N … / ad N … : ddibuntu-cluster / ddibuntu-ad dans l'environnement du nœud N (chacun appelle l'autre par son propre enrobage)
mkwrap() {
  local n="$1" r; r="$(R "$n")"
  printf '#!/bin/sh\nexec env DDI_TEST=1 DDI_ROOT=%s DDI_KEYTAB_GROUP=root DDI_RELOAD_CMD=/bin/true DDI_CLUSTER_CMD=%s/cl%s.sh bash %s "$@"\n' "$r" "$B" "$n" "$AD" > "$B/ad$n.sh"
  printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_AD_CMD=%s/ad%s.sh bash %s "$@"\n' "$r" "$PY" "$B" "$n" "$CL" > "$B/cl$n.sh"
  chmod 755 "$B/ad$n.sh" "$B/cl$n.sh"
}
cl() { local n="$1"; shift; "$B/cl$n.sh" "$@"; }
clp() { local pw="$1" n="$2"; shift 2; DDI_BUNDLE_PASS="$pw" "$B/cl$n.sh" "$@"; }
ad() { local n="$1"; shift; "$B/ad$n.sh" "$@"; }
mknode() { local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu" "$r/etc/bind" "$r/var/lib/ddibuntu/generated"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"; mkwrap "$1"; }
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { local r; r="$(R "$1")"; ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file "$r/etc/ddibuntu-cluster/etcd.yml" >"$B/etcd$1.log" 2>&1 & ); }
stop_etcd() { pkill -u etcd -f "$(R "$1")/" 2>/dev/null; sleep 1; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
KEY=/ddibuntu-cluster/ad/state
state() { ad "$1" export-state; }
shaof() { sha256sum < "$1" | cut -d' ' -f1; }
synced() { cat "$(R "$1")/var/lib/ddibuntu/cluster/ad-synced" 2>/dev/null; }
sync_state() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$(R "$1")/run/ddibuntu/ad-sync.json" 2>/dev/null; }

# Keytab MIT fabriqué (mêmes octets que b14-ad.sh)
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
# Valeur etcd fabriquée à la main : enc_value FICHIER_CLÉ_DDI-XFR JSON_CLAIR → valeur (chiffrée avec la clé d'enveloppe dérivée de cette clé)
enc_value() {
  local keyf="$1" plain="$2" pass; pass="$(SECRET="$(sed -n 's/^ *secret "\([A-Za-z0-9+\/=]*\)";$/\1/p' "$keyf")" python3 -c 'import hashlib,hmac,os; print(hmac.new(os.environ["SECRET"].encode(), b"ddibuntu-ad-keytab-v1", hashlib.sha256).hexdigest(), end="")')"
  local gh; gh="$(mktemp -d)"; printf '%s' "$plain" > "$gh/p"
  gpg --homedir "$gh" --batch --quiet --yes --pinentry-mode loopback --passphrase "$pass" --symmetric --cipher-algo AES256 -o "$gh/b" "$gh/p" 2>/dev/null
  PLAIN="$plain" python3 -c 'import base64,hashlib,json,os,sys; print(json.dumps({"v":1,"sha":hashlib.sha256(os.environ["PLAIN"].encode()).hexdigest(),"blob":base64.b64encode(open(sys.argv[1],"rb").read()).decode()}), end="")' "$gh/b"
  rm -rf "$gh"
}

W="$B/w"; mkdir -p "$W"
mkkt "$W/a.kt" 18 DNS/ns1.corp.test@CORP.TEST 3
mkkt "$W/b.kt" 18 DNS/ns2.corp.test@CORP.TEST 7

echo "== Cluster : 3 etcd réels (n1 autorité + n2 données, n3 arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
bundle() { cl 1 bundle --name "$1" --ip "$2" --role "$3" --out "$B/$1.bundle" 2>"$B/bundle-$1.err"; }
P2="$(bundle n2 "$(ip 2)" data)"; [ -n "$P2" ] && ok "lot n2 (données) créé" || ko "lot n2 créé" "$(cat "$B/bundle-n2.err")"; mknode 2; initdb_local 2
check "join n2 (données)" clp "$P2" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
start_etcd 2; wait_for 30 "etcd n2 répond" ectl 2 endpoint status
check "activate n2" cl 2 activate
wait_for 60 "etcd : les deux membres sont sains" ectl 1 endpoint health --cluster
sleep 8   # etcd n'ajoute un membre que si tous les autres sont connectés depuis plus de 5 s
P3="$(bundle n3 "$(ip 3)" witness)"; [ -n "$P3" ] && ok "lot n3 (arbitre) créé" || ko "lot n3 (arbitre) créé" "$(cat "$B/bundle-n3.err")"; mknode 3
check "join n3 (arbitre)" clp "$P3" 3 join "$B/n3.bundle" --no-activate
start_etcd 3; wait_for 30 "etcd n3 répond" ectl 3 endpoint status
check "activate n3" cl 3 activate
expect_eq "n1 et n2 ont la même clé de cluster ddi-xfr" "$(shaof "$(R 1)/etc/bind/ddi-xfr.key")" "$(shaof "$(R 2)/etc/bind/ddi-xfr.key")"
expect_eq "l'arbitre n'a PAS la clé de cluster (il ne pourra rien déchiffrer)" "no" "$([ -e "$(R 3)/etc/bind/ddi-xfr.key" ] && echo yes || echo no)"

echo "== Rien de configuré : synchronisation sans effet =="
check "ad-sync n1 sans état" cl 1 ad-sync
expect_eq "…aucune valeur publiée" "" "$(ectl 1 get "$KEY" --print-value-only)"
expect_eq "…état « à jour »" "synced" "$(sync_state 1)"

echo "== Publication depuis n1 (demande de la console) =="
printf '{"action":"configure","realm":"CORP.TEST","kdcs":["dc1.corp.test"]}' > "$(R 1)/var/lib/ddibuntu/generated/.ad-request"
check "n1 : demande configure (réplique automatiquement)" ad 1 request
cp "$W/a.kt" "$(R 1)/var/lib/ddibuntu/generated/.ad-keytab"
printf '{"action":"install-keytab"}' > "$(R 1)/var/lib/ddibuntu/generated/.ad-request"
check "n1 : demande install-keytab (réplique automatiquement)" ad 1 request
V="$(ectl 1 get "$KEY" --print-value-only)"
expect_eq "etcd : valeur publiée (v1, empreinte sha256 de l'état)" "1 64" "$(printf '%s' "$V" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["v"], len(d["sha"]))')"
expect_eq "etcd : l'empreinte est celle de l'état de n1" "$(state 1 | sha256sum | cut -d' ' -f1)" "$(printf '%s' "$V" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"
expect_eq "etcd : le domaine n'apparaît pas en clair" "0" "$(printf '%s' "$V" | grep -c 'CORP.TEST')"
expect_eq "etcd : le keytab n'apparaît pas en clair (base64 de ses octets)" "0" "$(printf '%s' "$V" | grep -cF "$(base64 -w0 "$W/a.kt" | cut -c1-40)")"
expect_eq "etcd : l'arbitre lit la même valeur chiffrée" "$V" "$(ectl 3 get "$KEY" --print-value-only)"
expect_eq "n1 : état synchronisé = état local" "$(state 1 | sha256sum | cut -d' ' -f1)" "$(synced 1)"
expect_eq "n1 : état publié" "published" "$(sync_state 1)"

echo "== L'arbitre ne fait rien ; n2 applique =="
check "ad-sync sur l'arbitre : sans effet" cl 3 ad-sync
expect_eq "arbitre : aucun fichier Kerberos" "no" "$([ -e "$(R 3)/etc/ddibuntu-ad/ad.conf" ] || [ -e "$(R 3)/etc/bind/krb5.keytab" ] && echo yes || echo no)"
check "ad-sync n2" cl 2 ad-sync
expect_eq "n2 : même état que n1" "$(state 1)" "$(state 2)"
expect_eq "n2 : keytab identique octet pour octet" "$(shaof "$W/a.kt")" "$(shaof "$(R 2)/etc/bind/krb5.keytab")"
expect_eq "n2 : keytab 0640" "640" "$(stat -c %a "$(R 2)/etc/bind/krb5.keytab")"
expect_eq "n2 : état appliqué" "applied" "$(sync_state 2)"
check "ad-sync n2 (idempotent)" cl 2 ad-sync
expect_eq "n2 : à jour" "synced" "$(sync_state 2)"
expect_eq "aucun secret résiduel dans les dossiers temporaires de n2" "0" "$(ls -d "$(R 2)"/var/lib/ddibuntu/cluster/.ad.* 2>/dev/null | wc -l)"
expect_eq "aucun secret résiduel dans les dossiers temporaires de n1" "0" "$(ls -d "$(R 1)"/var/lib/ddibuntu/cluster/.ad.* 2>/dev/null | wc -l)"

echo "== Modification (nouveaux KDC) puis retrait =="
ad 1 configure --realm CORP.TEST --kdc dc1.corp.test --kdc dc2.corp.test >/dev/null 2>&1
check "n1 publie" cl 1 ad-sync
check "n2 applique" cl 2 ad-sync
expect_eq "n2 : nouveaux KDC, keytab conservé" "$(state 1)" "$(state 2)"
ad 1 remove >/dev/null 2>&1
check "n1 publie le retrait" cl 1 ad-sync
expect_eq "etcd : retrait publié (sha « none »)" "none" "$(ectl 1 get "$KEY" --print-value-only | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"
check "n2 applique le retrait" cl 2 ad-sync
expect_eq "n2 : plus rien de configuré" '{}' "$(state 2)"
expect_eq "n2 : keytab retiré" "no" "$([ -e "$(R 2)/etc/bind/krb5.keytab" ] && echo yes || echo no)"

echo "== Changement d'origine : l'installation se fait maintenant sur n2 =="
ad 2 configure --realm CORP.TEST --kdc dc9.corp.test >/dev/null 2>&1; ad 2 install-keytab "$W/b.kt" >/dev/null 2>&1
check "n2 publie (via follow : la synchronisation précède le reste)" cl 2 follow
check "n1 applique (via follow)" cl 1 follow
expect_eq "n1 : état venu de n2" "$(state 2)" "$(state 1)"
expect_eq "n1 : keytab de n2" "$(shaof "$W/b.kt")" "$(shaof "$(R 1)/etc/bind/krb5.keytab")"

echo "== Premier contact : le cluster gagne =="
rm -f "$(R 2)/var/lib/ddibuntu/cluster/ad-synced"
ad 2 configure --realm LOCAL.TEST >/dev/null 2>&1
check "n2 (jamais synchronisé, état local différent)" cl 2 ad-sync
expect_eq "…l'état du cluster remplace l'état local" "$(state 1)" "$(state 2)"

echo "== etcd injoignable =="
stop_etcd 2
ad 2 configure --realm CORP.TEST --kdc dc7.corp.test >/dev/null 2>&1
check "n2 sans etcd : pas d'échec, rien d'appliqué à l'aveugle" cl 2 ad-sync
expect_eq "…état « failed » signalé à la console" "failed" "$(sync_state 2)"
start_etcd 2; wait_for 30 "etcd n2 revenu" ectl 2 endpoint health
check "n2 republie sa modification" cl 2 ad-sync
check "n1 applique" cl 1 ad-sync
expect_eq "n1 : KDC dc7" "yes" "$(state 1 | grep -q dc7 && echo yes || echo no)"

echo "== Valeurs hostiles dans etcd (n1 ne doit rien appliquer) =="
GOOD="$(state 1)"; GOODV="$(ectl 1 get "$KEY" --print-value-only)"
hostile() { printf '%s' "$1" | ectl 1 put "$KEY" >/dev/null 2>&1; }
hostile 'pas du json'
check_fail "valeur illisible : refusée" cl 1 ad-sync
expect_eq "…état local inchangé" "$GOOD" "$(state 1)"
hostile '{"v":1,"sha":"zz","blob":""}'
check_fail "empreinte invalide : refusée" cl 1 ad-sync
hostile '{"v":2,"sha":"none","blob":""}'
check_fail "version inconnue : refusée" cl 1 ad-sync
TAMP="$(printf '%s' "$GOODV" | python3 -c 'import base64,json,sys; d=json.load(sys.stdin); b=bytearray(base64.b64decode(d["blob"])); b[len(b)//2]^=1; d["blob"]=base64.b64encode(bytes(b)).decode(); d["sha"]="0"*64; print(json.dumps(d), end="")')"
hostile "$TAMP"
check_fail "blob altéré : refusé" cl 1 ad-sync
expect_eq "…état local toujours inchangé" "$GOOD" "$(state 1)"
OTHER="$(printf '%s' "$GOODV" | python3 -c 'import json,sys; d=json.load(sys.stdin); d["sha"]="1"*64; print(json.dumps(d), end="")')"
hostile "$OTHER"
check_fail "empreinte annoncée fausse : refusée" cl 1 ad-sync
expect_eq "…état local toujours inchangé" "$GOOD" "$(state 1)"
# chiffré avec une AUTRE clé d'enveloppe (clé de transfert d'un autre cluster)
mkdir -p "$B/alien/etc/bind"; printf 'key "ddi-xfr" {\n    algorithm hmac-sha256;\n    secret "%s";\n};\n' "$(openssl rand -base64 32)" > "$B/alien/etc/bind/ddi-xfr.key"
ALIEN="$(enc_value "$B/alien/etc/bind/ddi-xfr.key" '{"kdcs":[],"realm":"EVIL.TEST"}')"
hostile "$ALIEN"
check_fail "chiffré avec une autre clé : refusé" cl 1 ad-sync
expect_eq "…état local toujours inchangé" "$GOOD" "$(state 1)"
expect_eq "…la console voit l'échec" "failed" "$(sync_state 1)"
# chiffré avec la BONNE clé mais contenu invalide : c'est ddibuntu-ad qui refuse
BAD="$(enc_value "$(R 1)/etc/bind/ddi-xfr.key" '{"kdcs":["dc1;rm"],"realm":"corp test"}')"
hostile "$BAD"
check_fail "état invalide correctement chiffré : refusé par ddibuntu-ad" cl 1 ad-sync
expect_eq "…état local toujours inchangé (rien d'appliqué à moitié)" "$GOOD" "$(state 1)"
BAD2="$(enc_value "$(R 1)/etc/bind/ddi-xfr.key" "{\"keytab\":\"$(base64 -w0 "$W/a.kt")\",\"kdcs\":[],\"realm\":\"OTHER.TEST\"}")"
hostile "$BAD2"
check_fail "keytab d'un autre domaine : refusé" cl 1 ad-sync
expect_eq "…état local toujours inchangé" "$GOOD" "$(state 1)"
check_fail "…et refusé à chaque échéance (jamais republié à la place)" cl 1 ad-sync
expect_eq "…la valeur hostile n'a pas été remplacée par n1" "$BAD2" "$(ectl 1 get "$KEY" --print-value-only)"
echo "== Reprise : une modification légitime écrase la valeur hostile =="
ad 1 configure --realm CORP.TEST --kdc dc5.corp.test >/dev/null 2>&1
check "n1 publie sa modification légitime" cl 1 ad-sync
check "n2 l'applique" cl 2 ad-sync
expect_eq "n2 = n1" "$(state 1)" "$(state 2)"

echo "== Exécutions simultanées (verrou) =="
ad 1 configure --realm CORP.TEST --kdc dc6.corp.test >/dev/null 2>&1
cl 1 ad-sync >/dev/null 2>&1 & p1=$!; cl 1 ad-sync >/dev/null 2>&1 & p2=$!
wait "$p1"; r1=$?; wait "$p2"; r2=$?
expect_eq "deux ad-sync simultanés réussissent" "0 0" "$r1 $r2"
check "n2 applique" cl 2 ad-sync
expect_eq "n2 = n1 après exécutions simultanées" "$(state 1)" "$(state 2)"

finish
