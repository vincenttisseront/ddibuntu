#!/usr/bin/env bash
# Batterie 21 — réglages du cluster avec de VRAIS etcd (TLS mutuel) : 3 nœuds simulés sur 127.0.1.x.
# 1. adresse virtuelle et réseau dédié publiés pour tout le cluster (etcd), appliqués par chaque nœud, interface propre à chaque nœud ;
# 2. renouvellement des certificats : demande signée par l'autorité, la clé privée ne quitte jamais le nœud, etcd recharge le certificat seul,
#    demandes hostiles refusées ; 3. changement d'adresse d'un nœud (arbitre puis nœud de données) sans perdre le quorum, retour arrière si etcd ne redémarre pas ;
#    les autres nœuds ouvrent d'abord leur pare-feu à l'adresse annoncée et accusent réception (journal DDI_FW_LOG par nœud), sinon tout est annulé.
# Patroni/PostgreSQL ne sont pas nécessaires (etcd seul) ; initdb sert seulement aux nœuds « données » qui rejoignent.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
PY=python3.12
PGBIN=/usr/lib/postgresql/16/bin
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl openssl gpg runuser python3 patroni patronictl curl; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
command -v "$PY" >/dev/null 2>&1 || PY=python3
getent passwd etcd >/dev/null && getent passwd postgres >/dev/null || missing="$missing comptes-etcd/postgres"
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
if [ -n "$missing" ]; then note "batterie réglages du cluster non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() {
  pkill -u etcd -f "$B/" 2>/dev/null; pkill -9 -u postgres -f "$B/n" 2>/dev/null
  for _ in $(seq 1 40); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done   # l'arrêt d'etcd n'est pas instantané : la batterie suivante réutilise ses ports
  pkill -9 -u etcd -f "$B/" 2>/dev/null
  sleep 1; if [ -n "${KEEP:-}" ]; then echo "conservé : $B"; else rm -rf "$B"; fi; rm -rf "$T_TMP"
}
trap cleanup EXIT

# « curl » de substitution : si le fichier role-leader existe dans la racine du nœud, l'API Patroni répond « primaire » (sinon : le vrai curl)
mkdir -p "$B/stub"
printf '#!/bin/sh\ncase "$*" in */patroni) if [ -e "$DDI_ROOT/role-leader" ]; then echo "{\\"role\\":\\"master\\"}"; exit 0; fi ;; esac\nexec %s "$@"\n' "$(command -v curl)" > "$B/stub/curl"; chmod 755 "$B/stub/curl"

declare -A IPX=()
ip() { echo "${IPX[$1]:-127.0.1.$1}"; }
R() { echo "$B/n$1"; }
# interfaces simulées : n1 « ens18 ens19 », n2 « ens19 eth1 » (pas d'ens18), n3 (arbitre) « ens19 »
declare -A IFACES=([1]="ens18 ens19" [2]="ens19 eth1" [3]="ens19")
mkwrap() {
  local n="$1" r; r="$(R "$n")"
  printf '#!/bin/sh\nexec env PATH=%s/stub:$PATH DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_ETCD_CMD=%s/etcdcmd%s.sh DDI_IFACES="%s" DDI_VRRP_IFACE=ens19 DDI_FW_LOG=%s/fw%s.log bash %s "$@"\n' "$B" "$r" "$PY" "$B" "$n" "${IFACES[$n]}" "$B" "$n" "$CL" > "$B/cl$n.sh"
  # « echec-redemarrage » : le prochain redémarrage ne relance PAS etcd (simule un etcd qui ne revient pas) ; le suivant fonctionne
  cat > "$B/etcdcmd$n.sh" <<EOF
#!/bin/sh
st() { pkill -u etcd -f $r/ 2>/dev/null; sleep 1; }
go() { ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file $r/etc/ddibuntu-cluster/etcd.yml >>$B/etcd$n.log 2>&1 & ); }
case "\$1" in
  stop) st ;;
  start) go ;;
  restart) st; if [ -e $B/echec-redemarrage$n ]; then rm -f $B/echec-redemarrage$n; else go; fi ;;
esac
EOF
  chmod 755 "$B/cl$n.sh" "$B/etcdcmd$n.sh"
}
cl() { local n="$1"; shift; "$B/cl$n.sh" "$@"; }
clp() { local pw="$1" n="$2"; shift 2; DDI_BUNDLE_PASS="$pw" "$B/cl$n.sh" "$@"; }
mknode() { local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu" "$r/etc/bind" "$r/var/lib/ddibuntu/generated"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"; mkwrap "$1"; }
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { "$B/etcdcmd$1.sh" start; }
stop_etcd() { "$B/etcdcmd$1.sh" stop; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --command-timeout=5s --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
qj() { cl "$1" status 2>/dev/null | python3 -c 'import json,sys; q=json.load(sys.stdin)["etcd"]["quorum"]; print(eval(sys.argv[1]))' "$2"; }
healthy_is() { [ "$(qj "$1" 'q["healthy"]' 2>/dev/null)" = "$2" ]; }
st() { cl "$1" status 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"; }
conf() { grep "^$2=" "$(R "$1")/etc/ddibuntu-cluster/cluster.conf" | cut -d= -f2-; }
peers() { conf "$1" PEERS; }
kaconf() { echo "$(R "$1")/etc/keepalived/keepalived.conf"; }
newnode() {   # newnode NOM N IP RÔLE ORIGINE : lot depuis le nœud ORIGINE, installation et démarrage du nœud N
  local name="$1" n="$2" addr="$3" role="$4" from="$5" pw
  pw="$(cl "$from" bundle --name "$name" --ip "$addr" --role "$role" --out "$B/$name.bundle" 2>"$B/bundle-$name.err")"
  [ -n "$pw" ] && ok "lot $name ($role) créé sur n$from" || { ko "lot $name créé" "$(cat "$B/bundle-$name.err")"; return 1; }
  mknode "$n"; [ "$role" != data ] || initdb_local "$n"
  local a=(--no-activate); [ "$role" != data ] || a+=(--wipe-local-db)
  check "join $name" clp "$pw" "$n" join "$B/$name.bundle" "${a[@]}"
  start_etcd "$n"; wait_for 30 "etcd $name répond" ectl "$n" endpoint status
  check "activate $name" cl "$n" activate
  local k; for k in 1 2 3; do [ -x "$B/cl$k.sh" ] && [ "$k" != "$n" ] && cl "$k" sync >/dev/null 2>&1; done; cl "$n" sync >/dev/null 2>&1; true
}
# signataire : tant qu'il tourne, l'autorité (n1) traite les demandes de certificat (comme son minuteur, mais toutes les 2 s)
SIGNER=""
start_signer() { ( while true; do "$B/cl1.sh" sign-requests >/dev/null 2>&1; sleep 2; done ) & SIGNER=$!; }
stop_signer() { [ -z "$SIGNER" ] || { kill "$SIGNER" 2>/dev/null; wait "$SIGNER" 2>/dev/null; SIGNER=""; }; }
# observateurs : pendant un changement d'adresse, tous les AUTRES nœuds synchronisent en boucle (comme leur minuteur, toutes les secondes) :
# ils ouvrent leur pare-feu à l'adresse annoncée, accusent réception, et le nœud d'autorité signe. start_syncers NŒUD_QUI_BOUGE
SYNCER=""
start_syncers() {
  local skip=" $* "; rm -f "$B/stop-syncers"
  ( while [ ! -e "$B/stop-syncers" ]; do for k in 1 2 3; do case "$skip" in *" $k "*) continue ;; esac; "$B/cl$k.sh" sync >/dev/null 2>&1; done; sleep 1; done ) & SYNCER=$!
}
stop_syncers() { [ -z "$SYNCER" ] || { touch "$B/stop-syncers"; wait "$SYNCER" 2>/dev/null; SYNCER=""; }; }   # laisse finir la synchronisation en cours (jamais interrompue)
fwlast() { tail -n 1 "$B/fw$1.log" 2>/dev/null; }          # dernière règle appliquée (journal) du nœud N
fwlines() { wc -l < "$B/fw$1.log" 2>/dev/null || echo 0; }
ack() { ectl 1 get "/ddibuntu-cluster/moved-ack/$1/$2" --print-value-only 2>/dev/null; }   # accusé du nœud $2 pour le déplacement de $1
fwx() { [ -e "$(R "$1")/var/lib/ddibuntu/cluster/fw-extra" ] && echo yes || echo no; }
serial() { openssl x509 -in "$(R "$1")/etc/ddibuntu-cluster/pki/node.crt" -noout -serial | cut -d= -f2; }
etcd_serial() {   # numéro de série du certificat que PRÉSENTE réellement etcd du nœud N (rechargé à chaque connexion)
  local p; p="$(R "$2")/etc/ddibuntu-cluster/pki"
  echo | openssl s_client -connect "$(ip "$1"):2379" -CAfile "$p/ca.crt" -cert "$p/node.crt" -key "$p/node.key" 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}

echo "== Cluster : 3 etcd réels (n1 autorité + n2 données, n3 arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
check "init n1 (sans adresse virtuelle)" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
newnode n2 2 "$(ip 2)" data 1
wait_for 60 "etcd : les deux membres sont sains" ectl 1 endpoint health --cluster
sleep 8   # etcd n'ajoute un membre que si tous les autres sont connectés depuis plus de 5 s
newnode n3 3 "$(ip 3)" witness 1
wait_for 60 "etcd : trois membres sains" ectl 1 endpoint health --cluster
expect_eq "3 voix, 3 saines, tolérance 1" "3 3 1" "$(qj 1 '"%d %d %d" % (q["voters"], q["healthy"], q["tolerance"])')"

echo "== 1. Adresse virtuelle : publiée une fois, appliquée par chaque nœud =="
expect_eq "aucun réglage publié au départ" "null" "$(cl 1 settings | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["published"]))')"
expect_eq "aucune adresse virtuelle, pas de configuration Keepalived" "no" "$([ -e "$(kaconf 1)" ] && echo yes || echo no)"
check_fail "set-vip : adresse invalide refusée" cl 1 set-vip --vip 192.0.2.10 --iface ens18
check_fail "set-vip : préfixe hors plage refusé" cl 1 set-vip --vip 192.0.2.10/33 --iface ens18
check_fail "set-vip : adresse hostile refusée" cl 1 set-vip --vip '192.0.2.10/24;reboot' --iface ens18
check_fail "set-vip : interface inconnue de ce serveur refusée" cl 1 set-vip --vip 192.0.2.10/24 --iface ens99
check_fail "set-vip : interface hostile refusée" cl 1 set-vip --vip 192.0.2.10/24 --iface 'ens18;x'
check_fail "set-vip : VRID 0 refusé" cl 1 set-vip --vip 192.0.2.10/24 --iface ens18 --vrid 0
check_fail "set-vip : VRID 256 refusé" cl 1 set-vip --vip 192.0.2.10/24 --iface ens18 --vrid 256
check_fail "set-vip : adresse d'un nœud refusée" cl 1 set-vip --vip "$(ip 2)/24" --iface ens18
check_fail "set-vip : option inconnue refusée" cl 1 set-vip --vip 192.0.2.10/24 --iface ens18 --pas-une-option 1
check_fail "set-vip : refusé sur l'arbitre" cl 3 set-vip --vip 192.0.2.10/24 --iface ens19
expect_eq "rien n'a été publié par les refus" "null" "$(cl 1 settings | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["published"]))')"
check "set-vip 192.0.2.10/24 sur ens18, VRID 77" cl 1 set-vip --vip 192.0.2.10/24 --iface ens18 --vrid 77
expect_eq "n1 : configuration locale alignée" "192.0.2.10/24 ens18 77 1" "$(conf 1 VIP) $(conf 1 VIP_IFACE) $(conf 1 VIP_VRID) $(conf 1 SETTINGS_REV)"
expect_grep "n1 : Keepalived écrit (VRID, adresse, interface)" 'virtual_router_id 77' "$(kaconf 1)"
expect_grep "n1 : adresse virtuelle sur la bonne interface" '192\.0\.2\.10/24 dev ens18' "$(kaconf 1)"
expect_eq "réglages publiés dans etcd (révision 1)" "1 192.0.2.10/24 77 ens18" "$(ectl 1 get /ddibuntu-cluster/settings --print-value-only | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["rev"], d["vip"], d["vrid"], d["iface"])')"
expect_eq "n3 (arbitre) lit la même valeur" "$(ectl 1 get /ddibuntu-cluster/settings --print-value-only)" "$(ectl 3 get /ddibuntu-cluster/settings --print-value-only)"
# n2 n'a pas ens18 : réglages non appliqués, dit clairement, rien de cassé
OUT="$(cl 2 sync 2>&1)"; RC=$?
expect_eq "n2 : la synchronisation réussit malgré l'interface absente" "0" "$RC"
expect_eq "n2 : l'avertissement désigne l'interface et la commande de correction" "True" "$(printf '%s' "$OUT" | grep -q "ens18.*n'existe pas sur ce nœud" && printf '%s' "$OUT" | grep -q 'vip-iface' && echo True || echo False)"
expect_eq "n2 : configuration inchangée" "  0" "$(conf 2 VIP) $(conf 2 VIP_IFACE) $(conf 2 SETTINGS_REV)"
expect_eq "n2 : toujours pas de Keepalived" "no" "$([ -e "$(kaconf 2)" ] && echo yes || echo no)"
check_fail "vip-iface : interface inconnue refusée sur n2" cl 2 vip-iface ens18
check_fail "vip-iface : refusé sur l'arbitre" cl 3 vip-iface ens19
check "vip-iface eth1 sur n2" cl 2 vip-iface eth1
check "n2 : sync applique les réglages avec SON interface" cl 2 sync
expect_eq "n2 : adresse commune, interface propre" "192.0.2.10/24 eth1 77 1" "$(conf 2 VIP) $(conf 2 VIP_IFACE) $(conf 2 VIP_VRID) $(conf 2 SETTINGS_REV)"
expect_grep "n2 : Keepalived sur eth1" '192\.0\.2\.10/24 dev eth1' "$(kaconf 2)"
expect_grep "n2 : même VRID" 'virtual_router_id 77' "$(kaconf 2)"
check "n3 : sync (arbitre)" cl 3 sync
expect_eq "n3 : adresse et révision alignées, pas de Keepalived" "192.0.2.10/24 1 no" "$(conf 3 VIP) $(conf 3 SETTINGS_REV) $([ -e "$(kaconf 3)" ] && echo yes || echo no)"
OUT="$(cl 2 sync 2>&1)"
expect_eq "n2 : une seconde synchronisation n'applique rien" "0" "$(printf '%s' "$OUT" | grep -c 'réglages du cluster appliqués')"
expect_eq "état du cluster : adresse virtuelle et réglages" "192.0.2.10/24 1 1" "$(st 2 '"%s %d %d" % (d["vip"]["address"], d["settings"]["published"]["rev"], d["settings"]["applied"]["rev"])')"

echo "== 1b. Valeurs piégées dans etcd : ignorées =="
for bad in 'pas du json' '[1,2]' '{"rev":"x"}' '{"rev":9,"vip":"1.2.3.4/99"}' '{"rev":9,"vip":"192.0.2.99/24","vrid":300}' '{"rev":9,"vip":"192.0.2.99/24","iface":"ens18;reboot"}' '{"rev":9,"vip":"192.0.2.99/24","extra":1}' '{"rev":9,"net":"10.0.0.0/8; drop"}' '{"rev":-1}' '{"rev":true}'; do
  printf '%s' "$bad" | ectl 1 put /ddibuntu-cluster/settings >/dev/null
  cl 2 sync >/dev/null 2>&1; cl 3 sync >/dev/null 2>&1
  expect_eq "réglage piégé ignoré (${bad:0:36})" "192.0.2.10/24 1" "$(conf 2 VIP) $(conf 2 SETTINGS_REV)"
done
printf '{"rev":1,"vip":"192.0.2.10/24","vrid":77,"iface":"ens18","net":"","at":1,"by":"n1"}' | ectl 1 put /ddibuntu-cluster/settings >/dev/null   # valeur valide rétablie

echo "== 1c. Retrait de l'adresse virtuelle =="
check_fail "clear-vip refusé sur l'arbitre" cl 3 clear-vip
check "clear-vip sur n1" cl 1 clear-vip
expect_eq "n1 : adresse retirée, révision 2" " 2" "$(conf 1 VIP) $(conf 1 SETTINGS_REV)"
expect_eq "n1 : configuration Keepalived retirée" "no" "$([ -e "$(kaconf 1)" ] && echo yes || echo no)"
check "n2 : sync" cl 2 sync
expect_eq "n2 : adresse retirée et Keepalived supprimé" " 2 no" "$(conf 2 VIP) $(conf 2 SETTINGS_REV) $([ -e "$(kaconf 2)" ] && echo yes || echo no)"
check "n3 : sync" cl 3 sync
expect_eq "n3 : adresse retirée" " 2" "$(conf 3 VIP) $(conf 3 SETTINGS_REV)"
check_fail "clear-vip répété refusé (aucune adresse)" cl 1 clear-vip
check "set-vip de nouveau (autre adresse, interface propre à n2 conservée)" cl 1 set-vip --vip 192.0.2.20/24 --iface ens18
check "n2 : sync" cl 2 sync
expect_eq "n2 : nouvelle adresse, interface eth1 conservée, révision 3" "192.0.2.20/24 eth1 3" "$(conf 2 VIP) $(conf 2 VIP_IFACE) $(conf 2 SETTINGS_REV)"
expect_grep "n2 : Keepalived à jour" '192\.0\.2\.20/24 dev eth1' "$(kaconf 2)"

echo "== 1d. Réseau dédié =="
expect_eq "réseau actuel" "127.0.0.0/8" "$(conf 1 REPL_NET)"
check_fail "set-net : réseau invalide refusé" cl 1 set-net 127.0.0.0
check_fail "set-net : réseau hostile refusé" cl 1 set-net '127.0.0.0/16;x'
OUT="$(cl 1 set-net 10.0.0.0/8 2>&1)"; RC=$?
expect_eq "set-net : réseau qui exclut des nœuds refusé" "1" "$RC"
expect_eq "…et les nœuds hors réseau sont nommés" "True" "$(printf '%s' "$OUT" | grep -q 'n1=127.0.1.1' && printf '%s' "$OUT" | grep -q 'n3=127.0.1.3' && echo True || echo False)"
expect_eq "…rien n'a été modifié" "127.0.0.0/8 3" "$(conf 1 REPL_NET) $(conf 1 SETTINGS_REV)"
check "set-net 127.0.0.0/16" cl 1 set-net 127.0.0.0/16
expect_eq "n1 : réseau mis à jour, révision 4, adresse virtuelle conservée" "127.0.0.0/16 4 192.0.2.20/24" "$(conf 1 REPL_NET) $(conf 1 SETTINGS_REV) $(conf 1 VIP)"
expect_grep "n1 : pg_hba de Patroni suit le réseau" 'hostssl replication replicator 127\.0\.0\.0/16 cert' "$(R 1)/etc/patroni/config.yml"
check "n2 : sync" cl 2 sync
check "n3 : sync" cl 3 sync
expect_eq "n2 : réseau et révision alignés" "127.0.0.0/16 4" "$(conf 2 REPL_NET) $(conf 2 SETTINGS_REV)"
expect_grep "n2 : pg_hba de Patroni suit le réseau" 'hostssl replication replicator 127\.0\.0\.0/16 cert' "$(R 2)/etc/patroni/config.yml"
expect_eq "n3 : réseau aligné" "127.0.0.0/16 4" "$(conf 3 REPL_NET) $(conf 3 SETTINGS_REV)"
expect_eq "l'adresse virtuelle n'a pas été touchée par set-net" "192.0.2.20/24" "$(conf 2 VIP)"
expect_eq "réglages : publiés = appliqués" "4 4" "$(cl 3 settings | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["published"]["rev"], d["applied"]["rev"])')"


echo "== 2. Renouvellement des certificats : la clé reste sur le nœud, l'autorité signe =="
S1="$(serial 1)"; S2="$(serial 2)"; S3="$(serial 3)"
expect_eq "cert-status n2 : environ 825 jours, aucune demande en cours" "True False" "$(cl 2 cert-status | python3 -c 'import json,sys; d=json.load(sys.stdin); print(800 < d["node"]["daysLeft"] <= 825, d["pending"])')"
expect_eq "cert-status : l'autorité a plus de 3000 jours" "True" "$(cl 2 cert-status | python3 -c 'import json,sys; print(json.load(sys.stdin)["ca"]["daysLeft"] > 3000)')"
expect_eq "état du cluster : bloc pki présent" "True" "$(st 2 'd["pki"]["node"]["daysLeft"] > 800')"
check "renew-cert sans nécessité : rien à faire" cl 2 renew-cert
expect_eq "…certificat inchangé" "$S2" "$(serial 2)"
check_fail "renew-cert : option inconnue refusée" cl 2 renew-cert --nope
check_fail "renew-cert : --wait invalide refusé" cl 2 renew-cert --force --wait 'x;y'
check "renew-cert --force sur n2 : demande publiée" cl 2 renew-cert --force
expect_eq "demande présente dans etcd" "/ddibuntu-cluster/csr/n2" "$(ectl 1 get /ddibuntu-cluster/csr/n2 --keys-only | head -1)"
expect_eq "…aucune clé privée dans etcd (demandes, certificats, réglages)" "0" "$(ectl 1 get --prefix /ddibuntu-cluster/ --print-value-only | grep -c 'PRIVATE KEY')"
expect_eq "n2 : demande en cours annoncée par l'état" "True" "$(st 2 'd["pki"]["pending"]')"
expect_eq "n2 : la nouvelle clé reste sur n2, lisible par root et son groupe seulement" "600" "$(stat -c %a "$(R 2)/etc/ddibuntu-cluster/pki/renew/node.key")"
check "n2 : sync avant signature (rien ne change)" cl 2 sync
expect_eq "…ancien certificat toujours en service" "$S2" "$(serial 2)"
check "n3 (non autorité) : sign-requests sans effet" cl 3 sign-requests
expect_eq "…la demande de n2 n'est pas traitée par un non-autorité" "/ddibuntu-cluster/csr/n2" "$(ectl 1 get /ddibuntu-cluster/csr/n2 --keys-only | head -1)"
check "n1 (autorité) : sign-requests" cl 1 sign-requests
expect_eq "demande consommée" "" "$(ectl 1 get /ddibuntu-cluster/csr/n2 --keys-only | head -1)"
expect_eq "certificat déposé pour n2" "/ddibuntu-cluster/certs/n2" "$(ectl 1 get /ddibuntu-cluster/certs/n2 --keys-only | head -1)"
check "n2 : sync installe le certificat" cl 2 sync
S2B="$(serial 2)"
expect_eq "n2 : nouveau numéro de série" "True" "$([ -n "$S2B" ] && [ "$S2B" != "$S2" ] && echo True || echo False)"
expect_eq "n2 : certificat signé par l'autorité" "OK" "$(openssl verify -CAfile "$(R 2)/etc/ddibuntu-cluster/pki/ca.crt" "$(R 2)/etc/ddibuntu-cluster/pki/node.crt" 2>&1 | grep -o 'OK$')"
expect_eq "n2 : la clé correspond au certificat" "True" "$([ "$(openssl x509 -in "$(R 2)/etc/ddibuntu-cluster/pki/node.crt" -noout -pubkey)" = "$(openssl pkey -in "$(R 2)/etc/ddibuntu-cluster/pki/node.key" -pubout)" ] && echo True || echo False)"
expect_eq "n2 : adresses du certificat (réseau dédié + boucle locale)" "True" "$(openssl x509 -in "$(R 2)/etc/ddibuntu-cluster/pki/node.crt" -noout -ext subjectAltName | grep -q "IP Address:$(ip 2)" && openssl x509 -in "$(R 2)/etc/ddibuntu-cluster/pki/node.crt" -noout -ext subjectAltName | grep -q 'IP Address:127.0.0.1' && echo True || echo False)"
expect_eq "n2 : demande terminée, dossier de travail effacé" "no False" "$([ -e "$(R 2)/etc/ddibuntu-cluster/pki/renew" ] && echo yes || echo no) $(st 2 'd["pki"]["pending"]')"
expect_eq "certificat consommé : plus rien dans etcd" "" "$(ectl 1 get /ddibuntu-cluster/certs/n2 --keys-only | head -1)"
expect_eq "n2 : clé en 0640, certificat en 0644" "640 644" "$(stat -c %a "$(R 2)/etc/ddibuntu-cluster/pki/node.key") $(stat -c %a "$(R 2)/etc/ddibuntu-cluster/pki/node.crt")"
expect_eq "n2 : ancien certificat conservé (sans clé)" "1" "$(ls "$(R 2)/etc/ddibuntu-cluster/pki/old" | wc -l | tr -d ' ')"
expect_eq "etcd de n2 PRÉSENTE le nouveau certificat (rechargé sans redémarrage)" "$S2B" "$(etcd_serial 2 2)"
check "etcd : n2 joint les autres membres avec son nouveau certificat" ectl 2 endpoint health --cluster
expect_eq "quorum intact : 3 voix saines" "3" "$(qj 1 'q["healthy"]')"

echo "-- l'autorité renouvelle SON certificat"
check "renew-cert --force sur n1 (autorité)" cl 1 renew-cert --force
S1B="$(serial 1)"
expect_eq "n1 : nouveau numéro de série" "True" "$([ "$S1B" != "$S1" ] && echo True || echo False)"
expect_eq "etcd de n1 présente le nouveau certificat" "$S1B" "$(etcd_serial 1 1)"
expect_eq "n1 : signé par la même autorité" "OK" "$(openssl verify -CAfile "$(R 1)/etc/ddibuntu-cluster/pki/ca.crt" "$(R 1)/etc/ddibuntu-cluster/pki/node.crt" 2>&1 | grep -o 'OK$')"
check "etcd : tout le cluster joint n1 avec les nouveaux certificats" ectl 3 endpoint health --cluster

echo "-- l'arbitre attend la signature (--wait)"
start_signer
check "renew-cert --force --wait 60 sur n3 (signature par l'autorité en cours de route)" cl 3 renew-cert --force --wait 60
stop_signer
S3B="$(serial 3)"
expect_eq "n3 : nouveau numéro de série présenté par son etcd" "True" "$([ "$S3B" != "$S3" ] && [ "$(etcd_serial 3 3)" = "$S3B" ] && echo True || echo False)"
check "etcd : trois membres sains après trois renouvellements" ectl 1 endpoint health --cluster

echo "-- renouvellement automatique avant l'échéance"
check "n2 : demande forcée" cl 2 renew-cert --force
check "n1 : signature d'un certificat COURT (20 jours, essai)" env DDI_CERT_DAYS=20 "$B/cl1.sh" sign-requests
check "n2 : sync installe le certificat court" cl 2 sync
expect_eq "n2 : il reste au plus 20 jours" "True" "$(cl 2 cert-status | python3 -c 'import json,sys; d=json.load(sys.stdin); print(0 < d["node"]["daysLeft"] <= 20, d["pending"])' | sed 's/ False//')"
OUT="$(cl 2 sync 2>&1)"
expect_eq "n2 : la synchronisation suivante renouvelle SEULE (moins de 60 jours)" "True" "$(printf '%s' "$OUT" | grep -q 'renouvellement automatique' && st 2 'd["pki"]["pending"]')"
REV1="$(ectl 1 get /ddibuntu-cluster/csr/n2 -w json | python3 -c 'import json,sys; print(json.load(sys.stdin)["kvs"][0]["mod_revision"])')"
cl 2 sync >/dev/null 2>&1; cl 2 sync >/dev/null 2>&1
expect_eq "…une seule demande à la fois (pas de nouvelle demande à chaque minute)" "$REV1" "$(ectl 1 get /ddibuntu-cluster/csr/n2 -w json | python3 -c 'import json,sys; print(json.load(sys.stdin)["kvs"][0]["mod_revision"])')"
check "n1 : signature (825 jours)" cl 1 sign-requests
check "n2 : sync installe le certificat long" cl 2 sync
expect_eq "n2 : certificat de nouveau valable plus de 800 jours, plus de demande" "True False" "$(cl 2 cert-status | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["node"]["daysLeft"] > 800, d["pending"])')"
check "n2 : sync suivante : rien à renouveler" cl 2 sync
expect_eq "…aucune nouvelle demande" "" "$(ectl 1 get /ddibuntu-cluster/csr/n2 --keys-only | head -1)"

echo "-- demandes hostiles : refusées et supprimées par l'autorité"
mkcsr() {   # mkcsr CN TYPE [OPTION…] → CSR PEM ; TYPE = ec | rsa
  local cn="$1" ty="$2"; shift 2; local d; d="$(mktemp -d)"
  if [ "$ty" = rsa ]; then openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/k" 2>/dev/null; else openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$d/k" 2>/dev/null; fi
  openssl req -new -key "$d/k" -subj "/CN=$cn" "$@" 2>/dev/null; rm -rf "$d"
}
put_csr() {   # put_csr CLÉ IP CSR : écrit une demande au format attendu
  CSR="$3" IP="$2" python3 -c 'import json,os,time; print(json.dumps({"csr": os.environ["CSR"], "ip": os.environ["IP"], "at": int(time.time())}, separators=(",", ":")))' | ectl 1 put "/ddibuntu-cluster/csr/$1" >/dev/null
}
refused() {   # refused LIBELLÉ CLÉ : après sign-requests, ni demande ni certificat
  local out; out="$(cl 1 sign-requests 2>&1)"
  expect_eq "$1" "|" "$(ectl 1 get "/ddibuntu-cluster/csr/$2" --keys-only | head -1)|$(ectl 1 get "/ddibuntu-cluster/certs/$2" --keys-only | head -1)"
  LAST_OUT="$out"
}
put_csr n2 "$(ip 2)" "$(mkcsr node-n3 ec)"; refused "sujet d'un autre nœud refusé" n2
expect_eq "…le motif est journalisé" "True" "$(printf '%s' "$LAST_OUT" | grep -q 'non conforme' && echo True || echo False)"
put_csr n2 "$(ip 2)" "$(mkcsr node-n2 rsa)"; refused "clé RSA refusée (EC P-256 exigé)" n2
put_csr n2 "$(ip 2)" "$(mkcsr node-n2 ec -addext 'subjectAltName=IP:10.9.9.9')"; refused "demande qui réclame ses propres adresses (extensions) refusée" n2
put_csr n2 "$(ip 3)" "$(mkcsr node-n2 ec)"; refused "demande d'une adresse qui n'est pas celle du nœud refusée" n2
expect_eq "…le motif est journalisé" "True" "$(printf '%s' "$LAST_OUT" | grep -q "ni celle du registre ni celle d'un déplacement" && echo True || echo False)"
put_csr n9 "$(ip 9)" "$(mkcsr node-n9 ec)"; refused "nœud inconnu du registre refusé" n9
printf 'pas du json' | ectl 1 put /ddibuntu-cluster/csr/n2 >/dev/null; refused "contenu non JSON supprimé" n2
printf '{"csr":"x","ip":"127.0.1.2"}' | ectl 1 put /ddibuntu-cluster/csr/n2 >/dev/null; refused "demande tronquée supprimée" n2
CSRX="$(mkcsr node-n2 ec)"; printf '%s' "{\"csr\":$(printf '%s' "$CSRX" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),\"ip\":\"$(ip 2)\",\"at\":1,\"extra\":1}" | ectl 1 put /ddibuntu-cluster/csr/n2 >/dev/null; refused "clé inconnue dans la demande refusée" n2
printf '%s' "{\"csr\":$(printf '%s' "$CSRX" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),\"ip\":\"127.0.1.2; reboot\",\"at\":1}" | ectl 1 put /ddibuntu-cluster/csr/n2 >/dev/null; refused "adresse hostile refusée" n2
put_csr '../../etc' "$(ip 2)" "$CSRX"; out="$(cl 1 sign-requests 2>&1)"
expect_eq "nom de clé hostile ignoré (rien de signé)" "" "$(ectl 1 get --prefix /ddibuntu-cluster/certs/ --keys-only | grep -v '^$' | head -1)"
ectl 1 del --prefix /ddibuntu-cluster/csr/ >/dev/null
expect_eq "après les refus : certificat de n2 intact" "True" "$([ "$(etcd_serial 2 2)" = "$(serial 2)" ] && echo True || echo False)"

echo "-- certificat truqué déposé dans etcd : refusé par le nœud"
check "n2 : nouvelle demande" cl 2 renew-cert --force
RD="$(R 2)/etc/ddibuntu-cluster/pki/renew"
ROGUE="$(mktemp -d)"; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$ROGUE/ca.key" 2>/dev/null
openssl req -x509 -new -key "$ROGUE/ca.key" -sha256 -days 30 -subj "/CN=autorite-pirate" -out "$ROGUE/ca.crt" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:%s,IP:127.0.0.1\n' "$(ip 2)" > "$ROGUE/ext"
openssl x509 -req -in "$RD/node.csr" -CA "$ROGUE/ca.crt" -CAkey "$ROGUE/ca.key" -CAcreateserial -days 30 -extfile "$ROGUE/ext" -out "$ROGUE/n.crt" 2>/dev/null
FORGED="$(CRT="$(cat "$ROGUE/n.crt")" SHA="$(cat "$RD/csr.sha")" python3 -c 'import json,os; print(json.dumps({"cert": os.environ["CRT"], "for": os.environ["SHA"], "at": 1}, separators=(",", ":")))')"
printf '%s' "$FORGED" | ectl 1 put /ddibuntu-cluster/certs/n2 >/dev/null
S2C="$(serial 2)"
OUT="$(cl 2 sync 2>&1)"
expect_eq "certificat d'une autre autorité refusé, ancien certificat conservé" "$S2C" "$(serial 2)"
expect_eq "…le refus est journalisé et la demande abandonnée" "True no" "$(printf '%s' "$OUT" | grep -q 'certificat reçu refusé' && echo True || echo False) $([ -e "$RD" ] && echo yes || echo no)"
expect_eq "…etcd de n2 fonctionne toujours" "True" "$(ectl 2 endpoint health >/dev/null 2>&1 && echo True || echo False)"
ectl 1 del /ddibuntu-cluster/certs/n2 >/dev/null
check "n2 : nouvelle demande" cl 2 renew-cert --force
printf '%s' "$FORGED" | python3 -c 'import json,sys; d=json.load(sys.stdin); d["for"]="0"*64; print(json.dumps(d))' | ectl 1 put /ddibuntu-cluster/certs/n2 >/dev/null
cl 2 sync >/dev/null 2>&1
expect_eq "certificat destiné à une AUTRE demande ignoré : n2 attend toujours le sien" "True" "$(st 2 'd["pki"]["pending"]')"
check "n1 : signe la vraie demande" cl 1 sign-requests
check "n2 : installe le vrai certificat" cl 2 sync
expect_eq "n2 : certificat remplacé par celui de l'autorité" "True" "$([ "$(serial 2)" != "$S2C" ] && [ "$(etcd_serial 2 2)" = "$(serial 2)" ] && echo True || echo False)"
rm -rf "$ROGUE"
expect_eq "quorum : 3 voix saines" "3" "$(qj 1 'q["healthy"]')"

echo "== 3. Changement d'adresse d'un nœud =="
ORIG_PEERS="$(peers 1)"
expect_eq "pairs avant : trois nœuds aux adresses d'origine" "n1=127.0.1.1:data n2=127.0.1.2:data n3=127.0.1.3:witness" "$ORIG_PEERS"
NOW="$(date +%s)"
echo "-- refus (rien n'est modifié)"
check_fail "change-ip sans --yes refusé" cl 2 change-ip --ip 127.0.2.2
check_fail "change-ip sans adresse refusé" cl 2 change-ip --yes
check_fail "change-ip : adresse invalide refusée" cl 2 change-ip --ip 127.0.2 --yes
check_fail "change-ip : adresse hostile refusée" cl 2 change-ip --ip '127.0.2.2;reboot' --yes
check_fail "change-ip : option inconnue refusée" cl 2 change-ip --ip 127.0.2.2 --yes --autre 1
check_fail "change-ip : adresse inchangée refusée" cl 2 change-ip --ip "$(ip 2)" --yes
OUT="$(cl 2 change-ip --ip "$(ip 1)" --yes 2>&1)"; RC=$?
expect_eq "change-ip : adresse d'un autre nœud refusée, nœud nommé" "1 True" "$RC $(printf '%s' "$OUT" | grep -q 'déjà utilisée par le nœud n1' && echo True || echo False)"
OUT="$(cl 2 change-ip --ip 10.1.1.1 --yes 2>&1)"; RC=$?
expect_eq "change-ip : adresse hors du réseau dédié refusée (set-net indiqué)" "1 True" "$RC $(printf '%s' "$OUT" | grep -q 'set-net' && echo True || echo False)"
touch "$(R 2)/role-leader"
OUT="$(cl 2 change-ip --ip 127.0.2.2 --yes 2>&1)"; RC=$?
expect_eq "change-ip : refusé sur le primaire PostgreSQL (basculer d'abord)" "1 True" "$RC $(printf '%s' "$OUT" | grep -q 'primaire PostgreSQL' && echo True || echo False)"
rm -f "$(R 2)/role-leader"
stop_etcd 3
wait_for 40 "n3 arrêté : etcd n'a plus que 2 voix saines" healthy_is 1 2
OUT="$(cl 2 change-ip --ip 127.0.2.2 --yes 2>&1)"; RC=$?
expect_eq "change-ip : refusé quand le quorum n'a pas de marge" "1 True" "$RC $(printf '%s' "$OUT" | grep -q "n'a pas de marge" && echo True || echo False)"
start_etcd 3; wait_for 60 "n3 revenu : trois membres sains" ectl 1 endpoint health --cluster
expect_eq "refus sans effet : adresses, annonces et inscriptions intactes" "$ORIG_PEERS||127.0.1.2:data" "$(peers 2)|$(ectl 1 get --prefix /ddibuntu-cluster/moved/ --keys-only | head -1)|$(ectl 1 get /ddibuntu-cluster/nodes/n2 --print-value-only)"

echo "-- l'autorité ne signe pas à temps : rien n'est modifié ; la synchronisation automatique n'interfère pas (verrou du nœud)"
( env DDI_CHANGEIP_WAIT=12 "$B/cl3.sh" change-ip --ip 127.0.2.3 --yes > "$B/ci-timeout.out" 2>&1; echo "rc=$?" >> "$B/ci-timeout.out" ) &
CIPID=$!
sleep 4
OUT="$(cl 3 sync 2>&1)"; RC=$?
expect_eq "sync pendant un changement d'adresse : rend la main sans rien faire" "0 True" "$RC $(printf '%s' "$OUT" | grep -q 'autre opération du cluster' && echo True || echo False)"
wait "$CIPID"
expect_eq "change-ip abandonné proprement (délai dépassé)" "True True" "$(grep -q "pas signé le certificat à temps" "$B/ci-timeout.out" && echo True || echo False) $(grep -q '^rc=1' "$B/ci-timeout.out" && echo True || echo False)"
expect_eq "…adresse, annonce, demande et dossier de travail : rien ne reste" "127.0.1.3||no" "$(conf 3 NODE_IP)|$(ectl 1 get --prefix /ddibuntu-cluster/moved/ --keys-only | head -1)$(ectl 1 get /ddibuntu-cluster/csr/n3 --keys-only | head -1)|$([ -e "$(R 3)/etc/ddibuntu-cluster/pki/renew" ] && echo yes || echo no)"
expect_eq "…etcd de n3 inchangé" "True" "$(ectl 3 endpoint health >/dev/null 2>&1 && echo True || echo False)"
check "une fois l'opération terminée, sync reprend normalement" cl 3 sync

echo "-- annonces de déplacement hostiles : ignorées par les autres nœuds"
mv_put() { printf '%s' "$2" | ectl 1 put "/ddibuntu-cluster/moved/$1" >/dev/null; }
mv_check() {   # mv_check LIBELLÉ : après synchronisation de n1 et n2, les pairs n'ont pas bougé
  cl 1 sync >/dev/null 2>&1; cl 2 sync >/dev/null 2>&1
  expect_eq "$1" "$ORIG_PEERS|$ORIG_PEERS" "$(peers 1)|$(peers 2)"
}
mv_put n3 'pas du json'; mv_check "annonce non JSON ignorée"
mv_put n3 "{\"from\":\"127.0.1.3\",\"to\":\"127.0.2.3\",\"at\":$NOW}"; mv_check "annonce sans inscription correspondante ignorée (le registre dit encore 127.0.1.3)"
mv_put n3 "{\"from\":\"127.0.7.7\",\"to\":\"127.0.1.3\",\"at\":$NOW}"; mv_check "annonce d'une ancienne adresse inconnue ignorée"
mv_put n3 "{\"from\":\"127.0.1.3\",\"to\":\"127.0.2.3; reboot\",\"at\":$NOW}"; mv_check "annonce à adresse hostile ignorée"
mv_put n3 "{\"from\":\"127.0.1.3\",\"to\":\"127.0.2.3\",\"at\":$NOW,\"extra\":1}"; mv_check "annonce avec clé inconnue sans effet sur les pairs"
mv_put n1 "{\"from\":\"127.0.1.1\",\"to\":\"127.0.9.9\",\"at\":$NOW}"; mv_check "annonce pour le nœud lui-même / adresse non inscrite ignorée"
ectl 1 put /ddibuntu-cluster/nodes/n3 '127.0.2.3:witness' >/dev/null     # un attaquant réécrit le registre…
mv_put n3 "{\"from\":\"127.0.1.3\",\"to\":\"127.0.2.3\",\"at\":1}"; mv_check "annonce PÉRIMÉE (plus d'un jour) ignorée même si le registre correspond"
mv_put n3 "{\"from\":\"127.0.1.3\",\"to\":\"127.0.2.3\",\"at\":$((NOW + 100000))}"; mv_check "annonce datée du futur ignorée"
ectl 1 del /ddibuntu-cluster/moved/n3 >/dev/null
mv_check "registre réécrit SANS annonce : adresse non remplacée"
OUT="$(cl 1 sync 2>&1)"
expect_eq "…l'avertissement le dit" "True" "$(printf '%s' "$OUT" | grep -q '« n3 » figure déjà avec une autre adresse' && echo True || echo False)"
ectl 1 del /ddibuntu-cluster/moved/n1 >/dev/null
cl 3 sync >/dev/null 2>&1
expect_eq "n3 se réinscrit à sa vraie adresse" "127.0.1.3:witness" "$(ectl 1 get /ddibuntu-cluster/nodes/n3 --print-value-only)"
expect_eq "aucune annonce restante" "" "$(ectl 1 get --prefix /ddibuntu-cluster/moved/ --keys-only | head -1)"

echo "-- pare-feu : une adresse annoncée n'est ouverte que dans le réseau dédié, avec accusé de réception ; refermée avec l'annonce"
expect_eq "avant toute annonce : pas d'ouverture supplémentaire" "no no" "$(fwx 1) $(fwx 3)"
mv_put n2 "{\"from\":\"127.0.1.2\",\"to\":\"10.9.9.9\",\"at\":$NOW}"
cl 1 sync >/dev/null 2>&1; cl 3 sync >/dev/null 2>&1
expect_eq "annonce vers une adresse HORS du réseau dédié : pare-feu intact, aucun accusé" "no no 0 |" "$(fwx 1) $(fwx 3) $(grep -c '10\.9\.9\.9' "$B/fw1.log") $(ack n2 n1)|$(ack n2 n3)"
mv_put n2 "{\"from\":\"127.0.1.2\",\"to\":\"127.0.9.9\",\"at\":$NOW}"
FW1="$(fwlines 1)"; cl 1 sync >/dev/null 2>&1
expect_eq "annonce valide (n2 → 127.0.9.9) : n1 ouvre l'adresse annoncée EN PLUS des pairs" "CLUSTER_PEERS=127.0.1.2,127.0.1.3,127.0.9.9 yes" "$(fwlast 1) $(fwx 1)"
expect_eq "…puis accuse réception (valeur = nouvelle adresse)" "127.0.9.9" "$(ack n2 n1)"
cl 1 sync >/dev/null 2>&1
expect_eq "…une seconde synchronisation ne touche ni au pare-feu ni à l'accusé" "$((FW1 + 1))" "$(fwlines 1)"
cl 3 sync >/dev/null 2>&1
expect_eq "n3 (arbitre) accuse aussi réception" "127.0.9.9 CLUSTER_PEERS=127.0.1.1,127.0.1.2,127.0.9.9" "$(ack n2 n3) $(fwlast 3)"
expect_eq "…aucun pair n'a bougé" "$ORIG_PEERS|$ORIG_PEERS" "$(peers 1)|$(peers 3)"
ectl 1 del /ddibuntu-cluster/moved/n2 >/dev/null
cl 1 sync >/dev/null 2>&1; cl 2 sync >/dev/null 2>&1; cl 3 sync >/dev/null 2>&1
expect_eq "annonce retirée : pare-feu refermé sur n1 et n3" "CLUSTER_PEERS=127.0.1.2,127.0.1.3 no CLUSTER_PEERS=127.0.1.1,127.0.1.2 no" "$(fwlast 1) $(fwx 1) $(fwlast 3) $(fwx 3)"
expect_eq "…et leurs accusés avec (un accusé = pare-feu ouvert maintenant)" "|" "$(ack n2 n1)|$(ack n2 n3)"
expect_eq "…y compris les accusés laissés par les annonces hostiles précédentes" "" "$(ectl 1 get --prefix /ddibuntu-cluster/moved-ack/ --keys-only | head -1)"

member_urls() { ectl 1 member list -w json | python3 -c 'import json,sys; print(" ".join(sorted(u for m in json.load(sys.stdin)["members"] for u in m["peerURLs"])))'; }
san() { openssl x509 -in "$(R "$1")/etc/ddibuntu-cluster/pki/node.crt" -noout -ext subjectAltName | tr -d ' \n'; }

echo "-- un accusé manque (aucun autre nœud ne synchronise) : annulation sans trace, nœuds en défaut nommés"
FWB="$(fwlines 1)"
OUT="$(env DDI_FW_WAIT=6 "$B/cl1.sh" change-ip --ip 127.0.2.1 --yes 2>&1)"; RC=$?
expect_eq "n1 (autorité) : change-ip refusé faute d'accusés" "1 True" "$RC $(printf '%s' "$OUT" | grep -q "nœuds n2 n3 n'ont pas ouvert leur pare-feu" && echo True || echo False)"
expect_eq "…rien n'est modifié : adresse, pairs, annonce, accusés, pare-feu de n1" "127.0.1.1|$ORIG_PEERS|||$FWB" "$(conf 1 NODE_IP)|$(peers 1)|$(ectl 1 get --prefix /ddibuntu-cluster/moved/ --keys-only | head -1)|$(ectl 1 get --prefix /ddibuntu-cluster/moved-ack/ --keys-only | head -1)|$(fwlines 1)"
expect_eq "…etcd inchangé : trois membres sains aux adresses d'origine" "3 https://127.0.1.1:2380 https://127.0.1.2:2380 https://127.0.1.3:2380" "$(qj 1 'q["healthy"]') $(member_urls)"
check "…et une opération ultérieure n'est pas gênée (verrou libéré)" cl 1 sync

echo "-- l'arbitre n3 (non autorité) change d'adresse : 127.0.1.3 → 127.0.2.3"
FWB1="$(fwlines 1)"; FWB2="$(fwlines 2)"
start_syncers 3
check "n3 : change-ip 127.0.2.3" cl 3 change-ip --ip 127.0.2.3 --yes
stop_syncers
IPX[3]=127.0.2.3
expect_eq "n3 : configuration locale à la nouvelle adresse" "127.0.2.3 n1=127.0.1.1:data n2=127.0.1.2:data n3=127.0.2.3:witness" "$(conf 3 NODE_IP) $(peers 3)"
expect_grep "n3 : etcd écoute la nouvelle adresse" 'listen-client-urls: https://127\.0\.2\.3:2379' "$(R 3)/etc/ddibuntu-cluster/etcd.yml"
expect_grep "n3 : …et l'annonce aux autres" 'initial-advertise-peer-urls: https://127\.0\.2\.3:2380' "$(R 3)/etc/ddibuntu-cluster/etcd.yml"
expect_eq "etcd : le membre n3 est désormais joignable à la nouvelle adresse seulement" "https://127.0.1.1:2380 https://127.0.1.2:2380 https://127.0.2.3:2380" "$(member_urls)"
expect_eq "n3 : certificat valable pour l'ancienne ET la nouvelle adresse" "True" "$(s="$(san 3)"; case "$s" in *IPAddress:127.0.1.3*) case "$s" in *IPAddress:127.0.2.3*) echo True ;; *) echo False ;; esac ;; *) echo False ;; esac)"
expect_eq "n3 : certificat signé par l'autorité" "OK" "$(openssl verify -CAfile "$(R 3)/etc/ddibuntu-cluster/pki/ca.crt" "$(R 3)/etc/ddibuntu-cluster/pki/node.crt" 2>&1 | grep -o 'OK$')"
expect_eq "etcd de n3 présente ce certificat à sa nouvelle adresse" "$(serial 3)" "$(etcd_serial 3 3)"
expect_eq "annonce publiée (ancienne → nouvelle)" "127.0.1.3 127.0.2.3" "$(ectl 1 get /ddibuntu-cluster/moved/n3 --print-value-only | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["from"], d["to"])')"
expect_eq "registre : n3 à la nouvelle adresse" "127.0.2.3:witness" "$(ectl 1 get /ddibuntu-cluster/nodes/n3 --print-value-only)"
wait_for 40 "etcd : trois membres sains après le changement (vu par etcd lui-même)" ectl 1 endpoint health --cluster
expect_eq "n1 et n2 ont ouvert la nouvelle adresse EN PLUS de l'ancienne avant le déplacement (le déplacement n'a eu lieu qu'après leurs accusés)" "True True" "$(tail -n +$((FWB1 + 1)) "$B/fw1.log" | grep -qx 'CLUSTER_PEERS=127.0.1.2,127.0.1.3,127.0.2.3' && echo True || echo False) $(tail -n +$((FWB2 + 1)) "$B/fw2.log" | grep -qx 'CLUSTER_PEERS=127.0.1.1,127.0.1.3,127.0.2.3' && echo True || echo False)"
check "n1 : sync" cl 1 sync
check "n2 : sync" cl 2 sync
NEWPEERS="n1=127.0.1.1:data n2=127.0.1.2:data n3=127.0.2.3:witness"
expect_eq "n1 et n2 alignés sur la nouvelle adresse (annonce vérifiée)" "$NEWPEERS|$NEWPEERS" "$(peers 1)|$(peers 2)"
expect_eq "pare-feu après alignement : seulement les adresses actuelles (l'ancienne de n3 est fermée)" "CLUSTER_PEERS=127.0.1.2,127.0.2.3 CLUSTER_PEERS=127.0.1.1,127.0.2.3 no no" "$(fwlast 1) $(fwlast 2) $(fwx 1) $(fwx 2)"
wait_for 40 "etcd : trois voix saines vues par la sonde de root, après alignement" healthy_is 1 3
expect_grep "n3 : etcd.yml (initial-cluster) à la nouvelle adresse" 'n3=https://127\.0\.2\.3:2380' "$(R 3)/etc/ddibuntu-cluster/etcd.yml"
expect_eq "n2 : Patroni voit n3 à sa nouvelle adresse" "True" "$(grep -q '127.0.2.3:2379' "$(R 2)/etc/patroni/config.yml" && ! grep -q '127.0.1.3:2379' "$(R 2)/etc/patroni/config.yml" && echo True || echo False)"
OUT="$(cl 2 sync 2>&1)"
expect_eq "n2 : une seconde synchronisation ne change rien" "0" "$(printf '%s' "$OUT" | grep -c 'pairs mis à jour')"
printf '{"from":"127.0.1.3","to":"127.0.2.3","at":1}' | ectl 1 put /ddibuntu-cluster/moved/n3 >/dev/null
cl 3 sync >/dev/null 2>&1
expect_eq "n3 : son annonce périmée est retirée" "" "$(ectl 1 get /ddibuntu-cluster/moved/n3 --keys-only | head -1)"

echo "-- retour arrière : etcd ne redémarre pas sur la nouvelle adresse (n2)"
start_syncers 2
touch "$B/echec-redemarrage2"
OUT="$(env DDI_ETCD_RESTART_WAIT=6 "$B/cl2.sh" change-ip --ip 127.0.2.2 --yes 2>&1)"; RC=$?
stop_syncers
expect_eq "change-ip échoue et le dit" "1 True" "$RC $(printf '%s' "$OUT" | grep -q "changement d'adresse annulé" && echo True || echo False)"
expect_eq "n2 : configuration locale revenue à l'ancienne adresse" "127.0.1.2 $NEWPEERS" "$(conf 2 NODE_IP) $(peers 2)"
expect_grep "n2 : etcd.yml revenu à l'ancienne adresse" 'listen-client-urls: https://127\.0\.1\.2:2379' "$(R 2)/etc/ddibuntu-cluster/etcd.yml"
expect_eq "n2 : initial-cluster de retour" "True" "$(grep -q 'n2=https://127.0.1.2:2380' "$(R 2)/etc/ddibuntu-cluster/etcd.yml" && ! grep -q '127.0.2.2' "$(R 2)/etc/ddibuntu-cluster/etcd.yml" && echo True || echo False)"
wait_for 60 "etcd de n2 relancé à l'ancienne adresse" ectl 2 endpoint health
wait_for 60 "etcd : trois membres sains après le retour arrière" healthy_is 1 3
expect_eq "etcd : adresse du membre n2 rétablie" "https://127.0.1.2:2380 https://127.0.1.1:2380 https://127.0.2.3:2380" "$(ectl 1 member list -w json | python3 -c 'import json,sys; ms=json.load(sys.stdin)["members"]; print(" ".join(u for n in ("n2","n1","n3") for m in ms if m["name"]==n for u in m["peerURLs"]))')"
expect_eq "annonce retirée, registre inchangé" "|127.0.1.2:data" "$(ectl 1 get /ddibuntu-cluster/moved/n2 --keys-only | head -1)|$(ectl 1 get /ddibuntu-cluster/nodes/n2 --print-value-only)"
cl 1 sync >/dev/null 2>&1; cl 3 sync >/dev/null 2>&1
expect_eq "…plus aucun accusé pour l'opération annulée" "" "$(ectl 1 get --prefix /ddibuntu-cluster/moved-ack/n2/ --keys-only | head -1)"
expect_eq "…et les autres nœuds ont refermé leur pare-feu (adresse annoncée retirée)" "CLUSTER_PEERS=127.0.1.2,127.0.2.3 CLUSTER_PEERS=127.0.1.1,127.0.1.2 no no" "$(fwlast 1) $(fwlast 3) $(fwx 1) $(fwx 3)"
expect_eq "n2 : certificat toujours valide et présenté par etcd" "OK $(serial 2)" "$(openssl verify -CAfile "$(R 2)/etc/ddibuntu-cluster/pki/ca.crt" "$(R 2)/etc/ddibuntu-cluster/pki/node.crt" 2>&1 | grep -o 'OK$') $(etcd_serial 2 2)"

echo "-- le nœud de données n2 change d'adresse : 127.0.1.2 → 127.0.2.2"
start_syncers 2
check "n2 : change-ip 127.0.2.2" cl 2 change-ip --ip 127.0.2.2 --yes
stop_syncers
IPX[2]=127.0.2.2
expect_eq "n2 : configuration locale à la nouvelle adresse" "127.0.2.2 n1=127.0.1.1:data n2=127.0.2.2:data n3=127.0.2.3:witness" "$(conf 2 NODE_IP) $(peers 2)"
expect_eq "n2 : Patroni écoute et s'annonce à la nouvelle adresse" "True" "$(grep -q '127.0.2.2' "$(R 2)/etc/patroni/config.yml" && ! grep -q '127.0.1.2' "$(R 2)/etc/patroni/config.yml" && echo True || echo False)"
expect_eq "n2 : Keepalived à jour (adresse source)" "True" "$(grep -q 'unicast_src_ip 127.0.2.2' "$(kaconf 2)" && echo True || echo False)"
expect_eq "etcd : adresses des membres" "https://127.0.1.1:2380 https://127.0.2.2:2380 https://127.0.2.3:2380" "$(member_urls)"
expect_eq "etcd de n2 présente son certificat à la nouvelle adresse" "$(serial 2)" "$(etcd_serial 2 2)"
check "n1 : sync" cl 1 sync
check "n3 : sync" cl 3 sync
NEWPEERS="n1=127.0.1.1:data n2=127.0.2.2:data n3=127.0.2.3:witness"
expect_eq "n1 et n3 alignés" "$NEWPEERS|$NEWPEERS" "$(peers 1)|$(peers 3)"
expect_eq "n3 : etcd.yml (initial-cluster) suit l'adresse de n2" "True" "$(grep -q 'n2=https://127.0.2.2:2380' "$(R 3)/etc/ddibuntu-cluster/etcd.yml" && ! grep -q '127.0.1.2' "$(R 3)/etc/ddibuntu-cluster/etcd.yml" && echo True || echo False)"
expect_eq "n1 : Keepalived désigne le nouveau pair" "True" "$(grep -A1 'unicast_peer' "$(kaconf 1)" | grep -q '127.0.2.2' && echo True || echo False)"
wait_for 40 "etcd : trois membres sains" healthy_is 1 3

echo "-- l'autorité n1 change d'adresse : 127.0.1.1 → 127.0.2.1"
start_syncers 1
check "n1 (autorité) : change-ip 127.0.2.1" cl 1 change-ip --ip 127.0.2.1 --yes
stop_syncers
IPX[1]=127.0.2.1
expect_eq "n1 : configuration à la nouvelle adresse" "127.0.2.1 n1=127.0.2.1:data n2=127.0.2.2:data n3=127.0.2.3:witness" "$(conf 1 NODE_IP) $(peers 1)"
expect_eq "n1 : certificat valable pour les deux adresses" "True" "$(s="$(san 1)"; case "$s" in *IPAddress:127.0.1.1*) case "$s" in *IPAddress:127.0.2.1*) echo True ;; *) echo False ;; esac ;; *) echo False ;; esac)"
expect_eq "etcd de n1 présente son certificat à la nouvelle adresse" "$(serial 1)" "$(etcd_serial 1 1)"
check "n2 : sync" cl 2 sync
check "n3 : sync" cl 3 sync
NEWPEERS="n1=127.0.2.1:data n2=127.0.2.2:data n3=127.0.2.3:witness"
expect_eq "n2 et n3 alignés sur la nouvelle adresse de l'autorité" "$NEWPEERS|$NEWPEERS" "$(peers 2)|$(peers 3)"
expect_eq "etcd : adresses des membres" "https://127.0.2.1:2380 https://127.0.2.2:2380 https://127.0.2.3:2380" "$(member_urls)"
expect_eq "n2 : etcd.yml (initial-cluster) suit l'adresse de l'autorité" "True" "$(grep -q 'n1=https://127.0.2.1:2380' "$(R 2)/etc/ddibuntu-cluster/etcd.yml" && ! grep -q '127.0.1.1' "$(R 2)/etc/ddibuntu-cluster/etcd.yml" && echo True || echo False)"
wait_for 40 "etcd : trois membres sains, plus aucune ancienne adresse" healthy_is 2 3
check "etcd : tout le cluster se joint avec les nouveaux certificats" ectl 3 endpoint health --cluster
echo "-- après les trois déplacements, le cluster fonctionne comme avant"
check "n2 : renouvellement de certificat (adresse d'après le registre)" cl 2 renew-cert --force
check "n1 : signature" cl 1 sign-requests
check "n2 : installation" cl 2 sync
expect_eq "n2 : etcd présente le nouveau certificat" "$(serial 2)" "$(etcd_serial 2 2)"
check "n2 : réglages communs toujours appliqués (adresse virtuelle)" cl 2 sync
expect_eq "adresse virtuelle intacte" "192.0.2.20/24" "$(conf 3 VIP)"
expect_eq "état du cluster vu de n3 : trois membres, quorum" "3 True" "$(st 3 '"%d %s" % (d["etcd"]["quorum"]["healthy"], d["etcd"]["quorum"]["hasQuorum"])')"

echo "== 4. Demandes déposées par la console (fichier .cluster-action relu strictement par root) =="
CLN="$(conf 1 CLUSTER_NAME)"
GEN() { echo "$(R "$1")/var/lib/ddibuntu/generated/.cluster-action"; }
drop() { printf '%s' "$2" > "$(GEN "$1")"; chmod 640 "$(GEN "$1")"; cl "$1" request >/dev/null 2>&1; }   # drop N JSON : dépose la demande puis laisse root la traiter
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$(R "$1")/run/ddibuntu/cluster-result.json" "$2"; }
refused_req() {   # refused_req LIBELLÉ N JSON : demande refusée comme invalide, rien consommé, rien changé
  local before; before="$(conf "$2" PEERS)|$(conf "$2" VIP)|$(conf "$2" REPL_NET)|$(conf "$2" SETTINGS_REV)"
  drop "$2" "$3"
  expect_eq "$1" "False demande invalide False $before" "$([ -e "$(GEN "$2")" ] && echo True || echo False) $(res "$2" 'd["message"]') $(res "$2" 'd["ok"]') $(conf "$2" PEERS)|$(conf "$2" VIP)|$(conf "$2" REPL_NET)|$(conf "$2" SETTINGS_REV)"
}
refused_req "set-vip : adresse hostile" 2 "{\"action\":\"set-vip\",\"vip\":\"192.0.2.50/24;reboot\",\"iface\":\"eth1\",\"confirm\":\"$CLN\"}"
refused_req "set-vip : mauvaise confirmation" 2 '{"action":"set-vip","vip":"192.0.2.50/24","iface":"eth1","confirm":"autre"}'
refused_req "set-vip : VRID 0" 2 "{\"action\":\"set-vip\",\"vip\":\"192.0.2.50/24\",\"iface\":\"eth1\",\"vrid\":0,\"confirm\":\"$CLN\"}"
refused_req "set-vip : VRID booléen" 2 "{\"action\":\"set-vip\",\"vip\":\"192.0.2.50/24\",\"iface\":\"eth1\",\"vrid\":true,\"confirm\":\"$CLN\"}"
refused_req "set-vip : VRID texte" 2 "{\"action\":\"set-vip\",\"vip\":\"192.0.2.50/24\",\"iface\":\"eth1\",\"vrid\":\"5\",\"confirm\":\"$CLN\"}"
refused_req "set-vip : clé inconnue" 2 "{\"action\":\"set-vip\",\"vip\":\"192.0.2.50/24\",\"iface\":\"eth1\",\"confirm\":\"$CLN\",\"role\":\"data\"}"
refused_req "clear-vip : clé en trop" 2 "{\"action\":\"clear-vip\",\"confirm\":\"$CLN\",\"vip\":\"1.2.3.4/24\"}"
refused_req "vip-iface : confirmation superflue" 2 '{"action":"vip-iface","iface":"eth1","confirm":"x"}'
refused_req "set-net : réseau hostile" 2 "{\"action\":\"set-net\",\"net\":\"127.0.0.0/8 && reboot\",\"confirm\":\"$CLN\"}"
refused_req "renew-cert : paramètres interdits" 2 '{"action":"renew-cert","ip":"127.0.0.9"}'
refused_req "change-ip : confirmation d'un autre nœud" 2 '{"action":"change-ip","ip":"127.0.3.2","confirm":"n1"}'
refused_req "change-ip : adresse hostile" 2 '{"action":"change-ip","ip":"127.0.3.2;reboot","confirm":"n2"}'
refused_req "action inconnue" 2 '{"action":"format-disk","confirm":"n2"}'
refused_req "JSON invalide" 2 'pas du json'
refused_req "tableau JSON" 2 '[{"action":"renew-cert"}]'
refused_req "demande trop longue (tronquée)" 2 "{\"action\":\"set-net\",\"net\":\"127.0.0.0/8\",\"confirm\":\"$CLN\",\"pad\":\"$(head -c 1500 /dev/zero | tr '\0' 'x')\"}"
ln -sf /etc/passwd "$(GEN 2)"; cl 2 request >/dev/null 2>&1
expect_eq "lien symbolique : consommé sans être suivi" "False demande invalide" "$([ -e "$(GEN 2)" ] || [ -L "$(GEN 2)" ] && echo True || echo False) $(res 2 'd["message"]')"
drop 3 '{"action":"renew-cert"}'
expect_eq "sur l'arbitre : aucune action n'est traitée" "True" "$([ -e "$(GEN 3)" ] && echo True || echo False)"
rm -f "$(GEN 3)"

echo "-- demandes valides"
drop 1 "{\"action\":\"set-vip\",\"vip\":\"192.0.2.30/24\",\"iface\":\"ens18\",\"vrid\":88,\"confirm\":\"$CLN\"}"
expect_eq "set-vip : exécuté par root" "True set-vip" "$(res 1 'd["ok"]') $(res 1 'd["action"]')"
expect_eq "…réglages locaux et publiés" "192.0.2.30/24 ens18 88 5" "$(conf 1 VIP) $(conf 1 VIP_IFACE) $(conf 1 VIP_VRID) $(conf 1 SETTINGS_REV)"
check "n2 : sync" cl 2 sync
expect_eq "n2 : adresse commune appliquée avec SON interface" "192.0.2.30/24 eth1 88 5" "$(conf 2 VIP) $(conf 2 VIP_IFACE) $(conf 2 VIP_VRID) $(conf 2 SETTINGS_REV)"
drop 2 '{"action":"vip-iface","iface":"ens19"}'
expect_eq "vip-iface : exécuté" "True vip-iface ens19" "$(res 2 'd["ok"]') $(res 2 'd["action"]') $(conf 2 VIP_IFACE)"
expect_grep "…Keepalived suit l'interface" '192\.0\.2\.30/24 dev ens19' "$(kaconf 2)"
drop 2 '{"action":"vip-iface","iface":"inconnue0"}'
expect_eq "vip-iface : interface absente de ce serveur refusée avec explication" "False True" "$(res 2 'd["ok"]') $(res 2 '"existe pas" in d["message"]')"
drop 1 "{\"action\":\"set-net\",\"net\":\"127.0.0.0/8\",\"confirm\":\"$CLN\"}"
expect_eq "set-net : exécuté" "True 127.0.0.0/8 6" "$(res 1 'd["ok"]') $(conf 1 REPL_NET) $(conf 1 SETTINGS_REV)"
drop 1 '{"action":"set-net","net":"10.0.0.0/8","confirm":"'"$CLN"'"}'
expect_eq "set-net : réseau qui exclut des nœuds refusé par root (le message nomme les nœuds)" "False True 127.0.0.0/8" "$(res 1 'd["ok"]') $(res 1 '"hors de ce réseau" in d["message"]') $(conf 1 REPL_NET)"
S2D="$(serial 2)"
drop 2 '{"action":"renew-cert"}'
expect_eq "renew-cert : demande publiée par root" "True renew-cert True" "$(res 2 'd["ok"]') $(res 2 'd["action"]') $(st 2 'd["pki"]["pending"]')"
check "n1 : signature" cl 1 sign-requests
check "n2 : installation" cl 2 sync
expect_eq "n2 : certificat renouvelé, présenté par etcd" "True" "$([ "$(serial 2)" != "$S2D" ] && [ "$(etcd_serial 2 2)" = "$(serial 2)" ] && echo True || echo False)"
drop 1 "{\"action\":\"clear-vip\",\"confirm\":\"$CLN\"}"
expect_eq "clear-vip : exécuté" "True  7" "$(res 1 'd["ok"]') $(conf 1 VIP) $(conf 1 SETTINGS_REV)"
drop 1 "{\"action\":\"clear-vip\",\"confirm\":\"$CLN\"}"
expect_eq "clear-vip répété : refusé (aucune adresse)" "False" "$(res 1 'd["ok"]')"
check "n2 : sync" cl 2 sync
expect_eq "n2 : adresse virtuelle retirée" " no" "$(conf 2 VIP) $([ -e "$(kaconf 2)" ] && echo yes || echo no)"

echo "-- changement d'adresse demandé par la console (n2, l'autorité signe en tâche de fond)"
start_syncers 2
drop 2 '{"action":"change-ip","ip":"127.0.3.2","confirm":"n2"}'
stop_syncers
IPX[2]=127.0.3.2
expect_eq "change-ip : exécuté par root, résultat relayé avec le nom du nœud" "True change-ip n2" "$(res 2 'd["ok"]') $(res 2 'd["action"]') $(res 2 'd["candidate"]')"
expect_eq "…nouvelle adresse en service" "127.0.3.2" "$(conf 2 NODE_IP)"
expect_eq "…etcd présente le certificat à la nouvelle adresse" "$(serial 2)" "$(etcd_serial 2 2)"
check "n1 : sync" cl 1 sync
check "n3 : sync" cl 3 sync
NEWPEERS="n1=127.0.2.1:data n2=127.0.3.2:data n3=127.0.2.3:witness"
expect_eq "autres nœuds alignés" "$NEWPEERS|$NEWPEERS" "$(peers 1)|$(peers 3)"
wait_for 60 "etcd : trois membres sains à la fin" healthy_is 1 3

[ -n "${KEEP:-}" ] && { trap - EXIT; echo "gardé : $B"; }
finish
