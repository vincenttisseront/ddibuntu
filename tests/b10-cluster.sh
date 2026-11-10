#!/usr/bin/env bash
# Batterie 10 — ddibuntu-cluster, partie sans démon : analyse STRICTE de cluster.conf, rendu etcd/Patroni, lots d'enrôlement hostiles,
# règles de pare-feu des pairs. Le comportement avec de vrais etcd/Patroni est dans b10-cluster-live.sh.
# Ne demande ni root ni systemd (DDI_TEST=1, DDI_TEST_NOUSERS=1, DDI_ROOT).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
for t in openssl gpg python3; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
CL="$RFS/usr/local/sbin/ddibuntu-cluster"
FW="$RFS/usr/local/sbin/ddibuntu-fw"
W="$T_TMP/w"; mkdir -p "$W"

check "shellcheck : ddibuntu-cluster" bash -c "command -v shellcheck >/dev/null && shellcheck -x '$CL' || true"
check "bash -n : ddibuntu-cluster" bash -n "$CL"
expect_eq "sans argument : code 2 et aide" "2" "$(bash "$CL" >/dev/null 2>&1; echo $?)"

mkroot() { local r="$W/$1"; rm -rf "$r"; mkdir -p "$r/etc/ddibuntu-cluster"; echo "$r"; }
run() { local r="$1"; shift; DDI_ROOT="$r" DDI_TEST=1 DDI_TEST_NOUSERS=1 bash "$CL" "$@"; }
goodconf() { cat <<'EOF'
CLUSTER_NAME=lab
NODE_NAME=n1
NODE_ROLE=data
NODE_IP=10.9.0.1
REPL_NET=10.9.0.0/24
PEERS=n1=10.9.0.1:data n2=10.9.0.2:data n3=10.9.0.3:witness
CA_NODE=0
ETCD_STATE=existing
ETCD_INITIAL_CLUSTER=n1=https://10.9.0.1:2380,n2=https://10.9.0.2:2380,n3=https://10.9.0.3:2380
EOF
}

echo "== Analyse stricte de cluster.conf =="
R="$(mkroot ok)"; goodconf > "$R/etc/ddibuntu-cluster/cluster.conf"
check "configuration valide : render" run "$R" render
E="$R/etc/ddibuntu-cluster/etcd.yml"; P="$R/etc/patroni/config.yml"
expect_grep "etcd : écoute sur l'adresse du réseau dédié seulement" '^listen-peer-urls: https://10\.9\.0\.1:2380$' "$E"
expect_grep "etcd : initial-cluster repris du lot" '^initial-cluster: n1=https://10\.9\.0\.1:2380,n2=' "$E"
expect_grep "etcd : état « existing » pour un nœud rattaché" '^initial-cluster-state: existing$' "$E"
expect_grep "etcd : passerelle gRPC activée (exigée par Patroni etcd3)" '^enable-grpc-gateway: true$' "$E"
expect_grep "Patroni : hôtes etcd = les 3 pairs" 'hosts: \["10\.9\.0\.1:2379", "10\.9\.0\.2:2379", "10\.9\.0\.3:2379"\]' "$P"
expect_grep "Patroni : pg_rewind activé" 'use_pg_rewind: true' "$P"
expect_grep "Patroni : bascule automatique bornée en retard (1 Mo)" 'maximum_lag_on_failover: 1048576' "$P"
expect_grep "Patroni : TTL 30 s" 'ttl: 30' "$P"
expect_grep "pg_hba : réseau dédié repris de REPL_NET" 'hostssl replication replicator 10\.9\.0\.0/24 cert map=ddicluster' "$P"
expect_grep "PostgreSQL : TLS 1.2 minimum" 'ssl_min_protocol_version: TLSv1.2' "$P"
python3 - "$P" "$E" <<'EOF' >/dev/null 2>&1 && ok "les deux YAML se relisent" || ko "les deux YAML se relisent"
import sys, yaml
for f in sys.argv[1:]: yaml.safe_load(open(f))
EOF

R="$(mkroot witness)"; goodconf | sed 's/^NODE_ROLE=data/NODE_ROLE=witness/; s/^NODE_NAME=n1/NODE_NAME=n3/; s/^NODE_IP=.*/NODE_IP=10.9.0.3/' > "$R/etc/ddibuntu-cluster/cluster.conf"
check "arbitre : render" run "$R" render
expect_eq "arbitre : pas de configuration Patroni" "no" "$([ -e "$R/etc/patroni/config.yml" ] && echo yes || echo no)"
expect_eq "arbitre : etcd configuré" "yes" "$([ -f "$R/etc/ddibuntu-cluster/etcd.yml" ] && echo yes || echo no)"

bad() { # bad "nom" "sed expr"
  local r; r="$(mkroot bad)"; goodconf | sed "$2" > "$r/etc/ddibuntu-cluster/cluster.conf"
  check_fail "conf refusée : $1" run "$r" render
  expect_eq "conf refusée : $1 — aucun fichier produit" "no" "$([ -e "$r/etc/ddibuntu-cluster/etcd.yml" ] && echo yes || echo no)"
}
bad "substitution de commande dans le nom" 's/^NODE_NAME=n1/NODE_NAME=n1$(touch \/tmp\/pwn)/'
bad "point-virgule dans le nom du cluster" 's/^CLUSTER_NAME=lab/CLUSTER_NAME=lab;id/'
bad "nom en majuscules" 's/^NODE_NAME=n1/NODE_NAME=N1/'
bad "clé inconnue" 's/^CA_NODE=0/CA_NODE=0\nEVIL=1/'
bad "adresse hors plage" 's/^NODE_IP=.*/NODE_IP=10.9.0.300/'
bad "réseau sans masque" 's/^REPL_NET=.*/REPL_NET=10.9.0.0/'
bad "masque > 32" 's/^REPL_NET=.*/REPL_NET=10.9.0.0\/33/'
bad "rôle inconnu" 's/^NODE_ROLE=data/NODE_ROLE=admin/'
bad "pair mal formé" 's/n2=10.9.0.2:data/n2=10.9.0.2/'
bad "pair avec rôle inconnu" 's/n2=10.9.0.2:data/n2=10.9.0.2:root/'
bad "pair avec adresse invalide" 's/n2=10.9.0.2:data/n2=10.9.0.2999:data/'
bad "port invalide" 's/^CA_NODE=0/CA_NODE=0\nETCD_CLIENT_PORT=99999/'
bad "guillemets" 's/^CLUSTER_NAME=lab/CLUSTER_NAME="lab"/'
bad "retour chariot (fichier édité sous Windows)" 's/^NODE_NAME=n1/NODE_NAME=n1\r/'
bad "répertoire de sockets relatif" 's/^CA_NODE=0/CA_NODE=0\nPG_SOCKET_DIR=run\/pg/'
bad "répertoire avec .." 's/^CA_NODE=0/CA_NODE=0\nPG_CONFIG_DIR=\/etc\/..\/x$y/'
R="$(mkroot missing)"
check_fail "sans cluster.conf : message explicite" run "$R" status
check_fail "commande inconnue" run "$R" demolish

echo "== Lots d'enrôlement hostiles (join) =="
mkbundle() { # mkbundle nom conf-file [corrompre-manifest]
  local d="$W/bnd-$1"; rm -rf "$d"; mkdir -p "$d/b"; cp "$2" "$d/b/cluster.conf"
  ( cd "$d/b" && sha256sum cluster.conf > MANIFEST )
  tar -C "$d/b" -cf "$d/b.tar" .
  printf 'pw-%s' "$1" | gpg --homedir "$W/gh" --batch --quiet --yes --pinentry-mode loopback --passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$d/out.bundle" "$d/b.tar" 2>/dev/null
  echo "$d/out.bundle"
}
mkdir -p "$W/gh"; chmod 700 "$W/gh"
# stubs pour le contrôle préalable (le rôle de ce test n'est pas de vérifier la présence des démons)
STUBS="$W/stubs"; mkdir -p "$STUBS"
for t in etcd etcdctl patroni patronictl; do command -v "$t" >/dev/null 2>&1 || { printf '#!/bin/sh\nexit 0\n' > "$STUBS/$t"; chmod +x "$STUBS/$t"; }; done
python3.12 -c 'import psycopg2' 2>/dev/null || python3 -c 'import psycopg2' 2>/dev/null || note "psycopg2 absent : le contrôle préalable de join échouera avant l'analyse du lot (tests de lots hostiles non significatifs)"
PYX="$(command -v python3.12 || echo python3)"
joinb() { local r="$1" b="$2" pw="$3"; shift 3; PATH="$STUBS:$PATH" DDI_PY="$PYX" DDI_BUNDLE_PASS="$pw" DDI_ROOT="$r" DDI_TEST=1 DDI_TEST_NOUSERS=1 bash "$CL" join "$b" "$@"; }

goodconf | sed 's/^NODE_NAME=n1/NODE_NAME=n2/; s/^NODE_IP=.*/NODE_IP=10.9.0.2/' > "$W/c-ok"
B="$(mkbundle ok "$W/c-ok")"
R="$(mkroot j1)"
check_fail "lot correct mais phrase de passe fausse" joinb "$R" "$B" "mauvaise" --no-activate
check_fail "lot : un nœud de données exige --wipe-local-db" joinb "$R" "$B" "pw-ok" --no-activate
expect_eq "aucune configuration écrite après ces refus" "no" "$([ -e "$R/etc/ddibuntu-cluster/cluster.conf" ] && echo yes || echo no)"

sed 's/^CA_NODE=0/CA_NODE=1/' "$W/c-ok" > "$W/c-ca"
B="$(mkbundle ca "$W/c-ca")"; R="$(mkroot j2)"
check_fail "lot qui ferait de ce nœud une autorité : refusé" joinb "$R" "$B" "pw-ca" --wipe-local-db --no-activate
expect_grep "message : un lot ne peut pas créer d'autorité" "autorité" <(joinb "$R" "$B" "pw-ca" --wipe-local-db --no-activate 2>&1)

sed 's/^NODE_NAME=n2/NODE_NAME=n2$(id)/' "$W/c-ok" > "$W/c-inj"
B="$(mkbundle inj "$W/c-inj")"; R="$(mkroot j3)"
check_fail "lot avec injection dans le nom : refusé" joinb "$R" "$B" "pw-inj" --wipe-local-db --no-activate

sed 's/^CA_NODE=0/CA_NODE=0\nPG_SOCKET_DIR=\/tmp\/$(id)/' "$W/c-ok" > "$W/c-inj2"
B="$(mkbundle inj2 "$W/c-inj2")"; R="$(mkroot j4)"
check_fail "lot avec injection dans un chemin : refusé" joinb "$R" "$B" "pw-inj2" --wipe-local-db --no-activate

# manifeste incohérent : le contenu a été modifié après calcul des empreintes
B="$(mkbundle tamper "$W/c-ok")"; d="$W/bnd-tamper"
mkdir -p "$d/x"; tar -C "$d/x" -xf "$d/b.tar"; echo "# modifié" >> "$d/x/cluster.conf"; tar -C "$d/x" -cf "$d/b2.tar" .
printf 'pw-tamper' | gpg --homedir "$W/gh" --batch --quiet --yes --pinentry-mode loopback --passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$d/t.bundle" "$d/b2.tar" 2>/dev/null
R="$(mkroot j5)"
check_fail "manifeste incohérent (contenu modifié) : refusé" joinb "$R" "$d/t.bundle" "pw-tamper" --wipe-local-db --no-activate

echo "== Pare-feu : ports du cluster réservés aux pairs =="
FWD="$W/fw"; mkdir -p "$FWD"
fwr() { DDI_ROOT="$FWD" DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_FW_CONF="$FWD/firewall.conf" DDI_FW_STATE="$FWD/state" bash "$FW" "$@"; }
check "set CLUSTER_PEERS" fwr set CLUSTER_PEERS "10.9.0.2,10.9.0.3"
fwr render > "$W/nft.out" 2>&1
expect_grep "règle : 2379/2380/5432/8000/8008 depuis le jeu des pairs" 'ip saddr @cluster4 tcp dport \{ 2379, 2380, 5432, 8000, 8008 \} accept' "$W/nft.out"
expect_grep "jeu des pairs : deux adresses /32" 'elements = \{ 10\.9\.0\.2/32, 10\.9\.0\.3/32 \}' "$W/nft.out"
expect_nogrep "aucun de ces ports n'est ouvert à tous" '^\s+tcp dport \{[^}]*(2379|2380|5432|8000|8008)' "$W/nft.out"
check_fail "pair IPv6 refusé" fwr set CLUSTER_PEERS "fd00::1"
check_fail "pair invalide refusé" fwr set CLUSTER_PEERS "10.9.0.2; drop"
expect_grep "après refus : la configuration précédente est conservée" '10\.9\.0\.2,10\.9\.0\.3' "$FWD/firewall.conf"
if command -v nft >/dev/null 2>&1 && nft -c -f "$W/nft.out" >/dev/null 2>&1; then ok "nft -c accepte le jeu de règles"; else note "nft indisponible ou sans droits : syntaxe nftables non vérifiée ici"; fi
check "sans pairs : règle absente" bash -c "DDI_ROOT='$FWD' DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu' DDI_FW_CONF='$FWD/firewall.conf' DDI_FW_STATE='$FWD/state' bash '$FW' set CLUSTER_PEERS '' && ! DDI_ROOT='$FWD' DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu' DDI_FW_CONF='$FWD/firewall.conf' DDI_FW_STATE='$FWD/state' bash '$FW' render | grep -q 'dport { 2379'"

echo "== Console : pas de boîte de dialogue système =="
UI="$ROOT/webui/app"
if [ -d "$UI" ]; then
  if grep -rnE '(^|[^A-Za-z0-9_.])(window\.)?(confirm|alert|prompt)\(' "$UI" --include=*.vue --include=*.ts >"$T_TMP/dlg" 2>&1; then ko "aucune boîte système (confirm/alert/prompt)" "$(head -c 300 "$T_TMP/dlg")"; else ok "aucune boîte système (confirm/alert/prompt) dans la console"; fi
  check "indicateur d'attente global présent" test -f "$UI/components/BusyIndicator.vue"
  expect_grep "indicateur monté dans app.vue" '<BusyIndicator' "$UI/app.vue"
  expect_grep "useApi compte les écritures en cours" "busy.value\+\+" "$UI/composables/useApi.ts"
fi

finish
