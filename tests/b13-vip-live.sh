#!/usr/bin/env bash
# Batterie 13 (réel) — VIP de service Keepalived : deux espaces de noms réseau (kn1, kn2) reliés par une paire veth, un vrai Keepalived dans chacun,
# configuration produite par « ddibuntu-cluster keepalived » et test de santé réel « ddibuntu-cluster vip-check » interrogeant un faux Patroni en TLS mutuel
# (200 sur /primary pour le leader, 503 sinon — comme Patroni). Vérifie : la VIP n'existe que sur le leader, jamais nulle part sans leader, suit la bascule,
# jamais sur deux nœuds à la fois. Exige root, keepalived, ip netns/veth, openssl, curl, python3.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
CL="$RFS/usr/local/sbin/ddibuntu-cluster"
for t in keepalived ip openssl curl python3; do command -v "$t" >/dev/null 2>&1 || { note "batterie VIP non exécutable ici (outil absent : $t)"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }
if ! ip netns add ddikn-probe 2>/dev/null; then note "batterie VIP non exécutable ici (espaces de noms réseau indisponibles)"; finish; exit; fi
ip netns del ddikn-probe 2>/dev/null

W="$(mktemp -d /srv/ddivip.XXXXXX)"; chmod 755 "$W"
VIP=10.55.0.100/24
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 1; for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
  ip netns del kn1 2>/dev/null; ip netns del kn2 2>/dev/null; rm -rf "$W" "$T_TMP"
}
trap cleanup EXIT
ip netns add kn1; ip netns add kn2
ip link add vk1 type veth peer name vk2
ip link set vk1 netns kn1; ip link set vk2 netns kn2
ip netns exec kn1 ip addr add 10.55.0.1/24 dev vk1; ip netns exec kn1 ip link set vk1 up; ip netns exec kn1 ip link set lo up
ip netns exec kn2 ip addr add 10.55.0.2/24 dev vk2; ip netns exec kn2 ip link set vk2 up; ip netns exec kn2 ip link set lo up

# PKI du cluster de test
openssl ecparam -name prime256v1 -genkey -noout -out "$W/ca.key" 2>/dev/null
openssl req -x509 -new -key "$W/ca.key" -subj /CN=test-ca -days 2 -out "$W/ca.crt" 2>/dev/null
node_ip() { echo "10.55.0.$1"; }
for n in 1 2; do
  d="$W/n$n"; mkdir -p "$d/etc/ddibuntu-cluster/pki" "$d/etc/keepalived"; ip="$(node_ip $n)"
  cp "$W/ca.crt" "$d/etc/ddibuntu-cluster/pki/ca.crt"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/etc/ddibuntu-cluster/pki/node.key" 2>/dev/null
  openssl req -new -key "$d/etc/ddibuntu-cluster/pki/node.key" -subj "/CN=n$n" -out "$d/n.csr" 2>/dev/null
  printf 'subjectAltName=IP:%s\n' "$ip" > "$d/ext"
  openssl x509 -req -in "$d/n.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$d/ext" -out "$d/etc/ddibuntu-cluster/pki/node.crt" 2>/dev/null
  printf 'CLUSTER_NAME=lab\nNODE_NAME=n%s\nNODE_ROLE=data\nNODE_IP=%s\nREPL_NET=10.55.0.0/24\nPEERS=n1=10.55.0.1:data n2=10.55.0.2:data\nCA_NODE=0\nPATRONI_PORT=8008\nVIP=%s\nVIP_IFACE=vk%s\nVIP_VRID=61\n' "$n" "$ip" "$VIP" "$n" > "$d/etc/ddibuntu-cluster/cluster.conf"
  # enveloppe appelée par Keepalived (il ne transmet pas l'environnement de test)
  printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_TEST_NOUSERS=1 bash %s "$@"\n' "$d" "$CL" > "$d/wrapper"; chmod 755 "$d/wrapper"
done
# faux Patroni : API HTTPS avec certificat client EXIGÉ ; /primary = 200 si le fichier « leader » existe, 503 sinon
cat > "$W/fakepatroni.py" <<'PY'
import http.server, os, ssl, sys
d, ip = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/primary" and os.path.exists(os.path.join(d, "leader"))
        self.send_response(200 if ok else 503); self.end_headers(); self.wfile.write(b"x")
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(d, "etc/ddibuntu-cluster/pki/node.crt"), os.path.join(d, "etc/ddibuntu-cluster/pki/node.key"))
ctx.load_verify_locations(os.path.join(d, "etc/ddibuntu-cluster/pki/ca.crt")); ctx.verify_mode = ssl.CERT_REQUIRED
s = http.server.HTTPServer((ip, 8008), H); s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
vip_on() { ip netns exec "kn$1" ip -4 addr show dev "vk$1" | grep -q "10\.55\.0\.100/"; }
holders() { local c=0 n; for n in 1 2; do vip_on $n && c=$((c + 1)); done; echo "$c"; }
lead() { touch "$W/n$1/leader"; }
unlead() { rm -f "$W/n$1/leader"; }
wait_cond() { local s="$1" d="$2" e="$3" i=0; while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
start_ka() {
  local n="$1" d="$W/n$1"
  ip netns exec "kn$n" keepalived -n -f "$d/etc/keepalived/keepalived.conf" -D -l -G -p "$d/ka.pid" -r "$d/vrrp.pid" -c "$d/chk.pid" >"$d/ka.log" 2>&1 &
  eval "KPID$n=$!"; PIDS="$PIDS $!"
}

echo "== Configuration produite par ddibuntu-cluster =="
for n in 1 2; do
  d="$W/n$n"
  check "n$n : rendu de la configuration Keepalived" env DDI_ROOT="$d" DDI_TEST=1 DDI_TEST_NOUSERS=1 DDI_VRRP_IFACE="vk$n" DDI_CLUSTER_BIN="$d/wrapper" bash "$CL" keepalived
  check "n$n : keepalived -t accepte la configuration" ip netns exec "kn$n" keepalived -t -f "$d/etc/keepalived/keepalived.conf"
  ip netns exec "kn$n" python3 "$W/fakepatroni.py" "$d" "$(node_ip $n)" >"$d/fp.log" 2>&1 &
  PIDS="$PIDS $!"
done
sleep 1
echo "-- test de santé réel (vip-check contre le faux Patroni) --"
vc() { ip netns exec "kn$1" "$W/n$1/wrapper" vip-check; }
check_fail "vip-check : refus tant que le nœud n'est pas leader" vc 1
lead 1; check "vip-check : succès quand le nœud est leader" vc 1; unlead 1
check_fail "vip-check : refus sans certificat client valide (API Patroni)" ip netns exec kn1 curl -fsS --max-time 3 --cacert "$W/ca.crt" "https://10.55.0.1:8008/primary"

echo "== Keepalived réel dans chaque espace de noms =="
start_ka 1; start_ka 2
sleep 8
expect_eq "aucun leader : la VIP n'est nulle part" 0 "$(holders)"
lead 1
wait_cond 20 "n1 leader : n1 porte la VIP" 'vip_on 1'
expect_eq "…et n2 ne la porte pas" 0 "$(vip_on 2 && echo 1 || echo 0)"
echo "-- bascule du leader : n1 → n2 --"
unlead 1; lead 2
wait_cond 25 "n2 leader : la VIP arrive sur n2" 'vip_on 2'
wait_cond 15 "…et quitte n1" '! vip_on 1'
expect_eq "jamais deux porteurs de la VIP" 1 "$(holders)"
echo "-- perte du quorum : plus de leader --"
unlead 2
wait_cond 25 "sans leader, la VIP disparaît partout" '[ "$(holders)" = 0 ]'
echo "-- les deux se croient leader (anomalie simulée) : VRRP en désigne un seul --"
lead 1; lead 2
wait_cond 25 "un porteur exactement" '[ "$(holders)" = 1 ]'
sleep 5
expect_eq "…et il le reste (pas de bascule en boucle)" 1 "$(holders)"
echo "-- panne brutale de Keepalived sur le porteur --"
for n in 1 2; do if vip_on $n; then H=$n; fi; done
O=$((3 - H)); eval "kill -9 \$KPID$H"; pkill -9 -f "keepalived.*n$H/etc" 2>/dev/null
sleep 1; ip netns exec "kn$H" ip addr del 10.55.0.100/24 dev "vk$H" 2>/dev/null   # le noyau garde l'adresse d'un Keepalived tué : un redémarrage de service la retire
wait_cond 30 "l'autre nœud (leader) reprend la VIP" "vip_on $O"
echo "-- arrêt propre du service --"
eval "kill \$KPID$O"
wait_cond 15 "arrêt propre : la VIP est retirée" "! vip_on $O"

note "non couvert : ARP gratuit vu par de vrais équipements, bascule avec une vraie coupure réseau physique, interaction avec le pare-feu nftables (règle protocole 112 testée en b10), latence de bascule en production (les minuteries ici sont celles du produit : test de santé 2 s × 2)"
finish
