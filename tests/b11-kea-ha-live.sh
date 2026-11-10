#!/usr/bin/env bash
# Batterie 11 (réel) — deux vrais « kea-dhcp4 » avec la configuration produite par ddibuntu-reload, en load-balancing, TLS mutuel, sur la boucle locale
# (127.0.2.1 et 127.0.2.2, port 8000). Les baux sont obtenus par de vrais échanges DHCP via un agent de relais (giaddr) : tests/relay_client.py.
# Seuls les chemins (socket, baux, interface) et les minuteries HA sont adaptés pour tenir sur une machine : les minuteries sont ACCÉLÉRÉES ici
# (production : heartbeat 10 s, max-response-delay 60 s). Demande root, kea-dhcp4 et les bibliothèques HA.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"
for t in kea-dhcp4 openssl python3 ip; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }

W="$T_TMP/w"; mkdir -p "$W"
IP1=127.0.2.1; IP2=127.0.2.2; RELAY=10.20.0.1
PIDS=""
cleanup() { for p in $PIDS; do kill -9 "$p" 2>/dev/null; done; ip addr del $IP1/32 dev lo 2>/dev/null; ip addr del $IP2/32 dev lo 2>/dev/null; ip addr del $RELAY/32 dev lo 2>/dev/null; rm -rf "$T_TMP"; }
trap cleanup EXIT
ip addr add $IP1/32 dev lo 2>/dev/null; ip addr add $IP2/32 dev lo 2>/dev/null; ip addr add $RELAY/32 dev lo 2>/dev/null

# --- PKI de test et dossiers de chaque nœud
openssl ecparam -name prime256v1 -genkey -noout -out "$W/ca.key" 2>/dev/null
openssl req -x509 -new -key "$W/ca.key" -subj /CN=test-ca -days 2 -out "$W/ca.crt" 2>/dev/null
for n in 1 2; do
  d="$W/n$n"; mkdir -p "$d/cl/pki" "$d/gen" "$d/etc" "$d/state" "$d/run" "$d/lib"
  cp "$W/ca.crt" "$d/cl/pki/ca.crt"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/cl/pki/node.key" 2>/dev/null
  openssl req -new -key "$d/cl/pki/node.key" -subj "/CN=n$n" -out "$d/n.csr" 2>/dev/null
  eval "ipn=\$IP$n"; printf 'subjectAltName=IP:%s\n' "$ipn" > "$d/ext"
  openssl x509 -req -in "$d/n.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$d/ext" -out "$d/cl/pki/node.crt" 2>/dev/null
  printf 'CLUSTER_NAME=lab\nNODE_NAME=n%s\nNODE_ROLE=data\nNODE_IP=%s\nREPL_NET=127.0.2.0/24\nPEERS=n1=%s:data n2=%s:data\nCA_NODE=0\n' "$n" "$ipn" "$IP1" "$IP2" > "$d/cl/cluster.conf"
  cat > "$d/gen/kea-dhcp4.conf" <<JSON
{ "Dhcp4": {
  "interfaces-config": { "interfaces": ["lo/$ipn"], "dhcp-socket-type": "udp" },
  "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 3600,
  "subnet4": [ { "id": 1, "subnet": "10.20.0.0/24", "pools": [ { "pool": "10.20.0.100 - 10.20.0.250" } ], "relay": { "ip-addresses": ["$RELAY"] } } ],
  "loggers": [ { "name": "kea-dhcp4", "output_options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
JSON
  env DDI_GENERATED_DIR="$d/gen" DDI_KEA_ETC="$d/etc" DDI_STATE_DIR="$d/state" DDI_CLUSTER_DIR="$d/cl" DDI_RELOAD_NOSERVICES=1 \
      DDI_KEA_LEASE_FILE="$d/lib/leases.csv" bash "$RELOAD" --kea-only >"$d/reload.log" 2>&1 || { ko "ddibuntu-reload --kea-only n$n" "$(tail -3 "$d/reload.log")"; finish; exit; }
  # adaptation au banc UNIQUEMENT : socket, interface déjà posée ci-dessus, minuteries accélérées
  python3 - "$d/etc/kea-dhcp4.conf" "$d/run/kea4.sock" <<'PY'
import json, sys
f, sock = sys.argv[1:3]
d = json.load(open(f)); k = d["Dhcp4"]
k["control-socket"]["socket-name"] = sock
for h in k["hooks-libraries"]:
    if "libdhcp_ha" in h["library"]:
        ha = h["parameters"]["high-availability"][0]
        ha.update({"heartbeat-delay": 1000, "max-response-delay": 4000, "max-ack-delay": 1000, "max-unacked-clients": 1})
json.dump(d, open(f, "w"), indent=2)
PY
done
ok "configurations finales produites par ddibuntu-reload pour n1 et n2"

kstart() {   # kstart N
  local d="$W/n$1"
  KEA_PIDFILE_DIR="$d/run" KEA_LOCKFILE_DIR="$d/run" kea-dhcp4 -c "$d/etc/kea-dhcp4.conf" >"$d/out.log" 2>&1 &
  eval "PID$1=$!"; PIDS="$PIDS $!"
}
kstop() { eval "local p=\$PID$1"; kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null; rm -f "$W/n$1/run/kea4.sock" "$W/n$1/run/kea4.sock.lock"; }
kc() {   # kc N 'json' : commande sur la socket de contrôle du nœud N
  python3 - "$W/n$1/run/kea4.sock" "$2" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]); s.sendall(sys.argv[2].encode())
d = b""
while True:
    c = s.recv(65536); d += c
    try: json.loads(d); break
    except ValueError: pass
print(d.decode())
PY
}
hastate() {   # hastate N local|remote
  kc "$1" '{"command":"status-get"}' | python3 -c "
import json,sys
a=json.load(sys.stdin)['arguments']['high-availability'][0]['ha-servers']
print(a['$2'].get('state') or a['$2'].get('last-state'))"
}
has_lease() { kc "$1" "{\"command\":\"lease4-get\",\"arguments\":{\"ip-address\":\"$2\"}}" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["result"]==0 else 1)'; }
lease_set() { kc "$1" '{"command":"lease4-get-all"}' | python3 -c 'import json,sys; print(" ".join(sorted(l["ip-address"] for l in json.load(sys.stdin)["arguments"].get("leases",[]))))'; }
wait_cond() { local s="$1" d="$2" e="$3" i=0; while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
relay() { python3 "$ROOT/tests/relay_client.py" "$RELAY" "$1" "$IP1,$IP2" ${2:+$2} ${3:+$3}; }
jget() { python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('$2') or '')" "$1"; }

echo "== Démarrage des deux serveurs =="
kstart 1; kstart 2
wait_cond 30 "n1 répond sur sa socket de contrôle" 'kc 1 "{\"command\":\"version-get\"}"'
wait_cond 30 "n2 répond sur sa socket de contrôle" 'kc 2 "{\"command\":\"version-get\"}"'
wait_cond 60 "n1 en load-balancing" '[ "$(hastate 1 local)" = load-balancing ]'
wait_cond 60 "n2 en load-balancing" '[ "$(hastate 2 local)" = load-balancing ]'
wait_cond 10 "n1 voit n2 en load-balancing" '[ "$(hastate 1 remote)" = load-balancing ]'
expect_eq "n2 voit n1 en load-balancing" load-balancing "$(hastate 2 remote)"
expect_eq "n1 a le rôle primary" primary "$(kc 1 '{"command":"status-get"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["arguments"]["high-availability"][0]["ha-servers"]["local"]["role"])')"
expect_eq "n2 a le rôle secondary" secondary "$(kc 2 '{"command":"status-get"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["arguments"]["high-availability"][0]["ha-servers"]["local"]["role"])')"

echo "== Baux : échanges DHCP réels via relais, synchronisation vers le partenaire =="
A1=0; A2=0; N=0; BAD=0
for i in $(seq 1 14); do
  mac=$(printf '02:00:00:00:01:%02x' "$i"); r="$(relay "$mac")"; srv="$(jget "$r" server)"; ack="$(jget "$r" ack)"
  if [ -z "$ack" ]; then BAD=$((BAD + 1)); continue; fi
  N=$((N + 1)); [ "$srv" = "$IP1" ] && A1=$((A1 + 1)); [ "$srv" = "$IP2" ] && A2=$((A2 + 1))
  eval "other=\$([ \"$srv\" = \"$IP1\" ] && echo 2 || echo 1)"
  j=0; while [ "$j" -lt 10 ]; do has_lease "$other" "$ack" && break; sleep 0.5; j=$((j + 1)); done
  has_lease "$other" "$ack" || { BAD=$((BAD + 1)); echo "    bail $ack ($mac, servi par $srv) absent chez le partenaire"; }
done
expect_eq "14 clients servis (ACK reçus)" 14 "$N"
check "le trafic est réparti : les deux serveurs répondent" test "$A1" -gt 0 -a "$A2" -gt 0
expect_eq "chaque bail est présent chez le partenaire" 0 "$BAD"
expect_eq "les deux serveurs ont exactement les mêmes baux" "$(lease_set 1)" "$(lease_set 2)"
SERVED_BEFORE="$(lease_set 1)"

echo "== Panne du partenaire (arrêt brutal de n2) =="
kstop 2
wait_cond 30 "n1 détecte la perte de contact" '[ "$(hastate 1 local)" = communication-recovery ] || [ "$(hastate 1 local)" = partner-down ] || [ "$(hastate 1 local)" = load-balancing -a "$(hastate 1 remote)" != load-balancing ]'
# le basculement exige du trafic client sans réponse du partenaire (max-unacked-clients) : on en fournit
i=0; while [ "$i" -lt 40 ] && [ "$(hastate 1 local)" != partner-down ]; do
  relay "$(printf '02:00:00:00:02:%02x' $((i % 30 + 1)))" --discover-only --secs=10 >/dev/null 2>&1; i=$((i + 1))
done
expect_eq "n1 passe en partner-down" partner-down "$(hastate 1 local)"
OK2=0; for i in $(seq 1 10); do r="$(relay "$(printf '02:00:00:00:03:%02x' "$i")")"; [ "$(jget "$r" server)" = "$IP1" ] && [ -n "$(jget "$r" ack)" ] && OK2=$((OK2 + 1)); done
expect_eq "n1 sert seul TOUS les nouveaux clients (10/10)" 10 "$OK2"
DOWN_LEASES="$(lease_set 1)"

echo "== Retour du partenaire =="
kstart 2
wait_cond 60 "n2 revient en load-balancing" '[ "$(hastate 2 local)" = load-balancing ]'
wait_cond 60 "n1 revient en load-balancing" '[ "$(hastate 1 local)" = load-balancing ]'
expect_eq "n2 a rattrapé les baux accordés pendant la panne" "$DOWN_LEASES" "$(lease_set 2)"
check "les baux d'avant la panne sont toujours là" bash -c "for a in $SERVED_BEFORE; do case ' $(lease_set 2) ' in *\" \$a \"*) ;; *) exit 1;; esac; done"

echo "== Nouveau bail après retour à la normale =="
r="$(relay 02:00:00:00:04:01)"; a="$(jget "$r" ack)"; s="$(jget "$r" server)"; other=$([ "$s" = "$IP1" ] && echo 2 || echo 1)
check "ACK reçu" test -n "$a"
wait_cond 10 "…et répliqué chez le partenaire" "has_lease $other $a"

note "non couvert : coupure réseau réelle entre deux machines, minuteries de production (10 s / 60 s), relais réels qui listent les deux serveurs, charge ; à rejouer sur le premier laboratoire"
finish
