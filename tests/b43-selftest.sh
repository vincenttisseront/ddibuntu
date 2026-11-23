#!/usr/bin/env bash
# Batterie 43 — tests de fumée de l'appliance (ddibuntu-selftest), utilisés par l'instance de validation de la chaîne de publication.
# Faux services : console (serveur HTTP local), ddibuntu-health, named-checkconf, kea-dhcp4, dig. Ne demande ni root ni systemd.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
for t in python3 curl; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
ST="$RFS/usr/local/sbin/ddibuntu-selftest"
W="$T_TMP/w"; R="$W/root"; SRV="$W/srv"; F="$W/fake"; PORT=$((20000 + RANDOM % 20000))
mkdir -p "$R/usr/local/lib/ddibuntu" "$R/var/lib/ddibuntu" "$R/etc/ddibuntu" "$SRV/api/auth" "$F"
mk() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod "${3:-644}" "$1"; }
jget() { python3 -c "import json,sys; d=json.load(open('$1')); print(d.get('$2'))" 2>/dev/null; }
jcheck() { python3 -c "import json,sys; d=json.load(open('$1')); print(next((c['result'] for c in d['checks'] if c['name']=='$2'), 'absent'))" 2>/dev/null; }

mk "$R/usr/local/lib/ddibuntu/VERSION" 1.2.3
mk "$R/var/lib/ddibuntu/installed-version" 1.2.3
mk "$R/var/lib/ddibuntu/update-status.json" '{"state":"done","current":"1.2.3"}'
mk "$SRV/api/health" '{"status":"ok"}'
mk "$SRV/api/auth/providers" '{"version":"1.2.3","local":true}'
# faux ddibuntu-health : photographie lue dans $F/health.json
mk "$F/health.json" "{\"services\":[{\"name\":\"console\",\"state\":\"active\",\"expected\":true},{\"name\":\"dns\",\"state\":\"active\",\"expected\":true},{\"name\":\"dhcp\",\"state\":\"active\",\"expected\":true},{\"name\":\"keepalived\",\"state\":\"inactive\",\"expected\":false}],\"postgres\":true,\"disks\":[{\"mount\":\"/\",\"sizeBytes\":1000,\"availBytes\":500}],\"certs\":[{\"name\":\"console\",\"notAfter\":$(( $(date +%s) + 86400 * 90 ))}]}"
mk "$F/health" "#!/bin/bash
[ \"\$1\" = show ] && cat '$F/health.json'" 755
mk "$F/named-checkconf" "#!/bin/bash
[ -e '$F/bind-ko' ] && { echo 'zone db.x: syntax error'; exit 1; }
[ \"\$1\" = -l ] && { echo 'exemple.test IN _default primary'; echo '0.10.in-addr.arpa IN _default primary'; }
exit 0" 755
mk "$F/kea-dhcp4" "#!/bin/bash
[ -e '$F/kea-ko' ] && { echo 'DHCP4_CONFIG_LOAD_FAIL: erreur de syntaxe'; exit 1; }
exit 0" 755
mk "$F/dig" "#!/bin/bash
[ -e '$F/dig-ko' ] || echo 'ns1.exemple.test. hostmaster.exemple.test. 1 3600 600 86400 300'" 755

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$SRV" >"$W/http.log" 2>&1 &
echo $! > "$W/http.pid"
sleep 1
trap 'kill "$(cat "$W/http.pid")" 2>/dev/null; rm -rf "$T_TMP"' EXIT
export DDI_TEST=1 DDI_ROOT="$R" DDI_SELFTEST_URL="http://127.0.0.1:$PORT" DDI_HEALTH_CMD="$F/health" \
  DDI_NAMED_CHECKCONF="$F/named-checkconf" DDI_KEA_DHCP4="$F/kea-dhcp4" DDI_DIG="$F/dig"
run() { bash "$ST" "$@" > "$W/out" 2>&1; echo $?; }

echo "== 1. Tout va bien =="
expect_eq "code 0" 0 "$(run --expect-version 1.2.3)"
expect_grep "sortie texte : une ligne par contrôle" "ok +console-version +1\.2\.3" "$W/out"
expect_eq "JSON : code 0" 0 "$(run --expect-version 1.2.3 --json)"
expect_eq "JSON : ok = True" True "$(jget "$W/out" ok)"
expect_eq "JSON : version" 1.2.3 "$(jget "$W/out" version)"
for c in version update-state console-health console-version service:console service:dns service:dhcp postgres disk:/ cert:console bind-config dns-answer kea-config; do
  expect_eq "contrôle $c réussi" ok "$(jcheck "$W/out" "$c")"
done
expect_eq "service non attendu (keepalived) ignoré" absent "$(jcheck "$W/out" service:keepalived)"

echo "== 2. Mauvaise version =="
expect_eq "version attendue différente : code 1" 1 "$(run --expect-version 1.2.4 --json)"
expect_eq "…contrôle version en échec" ko "$(jcheck "$W/out" version)"
expect_eq "…la console sert l'ancienne version : en échec" ko "$(jcheck "$W/out" console-version)"
mk "$SRV/api/auth/providers" '{"version":"1.2.2"}'
expect_eq "console encore sur l'ancienne version (processus non redémarré) : code 1" 1 "$(run --expect-version 1.2.3 --json)"
expect_eq "…console-version en échec" ko "$(jcheck "$W/out" console-version)"
mk "$SRV/api/auth/providers" '{"version":"1.2.3"}'

echo "== 3. Services et configurations =="
sed -i 's/"name":"dhcp","state":"active"/"name":"dhcp","state":"failed"/' "$F/health.json"
expect_eq "Kea arrêté : code 1" 1 "$(run --json)"
expect_eq "…service:dhcp en échec" ko "$(jcheck "$W/out" service:dhcp)"
sed -i 's/"name":"dhcp","state":"failed"/"name":"dhcp","state":"active"/' "$F/health.json"
: > "$F/kea-ko"; expect_eq "configuration Kea refusée par kea-dhcp4 -t : code 1" 1 "$(run --json)"; rm -f "$F/kea-ko"
expect_eq "…kea-config en échec" ko "$(jcheck "$W/out" kea-config)"
: > "$F/bind-ko"; expect_eq "configuration BIND refusée : code 1" 1 "$(run --json)"; rm -f "$F/bind-ko"
: > "$F/dig-ko"; expect_eq "zone primaire sans réponse DNS : code 1" 1 "$(run --json)"; rm -f "$F/dig-ko"
expect_eq "…dns-answer en échec" ko "$(jcheck "$W/out" dns-answer)"
sed -i 's/"postgres":true/"postgres":false/' "$F/health.json"
expect_eq "PostgreSQL ne répond pas : code 1" 1 "$(run --json)"; sed -i 's/"postgres":false/"postgres":true/' "$F/health.json"

echo "== 3b. Jamais « rien à contrôler, donc bon » =="
cp "$F/health.json" "$F/health.ok"
echo 'pas du json' > "$F/health.json"; expect_eq "photographie illisible : code 1" 1 "$(run --json)"
expect_eq "…contrôle health en échec" ko "$(jcheck "$W/out" health)"
echo '{"services":[]}' > "$F/health.json"; expect_eq "photographie sans service : code 1" 1 "$(run --json)"
cp "$F/health.ok" "$F/health.json"
expect_eq "dig absent alors que le DNS est actif : code 1" 1 "$(DDI_DIG=/nonexistent/dig run --json)"
expect_eq "…dns-answer en échec" ko "$(jcheck "$W/out" dns-answer)"
mk "$F/named-checkconf" "#!/bin/bash
[ \"\$1\" = -l ] && echo 'secondaire.test IN _default secondary'
exit 0" 755
expect_eq "aucune zone primaire : code 1" 1 "$(run --json)"
mk "$F/named-checkconf" "#!/bin/bash
[ -e '$F/bind-ko' ] && { echo 'zone db.x: syntax error'; exit 1; }
[ \"\$1\" = -l ] && { echo 'exemple.test IN _default primary'; }
exit 0" 755
mk "$SRV/api/health" '{"status":"waiting_leader"}'
expect_eq "« attend un leader » hors cluster : code 1" 1 "$(run --json)"
expect_eq "…console-health en échec" ko "$(jcheck "$W/out" console-health)"
: > "$W/cluster.conf"; expect_eq "…mais normal pour un secondaire de cluster" 0 "$(DDI_CLUSTER_CONF="$W/cluster.conf" run --json)"
mk "$SRV/api/health" '{"status":"ok"}'
mk "$R/var/lib/ddibuntu/update-status.json" '{"state":"installing","current":"1.2.3"}'
expect_eq "mise à jour en cours : code 1" 1 "$(run --json)"
expect_eq "…update-state en échec" ko "$(jcheck "$W/out" update-state)"
mk "$R/var/lib/ddibuntu/update-status.json" '{"state":"done","current":"1.2.3"}'
expect_eq "retour à la normale : code 0" 0 "$(run --json)"

echo "== 4. Mise à jour en échec, console absente =="
mk "$R/var/lib/ddibuntu/update-status.json" '{"state":"failed","current":"1.2.3","error":"SIGNATURE INVALIDE"}'
expect_eq "dernière mise à jour en échec : code 1" 1 "$(run --json)"
expect_eq "…update-state en échec" ko "$(jcheck "$W/out" update-state)"
mk "$R/var/lib/ddibuntu/update-status.json" '{"state":"done","current":"1.2.3"}'
kill "$(cat "$W/http.pid")" 2>/dev/null; sleep 0.5
s=$(date +%s); expect_eq "console injoignable, --wait 4 : code 1" 1 "$(run --wait 4 --json)"
d=$(( $(date +%s) - s )); if [ "$d" -ge 3 ] && [ "$d" -le 20 ]; then ok "…attente bornée ($d s)"; else ko "…attente inattendue ($d s)"; fi
expect_eq "…console-health en échec" ko "$(jcheck "$W/out" console-health)"

echo "== 5. Clés de signature des mises à jour =="
bash "$ST" --json > "$W/j.json" 2>/dev/null
expect_eq "version sans jeu de clés : contrôle ignoré" skip "$(jcheck "$W/j.json" update-keys)"
cp "$RFS/usr/local/lib/ddibuntu/release-keys.sh" "$R/usr/local/lib/ddibuntu/"
cp -r "$RFS/etc/ddibuntu/keys" "$R/etc/ddibuntu/"; cp "$RFS/etc/ddibuntu/update-pubkey.pem" "$R/etc/ddibuntu/"
bash "$ST" --json > "$W/j.json" 2>/dev/null
expect_eq "clés livrées : contrôle réussi" ok "$(jcheck "$W/j.json" update-keys)"
rm "$R/etc/ddibuntu/keys/release-secours.pem"
bash "$ST" --json > "$W/j.json" 2>/dev/null
expect_eq "clé de secours absente : contrôle en échec" ko "$(jcheck "$W/j.json" update-keys)"
rm -r "$R/etc/ddibuntu/keys" "$R/etc/ddibuntu/update-pubkey.pem"
bash "$ST" --json > "$W/j.json" 2>/dev/null
expect_eq "aucune clé : contrôle en échec" ko "$(jcheck "$W/j.json" update-keys)"
rm "$R/usr/local/lib/ddibuntu/release-keys.sh"

echo "== 6. Usage =="
expect_eq "option inconnue : code 2" 2 "$(run --oups)"
expect_eq "version mal formée : code 2" 2 "$(run --expect-version 'x; rm -rf /')"
expect_eq "--wait non numérique : code 2" 2 "$(run --wait abc)"
finish
