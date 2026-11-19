#!/usr/bin/env bash
# samba-lab.sh start|stop|extra DOSSIER — contrôleur de domaine Samba AD JETABLE pour les tests « live » (domaine LAB / lab.test, LDAPS réel,
# certificat auto-signé généré par Samba, règle de chaîne d'appartenance réelle). Utilisé par webui/tests/e2e-iter39.test.ts.
# « extra » (0.13.3) complète un annuaire DÉJÀ démarré pour les règles d'accès : groupes aux noms difficiles (virgule, accent, barre oblique inverse), utilisateur
# sans groupe (erin), machine PC003 dans grp-vpn. Séparé de « start » : e2e-iter39 attend la liste exacte des groupes d'alice.
# Prérequis : root, samba + samba-ad-provision + python3-samba, ldap-utils (ldapmodify, ldapwhoami), ports 389 / 636 libres,
# et « 127.0.0.1 dc1.lab.test » dans /etc/hosts (le certificat porte ce nom : la vérification du nom d'hôte est faite pour de vrai).
# Code de sortie : 0 prêt · 3 prérequis absent (le test doit être ignoré) · 1 échec.
set -u
cmd="${1:-}"; D="${2:-}"
[ -n "$D" ] || { echo "usage : samba-lab.sh start|stop|extra DOSSIER" >&2; exit 2; }
SMB="$D/etc/smb.conf"
listen() {   # un socket TCP écoute-t-il sur ce port ? (lecture de /proc ; /proc/net/tcp6 est absent sans IPv6)
  local hex; hex="$(printf '%04X' "$1")"
  cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v h=":$hex" '$4 == "0A" && $2 ~ (h "$") { f = 1 } END { exit !f }'
}
skip() { echo "SKIP: $*" >&2; exit 3; }

if [ "$cmd" = stop ]; then
  for f in "$D/samba.pid" "$D/run/samba.pid"; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
  sleep 1; exit 0
fi
if [ "$cmd" = extra ]; then
  PY=""; for p in /usr/bin/python3.12 /usr/bin/python3; do [ -x "$p" ] && "$p" -c 'import ldb' 2>/dev/null && { PY="$p"; break; }; done
  [ -n "$PY" ] || skip "aucun Python avec le module ldb"
  S=("$PY" "$(command -v samba-tool)"); C=(--configfile="$SMB")
  export LDAPTLS_CACERT="$D/private/tls/ca.pem"
  ADM="administrator@lab.test"; PW='Passw0rd-Lab-1!'; H="ldaps://dc1.lab.test"
  {
    "${S[@]}" user create erin "Passw0rd-erin-1!" --given-name=erin --surname=Test --mail-address="erin@lab.test" "${C[@]}" || exit 1
    "${S[@]}" computer create PC003 "${C[@]}" || exit 1
    "${S[@]}" group addmembers grp-vpn 'PC003$' "${C[@]}" && "${S[@]}" group addmembers grp-wifi 'PC003$' "${C[@]}" || exit 1
    # le premier DN contient une virgule échappée ET un accent : il passe en base64 (« dn:: »), sinon l'encodage dépend de la locale du testeur
    ldapmodify -H "$H" -D "$ADM" -w "$PW" -a <<LDIF
dn:: $(printf '%s' "CN=Réseau\\, Wi-Fi d'essai,CN=Users,DC=lab,DC=test" | base64 -w0)
objectClass: group
sAMAccountName: reseau-wifi-essai
member: CN=alice Test,CN=Users,DC=lab,DC=test

dn: CN=back\\\\slash,CN=Users,DC=lab,DC=test
objectClass: group
sAMAccountName: back-slash-grp
member: CN=alice Test,CN=Users,DC=lab,DC=test

dn: CN=PC003,CN=Computers,DC=lab,DC=test
changetype: modify
replace: dNSHostName
dNSHostName: pc003.lab.test
-
replace: userAccountControl
userAccountControl: 4096
LDIF
  } >"$D/extra.log" 2>&1 || { tail -8 "$D/extra.log" >&2; exit 1; }
  echo "extra ok"; exit 0
fi
[ "$cmd" = start ] || { echo "usage : samba-lab.sh start|stop|extra DOSSIER" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || skip "root requis"
for b in /usr/sbin/samba samba-tool ldapmodify ldapwhoami; do command -v "$b" >/dev/null || skip "$b absent"; done
[ -d /usr/share/samba/setup ] || skip "paquet samba-ad-provision absent"
if listen 389 || listen 636; then skip "ports 389 / 636 déjà utilisés"; fi
[ "$(getent hosts dc1.lab.test | awk '{print $1}')" = "127.0.0.1" ] || skip "ajouter « 127.0.0.1 dc1.lab.test » à /etc/hosts"
# samba-tool a besoin du Python pour lequel les modules Samba sont compilés (pas forcément « python3 » du PATH)
PY=""; for p in /usr/bin/python3.12 /usr/bin/python3; do [ -x "$p" ] && "$p" -c 'import ldb' 2>/dev/null && { PY="$p"; break; }; done
[ -n "$PY" ] || skip "aucun Python avec le module ldb"
S=("$PY" "$(command -v samba-tool)"); C=(--configfile="$SMB")

rm -rf "$D"; mkdir -p "$D"
"${S[@]}" domain provision --targetdir="$D" --use-rfc2307 --realm=LAB.TEST --domain=LAB --adminpass='Passw0rd-Lab-1!' --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --option="dns forwarder=127.0.0.1" --option="ntlm auth=yes" --host-name=dc1 --host-ip=127.0.0.1 --option="pid directory=$D/run" >"$D/provision.log" 2>&1 || { tail -5 "$D/provision.log" >&2; exit 1; }
mkdir -p "$D/run"
# le démon ne doit hériter d'aucun descripteur du testeur (sinon spawnSync attendrait sa fin)
( cd "$D" || exit 1; setsid nohup /usr/sbin/samba -s "$SMB" -i -M single >"$D/samba.log" 2>&1 </dev/null & echo $! > "$D/samba.pid" )
for _ in $(seq 1 60); do listen 636 && break; sleep 0.5; done
listen 636 || { tail -5 "$D/samba.log" >&2; exit 1; }
sleep 1
export LDAPTLS_CACERT="$D/private/tls/ca.pem"
ADM="administrator@lab.test"; PW='Passw0rd-Lab-1!'; H="ldaps://dc1.lab.test"
{
  "${S[@]}" domain passwordsettings set --account-lockout-threshold=3 --account-lockout-duration=30 --reset-account-lockout-after=30 --complexity=off "${C[@]}"
  for u in alice bob carol dave svc-radius; do "${S[@]}" user create "$u" "Passw0rd-$u-1!" --given-name="$u" --surname=Test --mail-address="$u@lab.test" "${C[@]}" || exit 1; done
  "${S[@]}" user disable bob "${C[@]}"
  for g in grp-wifi grp-wifi-it grp-tout-acces grp-vpn; do "${S[@]}" group add "$g" "${C[@]}" || exit 1; done
  "${S[@]}" group addmembers grp-wifi-it alice,dave "${C[@]}"       # alice → grp-wifi-it → grp-wifi → grp-tout-acces : trois niveaux d'imbrication
  "${S[@]}" group addmembers grp-wifi grp-wifi-it "${C[@]}"
  "${S[@]}" group addmembers grp-tout-acces grp-wifi "${C[@]}"
  "${S[@]}" group addmembers grp-vpn alice "${C[@]}"                # appartenance directe
  "${S[@]}" computer create PC001 "${C[@]}"; "${S[@]}" computer create PC002 "${C[@]}"   # une machine fraîchement créée est désactivée tant qu'elle n'a pas rejoint le domaine
  "${S[@]}" group addmembers grp-wifi 'PC001$' "${C[@]}"
  ldapmodify -H "$H" -D "$ADM" -w "$PW" <<LDIF
dn: CN=carol Test,CN=Users,DC=lab,DC=test
changetype: modify
replace: accountExpires
accountExpires: 132000000000000000

dn: CN=PC001,CN=Computers,DC=lab,DC=test
changetype: modify
replace: dNSHostName
dNSHostName: pc001.lab.test
-
replace: userAccountControl
userAccountControl: 4096

dn: CN=PC002,CN=Computers,DC=lab,DC=test
changetype: modify
replace: dNSHostName
dNSHostName: pc002.lab.test
LDIF
} >"$D/populate.log" 2>&1 || { tail -8 "$D/populate.log" >&2; exit 1; }
for i in 1 2 3; do ldapwhoami -H "$H" -D "dave@lab.test" -w "mauvais-$i" >/dev/null 2>&1; done   # trois échecs : dave est verrouillé
echo "ready ca=$D/private/tls/ca.pem"
