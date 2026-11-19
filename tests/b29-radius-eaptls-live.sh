#!/usr/bin/env bash
# Batterie 29 — EAP-TLS du service RADIUS (0.13.2) : PKI fabriquée avec openssl (racine, émettrice, certificats serveur et clients), ddibuntu-radius
# contre un VRAI FreeRADIUS (lancé par un faux systemctl) et de VRAIES poignées de main EAP-TLS (eapol_test, TLS 1.2 et 1.3) : certificat valide,
# révoqué, expiré, hors chaîne, mauvais usage ; CRL expirée ; validation stricte du dossier PKI ; installation des CRL sans redémarrage ; retour arrière.
# Prérequis : root, freeradius, eapol_test (paquet eapoltest), openssl ; sinon la batterie est ignorée.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=lib-pki.sh
. "$(dirname "$0")/lib-pki.sh"

RAD="$RFS/usr/local/sbin/ddibuntu-radius"
if [ "$(id -u)" -ne 0 ] || ! command -v freeradius >/dev/null || ! command -v eapol_test >/dev/null || ! command -v openssl >/dev/null; then
  note "prérequis absents (root, freeradius, eapol_test, openssl) : batterie ignorée"; finish; exit $?
fi
udp_listen() { local hex; hex="$(printf '%04X' "$1")"; cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk -v h=":$hex" '$2 ~ (h "$") { f = 1 } END { exit !f }'; }
if udp_listen 1812 || udp_listen 1813; then note "ports UDP 1812/1813 déjà utilisés : batterie ignorée"; finish; exit $?; fi
D="$T_TMP"; chmod 0755 "$D"
mkdir -p "$D/gen" "$D/run" "$D/state" "$D/bin" "$D/pki"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_RADIUS_DIR="$D/etc" DDI_RADIUS_LOCK="$D/lock" DDI_STATE_DIR="$D/state" DDI_RUN_DIR="$D/run" DDI_GENERATED_DIR="$D/gen"
export DDI_RADIUS_SYSTEMCTL="$D/bin/systemctl" DDI_FW_BIN="$D/bin/fw"
export DDI_RADIUS_AUTHLOG_DIR="$D/authlog" DDI_CONSOLE_GROUP=daemon
SELF="0123456789abcdef0123456789abcdef"

cat > "$D/bin/systemctl" <<SH
#!/bin/bash
P="$D/radiusd.pid"
alive() { [ -f "\$P" ] && kill -0 "\$(cat "\$P")" 2>/dev/null; }
case "\$1" in
  daemon-reload|enable) exit 0 ;;
  restart) [ -e "$D/failstart" ] && exit 1
           alive && { kill "\$(cat "\$P")"; sleep 0.5; }
           ( /usr/sbin/freeradius -f -d "$D/etc" >"$D/daemon.out" 2>&1 9>&- </dev/null & echo \$! > "\$P" ); sleep 1.5; exit 0 ;;
  disable) alive && kill "\$(cat "\$P")"; rm -f "\$P"; sleep 0.3; exit 0 ;;
  is-active) alive; exit \$? ;;
  is-enabled) exit 0 ;;
esac
SH
printf '#!/bin/bash\nexit 0\n' > "$D/bin/fw"; chmod +x "$D/bin/systemctl" "$D/bin/fw"
trap 'kill "$(cat "$D/radiusd.pid" 2>/dev/null)" 2>/dev/null; rm -rf "$T_TMP"' EXIT

clients() {
  local f="$D/clients.$RANDOM"
  printf 'client "ddi-selftest" {\n\tipaddr = 127.0.0.1\n\tsecret = "%s"\n\tshortname = ddi-selftest\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n' "$SELF" > "$f"; printf '%s' "$f"
}
rj() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d := d[k] for k in sys.argv[2].split(".")]; print(d)' "$1" "$2"; }

echo "== PKI de test (openssl) =="
P="$D/pki"
pki_root "$P/root" "Lab Root CA"; pki_inter "$P/issuing" "$P/root" "Lab Issuing CA"
pki_root "$P/xroot" "Autre Racine"; pki_inter "$P/xissuing" "$P/xroot" "Autre Emettrice"
pki_issue "$P/issuing" "$P/srv" "radius.lab.test" server "DNS:radius.lab.test"
pki_issue "$P/issuing" "$P/alice" "alice" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:alice@lab.test"
pki_issue "$P/issuing" "$P/pc001" "pc001" client "DNS:pc001.lab.test"
pki_issue "$P/issuing" "$P/bob" "bob" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:bob@lab.test"
pki_issue "$P/issuing" "$P/old" "old" client "" 20200101000000Z 20200201000000Z
pki_issue "$P/issuing" "$P/badeku" "badeku" clientbad ""
pki_issue "$P/xissuing" "$P/foreign" "foreign" client ""
pki_revoke "$P/issuing" "$P/bob.pem"
pki_crl "$P/issuing" "$P/crl.pem"; pki_crl "$P/issuing" "$P/crl-exp.pem" expire
# CRL émise « demain » (horloge de l'autorité en avance) : OpenSSL la juge « pas encore valide » et refuserait tous les certificats
openssl ca -batch -config "$P/issuing/openssl.cnf" -gencrl -crlexts crl_ext -crl_lastupdate "$(date -u -d '+1 day' +%Y%m%d%H%M%SZ)" -crl_nextupdate "$(date -u -d '+8 days' +%Y%m%d%H%M%SZ)" -out "$P/crl-fut.pem" 2>/dev/null
check "PKI de test fabriquée" test -s "$P/crl.pem"

mkdep() {   # mkdep DIR checkCrl [crl.pem|-] : dépôt de la console (pki.json, ca.pem, server.pem, server.key, crl/)
  rm -rf "$1"; mkdir -p "$1/crl"
  printf '{"checkCrl": %s}\n' "$2" > "$1/pki.json"
  cat "$P/root/ca.pem" "$P/issuing/ca.pem" > "$1/ca.pem"
  cat "$P/srv.pem" "$P/issuing/ca.pem" > "$1/server.pem"; cp "$P/srv.key" "$1/server.key"
  [ "${3:--}" = "-" ] || cp "$3" "$1/crl/issuing.pem"
}
DEP="$D/dep"

echo "== Validation stricte du dossier PKI (aucune écriture) =="
mkdep "$DEP" true "$P/crl.pem"
check "dépôt conforme accepté" "$RAD" check-pki "$DEP"
mkdep "$DEP" true -;                       check_fail "CRL manquante refusée quand les révocations sont vérifiées" "$RAD" check-pki "$DEP"
mkdep "$DEP" false -;                      check "sans CRL accepté quand la vérification des révocations est coupée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl-exp.pem";        check_fail "CRL expirée refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl-fut.pem";        check_fail "CRL émise dans le futur refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cp "$P/srv.pem" "$DEP/server.pem"; check_fail "chaîne du serveur sans l'intermédiaire refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cp "$P/alice.key" "$DEP/server.key"; check_fail "clé privée qui ne correspond pas refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cat "$P/root/ca.pem" > "$DEP/ca.pem"; check_fail "intermédiaire absente de la liste (CRL non vérifiable) refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cp "$P/issuing/ca.pem" "$DEP/ca.pem"; check_fail "liste sans racine refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cat "$P/xissuing/ca.pem" >> "$DEP/ca.pem"; check_fail "autorité d'une autre PKI sans sa racine refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cat "$P/srv.key" >> "$DEP/ca.pem"; check_fail "clé privée glissée dans ca.pem refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; openssl pkey -in "$P/srv.key" -aes256 -passout pass:secret -out "$DEP/server.key" 2>/dev/null; check_fail "clé chiffrée refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; pki_crl "$P/xissuing" "$P/xcrl.pem"; cp "$P/xcrl.pem" "$DEP/crl/autre.pem"; check_fail "CRL non signée par une autorité de la liste refusée" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; cp "$P/crl.pem" "$DEP/crl/../x.txt"; mkdir -p "$DEP/crl"; cp "$P/crl.pem" "$DEP/crl/mal nom.pem"; check_fail "nom de fichier de CRL piégé refusé" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; ln -sf /etc/passwd "$DEP/server.key.l"; rm "$DEP/server.key"; ln -s "$P/srv.key" "$DEP/server.key"; check_fail "lien symbolique refusé" "$RAD" check-pki "$DEP"
mkdep "$DEP" true "$P/crl.pem"; printf '{"checkCrl": "oui"}' > "$DEP/pki.json"; check_fail "option non booléenne refusée" "$RAD" check-pki "$DEP"
pki_issue "$P/issuing" "$P/srvcl" "client-only" client "DNS:x"; mkdep "$DEP" true "$P/crl.pem"; cat "$P/srvcl.pem" "$P/issuing/ca.pem" > "$DEP/server.pem"; cp "$P/srvcl.key" "$DEP/server.key"
check_fail "certificat sans usage « serveur » refusé" "$RAD" check-pki "$DEP"

echo "== Déploiement avec EAP-TLS =="
mkdep "$DEP" true "$P/crl.pem"
"$RAD" apply "$(clients)" "$DEP" >"$D/apply.out" 2>&1; rc=$?
expect_eq "apply avec PKI : code 0" 0 "$rc"
expect_grep "message : EAP-TLS activé" 'EAP-TLS activé' "$D/apply.out"
expect_eq "certs/ : 0750 root:freerad" "750 root freerad" "$(stat -c '%a %U %G' "$D/etc/certs")"
expect_eq "server.key : 0640 root:freerad" "640 root freerad" "$(stat -c '%a %U %G' "$D/etc/certs/server.key")"
expect_eq "module eap généré (plus de lien vers le paquet)" "regular file" "$(stat -c '%F' "$D/etc/mods-enabled/eap")"
expect_eq "modules : liste blanche + eap" "always attr_filter ddibuntu_authlog eap expr preprocess" "$(find "$D/etc/mods-enabled" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
expect_grep "EAP-TLS seul (pas d'autre méthode)" 'default_eap_type = tls' "$D/etc/mods-enabled/eap"
expect_nogrep "aucun mot de passe de clé en clair dans la configuration" 'private_key_password' "$D/etc/mods-enabled/eap"
expect_grep "révocations vérifiées" 'check_crl = yes' "$D/etc/mods-enabled/eap"
expect_grep "CRL périmée = refus" 'allow_expired_crl = no' "$D/etc/mods-enabled/eap"
expect_grep "TLS 1.2 minimum" 'tls_min_version = "1.2"' "$D/etc/mods-enabled/eap"
expect_grep "serveur virtuel de décision (refus par défaut)" 'server ddibuntu-check-eap-tls' "$D/etc/sites-available/ddibuntu"
check "CRL installée sous son nom de hachage" bash -c "ls '$D/etc/certs/crl' | grep -q '\\.r0\$'"
expect_eq "statut publié : EAP-TLS actif" True "$(rj "$D/run/radius-status.json" eap.enabled)"
expect_eq "statut publié : certificat du serveur" "CN=radius.lab.test" "$(rj "$D/run/radius-status.json" eap.server.subject)"
expect_eq "statut publié : 2 autorités" 2 "$(rj "$D/run/radius-status.json" eap.cas)"
expect_eq "statut publié : 1 CRL" 1 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["eap"]["crls"]))' "$D/run/radius-status.json")"

echo "== Poignées de main EAP-TLS réelles (eapol_test) =="
RLOG="$D/authlog/radius.log"; AL="$D/authlog/radius-auth.log"
eap() {   # eap CERT KEY [TLS13=1|0] : sortie d'eapol_test
  local c="$1" k="$2" v13="${3:-1}" cf="$D/eap.$RANDOM.conf"
  { echo 'network={'; echo ' key_mgmt=WPA-EAP'; echo ' eap=TLS'; echo ' identity="test@lab.test"'; echo " ca_cert=\"$P/root/ca.pem\""
    echo " client_cert=\"$c\""; echo " private_key=\"$k\""; [ "$v13" = 0 ] && echo ' phase1="tls_disable_tlsv1_3=1"'; echo '}'; } > "$cf"
  eapol_test -c "$cf" -a 127.0.0.1 -p 1812 -s "$SELF" -t 8 2>&1
}
lastlog() { tail -n "${1:-4}" "$RLOG" | grep -E 'Login (OK|incorrect)' | tail -n 1; }
for v in 1 0; do
  vn=$([ "$v" = 1 ] && echo "TLS 1.3 permis" || echo "TLS 1.2 imposé")
  r="$(eap "$P/alice.pem" "$P/alice.key" "$v")"
  echo "$r" | tail -1 | grep -q '^FAILURE' && ok "($vn) certificat valide : REFUSÉ faute de règle d'accès (refus par défaut)" || ko "($vn) certificat valide : refus attendu" "$(echo "$r" | tail -3)"
  expect_grep "($vn) le journal dit « certificat valide, aucune règle »" 'Login incorrect.*certificat valide, aucune regle' <(lastlog 6)
  echo "$r" | grep -q 'TLS: Certificate verification failed\|SSL: .*alert' && ko "($vn) l'échec n'est pas un échec TLS" "$(echo "$r" | grep -E 'alert|failed' | head -3)" || ok "($vn) la poignée de main TLS a abouti (aucune alerte)"
done
for case in "bob|révoqué" "old|expiré" "badeku|mauvais usage (EKU serveur)" "foreign|émis par une autre PKI"; do
  f="${case%%|*}"; label="${case#*|}"; k="$P/$f.key"; c="$P/$f.pem"
  [ "$f" = foreign ] && c="$P/foreign.pem"
  for v in 1 0; do
    vn=$([ "$v" = 1 ] && echo "1.3" || echo "1.2")
    r="$(eap "$c" "$k" "$v")"
    if echo "$r" | tail -1 | grep -q '^FAILURE'; then ok "(TLS $vn) certificat $label : refusé"; else ko "(TLS $vn) certificat $label : refus attendu" "$(echo "$r" | tail -3)"; fi
    if lastlog 8 | grep -q 'certificat valide, aucune regle'; then ko "(TLS $vn) certificat $label : refusé par le TLS, pas par la règle par défaut" "$(lastlog 8)"; else ok "(TLS $vn) certificat $label : refusé avant la règle (échec TLS)"; fi
  done
done

echo "== Preuve du chemin d'acceptation (règle temporaire « accepter » dans le site) =="
site="$D/etc/sites-available/ddibuntu"; cp "$site" "$D/site.orig"
sed -i 's/&Auth-Type := Reject/\&Auth-Type := Accept/' "$site"; "$D/bin/systemctl" restart freeradius.service
for v in 1 0; do
  vn=$([ "$v" = 1 ] && echo "TLS 1.3" || echo "TLS 1.2")
  r="$(eap "$P/alice.pem" "$P/alice.key" "$v")"
  echo "$r" | tail -1 | grep -q '^SUCCESS' && ok "($vn) certificat valide : EAP-Success (échange complet)" || ko "($vn) certificat valide : succès attendu quand la règle accepte" "$(echo "$r" | tail -3)"
  echo "$r" | grep -q 'MPPE keys OK: 1' && ok "($vn) clés MPPE cohérentes entre le client et le serveur" || ko "($vn) clés MPPE" "$(echo "$r" | tail -3)"
  r="$(eap "$P/bob.pem" "$P/bob.key" "$v")"; echo "$r" | tail -1 | grep -q '^FAILURE' && ok "($vn) certificat révoqué : refusé même quand la règle accepte" || ko "($vn) révoqué refusé" "$(echo "$r" | tail -3)"
done
cp "$D/site.orig" "$site"; "$D/bin/systemctl" restart freeradius.service
r="$(eap "$P/alice.pem" "$P/alice.key" 1)"; echo "$r" | tail -1 | grep -q '^FAILURE' && ok "règle par défaut remise : refus" || ko "règle par défaut remise : refus attendu" "$(echo "$r" | tail -2)"

echo "== CRL : installation (le service redémarre seulement si le jeu de CRL a changé) =="
pki_revoke "$P/issuing" "$P/alice.pem"; pki_crl "$P/issuing" "$P/crl2.pem"
sed -i 's/&Auth-Type := Reject/\&Auth-Type := Accept/' "$site"; "$D/bin/systemctl" restart freeradius.service   # règle « accepter » : seule la révocation peut refuser
r="$(eap "$P/alice.pem" "$P/alice.key" 1)"; echo "$r" | tail -1 | grep -q '^SUCCESS' && ok "avant la nouvelle CRL : alice (non révoquée) est acceptée" || ko "alice acceptée avant révocation" "$(echo "$r" | tail -2)"
mkdir -p "$D/gen/radius-pki/crl"; cp "$P/crl2.pem" "$D/gen/radius-pki/crl/issuing.pem"; printf '{"action":"crl"}\n' > "$D/gen/.radius-request"
pid1="$(cat "$D/radiusd.pid")"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "request crl : code 0" 0 "$rc"
check "…le service a redémarré (jeu de CRL modifié)" test "$pid1" != "$(cat "$D/radiusd.pid")"
expect_eq "…dépôt effacé" no "$([ -e "$D/gen/radius-pki" ] && echo yes || echo no)"
expect_grep "…résultat publié" 'CRL install.*révocations sont effectives' "$D/run/radius-result.json"
r="$(eap "$P/alice.pem" "$P/alice.key" 1)"
echo "$r" | tail -1 | grep -q '^FAILURE' && ok "alice révoquée : refusée tout de suite (même quand la règle accepte)" || ko "révocation effective immédiatement" "$(echo "$r" | tail -2)"
tail -n 12 "$RLOG" | grep -q 'certificate revoked' && ok "…le journal dit « certificate revoked »" || ko "journal : certificate revoked" "$(tail -n 3 "$RLOG")"
cp "$D/site.orig" "$site"; "$D/bin/systemctl" restart freeradius.service
pid2="$(cat "$D/radiusd.pid")"
mkdir -p "$D/gen/radius-pki/crl"; cp "$P/crl2.pem" "$D/gen/radius-pki/crl/issuing.pem"; printf '{"action":"crl"}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "mêmes CRL redéposées : code 0" 0 "$rc"
expect_eq "…aucun redémarrage inutile" "$pid2" "$(cat "$D/radiusd.pid")"
expect_grep "…résultat : inchangées" 'CRL inchangées' "$D/run/radius-result.json"
h1="$(cd "$D/etc/certs" && find crl -type f | sort | xargs sha256sum | sha256sum)"
mkdir -p "$D/gen/radius-pki/crl"; cp "$P/crl-exp.pem" "$D/gen/radius-pki/crl/issuing.pem"; printf '{"action":"crl"}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "CRL expirée déposée : refusée" 1 "$rc"
expect_eq "…résultat publié : échec" False "$(rj "$D/run/radius-result.json" ok)"
expect_eq "…CRL installées inchangées" "$h1" "$(cd "$D/etc/certs" && find crl -type f | sort | xargs sha256sum | sha256sum)"
mkdir -p "$D/gen/radius-pki/crl"; cp "$P/xcrl.pem" "$D/gen/radius-pki/crl/autre.pem"; printf '{"action":"crl"}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "CRL d'une autre PKI : refusée" 1 "$rc"
mkdir -p "$D/gen/radius-pki/crl"; printf '{"action":"crl"}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "aucune CRL déposée alors que les révocations sont vérifiées : refusée" 1 "$rc"
mkdir -p "$D/gen/radius-pki/crl"; cp "$P/crl.pem" "$D/gen/radius-pki/crl/issuing.pem"; printf '{"action":"crl"}\n' > "$D/gen/.radius-request"; touch "$D/failstart"
"$RAD" request >/dev/null 2>&1; rc=$?; rm -f "$D/failstart"
expect_eq "redémarrage impossible avec la nouvelle CRL : refusé" 1 "$rc"
expect_eq "…anciennes CRL rétablies" "$h1" "$(cd "$D/etc/certs" && find crl -type f | sort | xargs sha256sum | sha256sum)"
"$D/bin/systemctl" restart freeradius.service

echo "== Demande de la console avec PKI =="
mkdep "$D/gen/radius-pki" true "$P/crl2.pem"; cp "$(clients)" "$D/gen/radius-clients.conf"; printf '{"action":"apply","pki":true}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "request apply (pki) : code 0" 0 "$rc"
expect_eq "…dépôt PKI effacé (clé privée jamais conservée)" no "$([ -e "$D/gen/radius-pki" ] && echo yes || echo no)"
expect_nogrep "…résultat sans clé privée" 'PRIVATE KEY' "$D/run/radius-result.json"
expect_eq "…statut : EAP-TLS actif" True "$(rj "$D/run/radius-status.json" eap.enabled)"
# 0.14.16 : sous systemd le démon (et son contrôle de démarrage) tourne en tant que freerad, pas en root : le faux systemctl de cette batterie le lançait en root,
# ce qui avait masqué un fichier (mods-enabled/eap) illisible pour freerad. Contrôle EN TANT QUE freerad, comme le service réel.
check "…le démon, EN TANT QUE freerad, lit toute l'arborescence (freeradius -Cx)" runuser -u freerad -- /usr/sbin/freeradius -d "$D/etc" -Cx -lstdout
expect_eq "…aucun fichier de l'arborescence hors du groupe freerad (liens symboliques exceptés)" "" "$(find "$D/etc" ! -type l ! -group freerad)"
expect_eq "…aucun fichier lisible par tous (clés)" "" "$(find "$D/etc" -type f -perm -004)"
expect_eq "…aucun fichier temporaire de PKI oublié" 0 "$(find /tmp -maxdepth 1 -name 'ddi-radius-pki.*' 2>/dev/null | wc -l)"
tree_hash() { (cd "$D/etc" && find . -type f -o -type l | sort | xargs -I{} sh -c 'printf "%s " {}; readlink {} || sha256sum < {}' | sha256sum); }
h1="$(tree_hash)"
mkdep "$D/gen/radius-pki" true "$P/crl-exp.pem"; cp "$(clients)" "$D/gen/radius-clients.conf"; printf '{"action":"apply","pki":true}\n' > "$D/gen/.radius-request"
"$RAD" request >/dev/null 2>&1; rc=$?
expect_eq "PKI invalide (CRL expirée) : déploiement refusé" 1 "$rc"
expect_eq "…dépôt effacé malgré le refus" no "$([ -e "$D/gen/radius-pki" ] && echo yes || echo no)"
expect_eq "…arborescence inchangée" "$h1" "$(tree_hash)"
expect_eq "…le service tourne toujours" yes "$("$D/bin/systemctl" is-active x && echo yes || echo no)"

echo "== Retour arrière si le service ne démarre pas =="
touch "$D/failstart"; mkdep "$DEP" false -
check_fail "démarrage impossible : apply avec PKI échoue" "$RAD" apply "$(clients)" "$DEP"
expect_eq "…arborescence restaurée à l'identique (certificats compris)" "$h1" "$(tree_hash)"
rm -f "$D/failstart"
expect_eq "…aucune sauvegarde (avec ses clés) ne reste" no "$([ -e "$D/state/radius-backup" ] && echo yes || echo no)"

echo "== Poste qui ne fait pas confiance au serveur : l'alerte TLS du poste arrive au journal du démon =="
cf="$D/eap.untrust.conf"
{ echo 'network={'; echo ' key_mgmt=WPA-EAP'; echo ' eap=TLS'; echo ' identity="test@lab.test"'; echo " ca_cert=\"$P/xroot/ca.pem\""; echo " client_cert=\"$P/alice.pem\""; echo " private_key=\"$P/alice.key\""; echo '}'; } > "$cf"
r="$(eapol_test -c "$cf" -a 127.0.0.1 -p 1812 -s "$SELF" -t 8 2>&1)"
echo "$r" | tail -1 | grep -q '^FAILURE' && ok "poste sans confiance dans l'autorité du serveur : refusé" || ko "poste sans confiance : refus attendu" "$(echo "$r" | tail -3)"
sleep 1
[ -n "${B29_SHOW:-}" ] && { echo "--- journal technique (alertes) ---"; grep -n -i 'alert\|unknown ca' "$RLOG" | tail -6; echo "--- dernier refus du journal d'authentifications ---"; tail -n 1 "$AL"; }
expect_grep "journal technique : l'alerte TLS envoyée par le poste est lisible (« Alert read »)" 'Alert read:fatal' "$RLOG"

echo "== Journal des authentifications : certificat et raison de chaque décision =="
expect_eq "journal : fichier 0640 freerad:groupe de la console, dossier 2750" "640 freerad daemon 2750" "$(stat -c '%a %U %G' "$AL" | tr -d '\n'; printf ' %s' "$(stat -c '%a' "$D/authlog")")"
expect_eq "journal : toutes les lignes ont 18 champs (aucune valeur ne casse le format)" 0 "$(awk -F'|' 'NF!=18' "$AL" | wc -l)"
expect_grep "journal : certificat révoqué (bob) : sujet, série, UPN et raison" '\|reject\|.*\|/CN=3Dbob\|/CN=3DLab Issuing CA\|1003\|[^|]*\|bob@lab.test\|.*certificate revoked$' "$AL"
expect_grep "journal : certificat expiré (old)" '\|reject\|.*\|/CN=3Dold\|.*certificate has expired$' "$AL"
expect_grep "journal : mauvais usage (badeku)" '\|reject\|.*\|/CN=3Dbadeku\|.*unsuitable certificate purpose$' "$AL"
expect_grep "journal : autorité inconnue (foreign) : émetteur et raison" '\|reject\|.*\|/CN=3Dforeign\|/CN=3DAutre Emettrice\|.*unable to get local issuer certificate$' "$AL"
expect_grep "journal : acceptation (alice) : sujet, UPN, et aucune raison" '\|accept\|.*\|/CN=3Dalice\|/CN=3DLab Issuing CA\|1001\|[^|]*\|alice@lab.test\|[^|]*\|[^|]*\|[^|]*\|$' "$AL"
expect_nogrep "journal : aucune clé privée ni secret dans le fichier" 'PRIVATE KEY|'"$SELF" "$AL"

echo "== Retour à un déploiement sans PKI =="
"$RAD" apply "$(clients)" >/dev/null 2>&1; rc=$?
expect_eq "apply sans PKI : code 0" 0 "$rc"
expect_eq "…plus de certificats ni de clé sur le disque" no "$([ -e "$D/etc/certs" ] && echo yes || echo no)"
expect_eq "…module eap retiré" "always attr_filter ddibuntu_authlog expr preprocess" "$(find "$D/etc/mods-enabled" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
expect_nogrep "…plus de serveur virtuel de décision" 'ddibuntu-check-eap-tls' "$D/etc/sites-available/ddibuntu"
expect_eq "…statut : EAP-TLS inactif" False "$(rj "$D/run/radius-status.json" eap.enabled)"
r="$(eap "$P/alice.pem" "$P/alice.key" 1)"; echo "$r" | tail -1 | grep -q '^FAILURE' && ok "…un certificat valide n'ouvre aucun accès (EAP non configuré)" || ko "…refus attendu" "$(echo "$r" | tail -2)"
finish
