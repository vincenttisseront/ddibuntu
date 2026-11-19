#!/usr/bin/env bash
# Batterie 31 — service PKI (EJBCA Community en conteneur Podman) : installation, secrets, base, unité Quadlet, état, demandes de la console,
# pare-feu. Podman, systemctl, psql, curl et ddibuntu-fw sont remplacés par des bouchons : on vérifie la logique de ddibuntu-pki (validation,
# secrets jamais régénérés, nom public figé, données conservées à la désinstallation), pas le conteneur lui-même.
# Si le vrai générateur Quadlet de Podman est présent, l'unité écrite est en plus relue par lui (podman-system-generator --dryrun).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

PKI="$RFS/usr/local/sbin/ddibuntu-pki"
B="$T_TMP/bin"; mkdir -p "$B" "$T_TMP/etc" "$T_TMP/data" "$T_TMP/quad" "$T_TMP/run" "$T_TMP/gen"
LOG="$T_TMP/calls.log"
cat > "$B/podman" <<EOF
#!/bin/bash
echo "podman \$*" >> "$LOG"
case "\$1 \$2" in
  "image exists") [ -f "$T_TMP/image.present" ] ;;
  "image inspect") echo "sha256:$(printf 'a%.0s' $(seq 64))" ;;
  *) [ "\$1" = pull ] && touch "$T_TMP/image.present"; exit 0 ;;
esac
EOF
cat > "$B/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >> "$LOG"
case "\$1" in
  is-active) [ -f "$T_TMP/active" ] ;;
  show) date -u -d "\${SINCE:--20 seconds}" '+%a %Y-%m-%d %H:%M:%S UTC' ;;
  start|restart) touch "$T_TMP/active" ;;
  stop) rm -f "$T_TMP/active" ;;
esac
EOF
cat > "$B/psql" <<EOF
#!/bin/bash
{ echo "psql \$* [PKI_DB_PW=\${PKI_DB_PW:+défini}]"; cat; } >> "$T_TMP/psql.log"
EOF
cat > "$B/curl" <<EOF
#!/bin/bash
if [ -f "$T_TMP/healthy" ]; then printf 'ALLOK'; exit 0; fi
exit 22
EOF
cat > "$B/fw" <<EOF
#!/bin/bash
echo "fw \$*" >> "$LOG"
EOF
chmod +x "$B"/*
PKI_UID="$(id -u)"
export DDI_PKI_ALLOW_USER=1 DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_GENERATED_DIR="$T_TMP/gen" DDI_RUN_DIR="$T_TMP/run"
export DDI_PKI_ETC="$T_TMP/etc" DDI_PKI_DATA="$T_TMP/data" DDI_PKI_QUADLET_DIR="$T_TMP/quad" DDI_PKI_PODMAN="$B/podman"
export DDI_PKI_SYSTEMCTL="$B/systemctl" DDI_PKI_CURL="$B/curl" DDI_FW_BIN="$B/fw" DDI_PKI_PSQL="$B/psql" DDI_PKI_LOCK="$T_TMP/lock" DDI_PKI_UID="$PKI_UID"
IMG=docker.io/keyfactor/ejbca-ce:9.6.3
HOST=pki.lab.test
req() { printf '%s' "$1" > "$T_TMP/gen/.pki-request"; "$PKI" request >/dev/null 2>&1; }
res() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$T_TMP/run/pki-result.json" "$1"; }
st() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$T_TMP/run/pki-status.json" "$1"; }
mode() { stat -c %a "$1"; }

echo "== Validation sans effet =="
check "l'unité se rend avec une image et un nom valides" "$PKI" render "$IMG" "$HOST"
check_fail "image d'un autre dépôt refusée" "$PKI" render docker.io/evil/ejbca-ce:9.6.3 "$HOST"
check_fail "étiquette « latest » refusée" "$PKI" render docker.io/keyfactor/ejbca-ce:latest "$HOST"
check_fail "image par empreinte refusée (c'est root qui épingle)" "$PKI" render "docker.io/keyfactor/ejbca-ce@sha256:$(printf 'b%.0s' $(seq 64))" "$HOST"
check_fail "nom public sans point refusé" "$PKI" render "$IMG" pki
check_fail "nom public qui est une adresse IP refusé" "$PKI" render "$IMG" 10.0.0.1
check_fail "nom public à dernière étiquette numérique refusé" "$PKI" render "$IMG" pki.lab.42
check_fail "nom public avec majuscules refusé" "$PKI" render "$IMG" PKI.lab.test
check_fail "nom public avec caractère de commande refusé" "$PKI" render "$IMG" 'pki.lab.test;id'
check "réseaux valides acceptés" "$PKI" check "$IMG" "$HOST" "10.0.0.0/8, 2001:db8::/32"
check_fail "réseau invalide refusé" "$PKI" check "$IMG" "$HOST" "pas-un-reseau"
check_fail "réseau /0 refusé" "$PKI" check "$IMG" "$HOST" "0.0.0.0/0"

echo "== Installation =="
rm -f "$LOG" "$T_TMP/psql.log" "$T_TMP/active" "$T_TMP/healthy" "$T_TMP/image.present"
out="$("$PKI" apply "$IMG" "$HOST" "192.168.10.0/24,10.1.0.0/16" 2>&1)"; rc=$?
expect_eq "apply : code de sortie 0" 0 "$rc"
expect_eq "fichier de secrets en 0600" 600 "$(mode "$T_TMP/etc/ejbca.env")"
expect_eq "instance.json en 0600" 600 "$(mode "$T_TMP/etc/instance.json")"
for k in PASSWORD_ENCRYPTION_KEY CA_KEYSTOREPASS EJBCA_CLI_DEFAULTPASSWORD DATABASE_PASSWORD; do
  v="$(sed -n "s/^$k=//p" "$T_TMP/etc/ejbca.env")"
  if [[ "$v" =~ ^[A-Za-z0-9]{40}$ ]]; then ok "$k : 40 caractères alphanumériques"; else ko "$k : forme inattendue" "[${v:0:3}…]"; fi
done
expect_grep "base visée : ejbca sur 127.0.0.1" '^DATABASE_JDBC_URL=jdbc:postgresql://127\.0\.0\.1:5432/ejbca$' "$T_TMP/etc/ejbca.env"
expect_grep "nom public dans HTTPSERVER_HOSTNAME" "^HTTPSERVER_HOSTNAME=$HOST\$" "$T_TMP/etc/ejbca.env"
expect_grep "administration protégée par certificat client (TLS_SETUP_ENABLED=true)" '^TLS_SETUP_ENABLED=true$' "$T_TMP/etc/ejbca.env"
expect_eq "quatre secrets distincts" 4 "$(sed -n -E 's/^(PASSWORD_ENCRYPTION_KEY|CA_KEYSTOREPASS|EJBCA_CLI_DEFAULTPASSWORD|DATABASE_PASSWORD)=//p' "$T_TMP/etc/ejbca.env" | sort -u | wc -l)"
Q="$T_TMP/quad/ddibuntu-ejbca.container"
expect_grep "unité : image épinglée par empreinte" "^Image=docker\.io/keyfactor/ejbca-ce@sha256:a{64}\$" "$Q"
expect_grep "unité : réseau de l'hôte (PostgreSQL en 127.0.0.1)" '^Network=host$' "$Q"
expect_grep "unité : secrets lus dans le fichier root" "^EnvironmentFile=$T_TMP/etc/ejbca\.env\$" "$Q"
expect_grep "unité : volume persistant" "^Volume=$T_TMP/data/persistent:/mnt/persistent\$" "$Q"
expect_grep "unité : arrêt propre de WildFly" '^PodmanArgs=--stop-timeout=90$' "$Q"
expect_grep "unité : pas d'élévation de privilèges" '^NoNewPrivileges=true$' "$Q"
expect_nogrep "unité : aucun secret écrit dans l'unité" 'PASSWORD|KEYSTOREPASS|DATABASE_PASSWORD' "$Q"
expect_eq "volume en 0700" 700 "$(mode "$T_TMP/data/persistent")"
expect_grep "instance : étiquette lisible conservée" '"tag": "9\.6\.3"' "$T_TMP/etc/instance.json"
expect_grep "instance : réseaux normalisés" '"nets": "192\.168\.10\.0/24,10\.1\.0\.0/16"' "$T_TMP/etc/instance.json"
expect_grep "base : rôle créé" "create role ejbca login password" "$T_TMP/psql.log"
expect_grep "base : base créée avec le rôle propriétaire" "create database ejbca owner ejbca" "$T_TMP/psql.log"
expect_grep "base : mot de passe transmis par l'environnement" 'PKI_DB_PW=défini' "$T_TMP/psql.log"
expect_nogrep "base : mot de passe jamais sur la ligne de commande" "$(sed -n 's/^DATABASE_PASSWORD=//p' "$T_TMP/etc/ejbca.env")" "$T_TMP/psql.log"
expect_grep "image tirée (absente au départ)" '^podman pull ' "$LOG"
expect_grep "systemd relu puis conteneur démarré" '^systemctl start ddibuntu-ejbca\.service$' "$LOG"
expect_grep "pare-feu : réseaux de la PKI ouverts" '^fw set PKI_NETS 192\.168\.10\.0/24,10\.1\.0\.0/16$' "$LOG"
expect_nogrep "le résultat ne contient aucun secret" "$(sed -n 's/^PASSWORD_ENCRYPTION_KEY=//p' "$T_TMP/etc/ejbca.env")" <(printf '%s' "$out")

echo "== Réinstallation : les secrets ne changent jamais =="
cp "$T_TMP/etc/ejbca.env" "$T_TMP/env.before"
rm -f "$LOG"
check "apply repasse sans erreur (mêmes paramètres, autres réseaux)" "$PKI" apply "$IMG" "$HOST" "172.16.0.0/12"
check "fichier de secrets identique octet pour octet" cmp "$T_TMP/etc/ejbca.env" "$T_TMP/env.before"
expect_nogrep "image déjà présente : pas de nouveau tirage" '^podman pull ' "$LOG"
expect_grep "pare-feu : réseaux remplacés" '^fw set PKI_NETS 172\.16\.0\.0/12$' "$LOG"
check_fail "le nom public ne change plus après l'installation" "$PKI" apply "$IMG" other.lab.test ""
check_fail "la version ne change que par la mise à jour de la PKI" "$PKI" apply docker.io/keyfactor/ejbca-ce:9.6.4 "$HOST" ""
# 0.14.6 : sans podman, l'installation le pose elle-même par apt ; un échec d'apt arrête tout avec la commande à lancer à la main
cat > "$B/apt-fail" <<EOF
#!/bin/bash
echo "apt-get \$*" >> "$LOG"
case "\$*" in *update*) exit 100 ;; *) echo "E: Impossible de récupérer http://archive.ubuntu.com/pool/podman.deb" >&2; exit 100 ;; esac
EOF
cat > "$B/apt-ok" <<EOF
#!/bin/bash
echo "apt-get \$* (DEBIAN_FRONTEND=\${DEBIAN_FRONTEND:-})" >> "$LOG"
case "\$*" in *install*podman*) mkdir -p "$T_TMP/late"; cp "$B/podman" "$T_TMP/late/podman" ;; esac
EOF
chmod +x "$B/apt-fail" "$B/apt-ok"
rm -f "$LOG"
check_fail "sans podman et sans accès à apt : installation refusée" env DDI_PKI_PODMAN="$T_TMP/late/podman" DDI_PKI_APT_GET="$B/apt-fail" "$PKI" apply "$IMG" "$HOST" ""
expect_grep "…apt a bien été essayé (liste puis paquet)" '^apt-get .*update' "$LOG"
expect_grep "…et le paquet demandé est podman" '^apt-get .*install -y -qq podman' "$LOG"
out="$(DDI_PKI_PODMAN="$T_TMP/late/podman" DDI_PKI_APT_GET="$B/apt-fail" "$PKI" apply "$IMG" "$HOST" "" 2>&1 || true)"
expect_grep "…le message donne la commande à lancer à la main" 'apt install podman' <(printf '%s' "$out")
check "fichier de secrets toujours identique après le refus" cmp "$T_TMP/etc/ejbca.env" "$T_TMP/env.before"
check_fail "sans podman et sans apt-get : installation refusée" env DDI_PKI_PODMAN="$T_TMP/late/podman" DDI_PKI_APT_GET=/nonexistent "$PKI" apply "$IMG" "$HOST" ""
rm -f "$LOG"; rm -rf "$T_TMP/late"
check "sans podman : apt le pose, l'installation continue" env DDI_PKI_PODMAN="$T_TMP/late/podman" DDI_PKI_APT_GET="$B/apt-ok" "$PKI" apply "$IMG" "$HOST" "172.16.0.0/12"
expect_grep "…installation non interactive" 'install -y -qq podman \(DEBIAN_FRONTEND=noninteractive\)' "$LOG"
expect_grep "…puis l'installation de la PKI se poursuit avec ce podman" '^podman ' "$LOG"
rm -f "$LOG"
check "podman déjà présent : apt n'est jamais appelé" env DDI_PKI_APT_GET="$B/apt-fail" "$PKI" apply "$IMG" "$HOST" "172.16.0.0/12"
expect_nogrep "…vérifié dans le journal" '^apt-get ' "$LOG"
check "fichier de secrets toujours identique après les refus" cmp "$T_TMP/etc/ejbca.env" "$T_TMP/env.before"

# 0.14.11 : le paquet podman voyage dans l'archive de mise à jour ; sans lui, l'installation le repose d'abord depuis l'archive signée (ddibuntu-selfupdate packages), apt en dernier
cat > "$B/selfupdate-ok" <<EOS
#!/bin/bash
echo "selfupdate \$*" >> "$LOG"
mkdir -p "$T_TMP/late"; cp "$B/podman" "$T_TMP/late/podman"
EOS
cat > "$B/selfupdate-ko" <<EOS
#!/bin/bash
echo "selfupdate \$*" >> "$LOG"
exit 1
EOS
chmod +x "$B/selfupdate-ok" "$B/selfupdate-ko"
rm -f "$LOG"; rm -rf "$T_TMP/late"
check "sans podman : le paquet embarqué est posé, apt n'est pas sollicité" env DDI_PKI_PODMAN="$T_TMP/late/podman" DDI_PKI_SELFUPDATE="$B/selfupdate-ok" DDI_PKI_APT_GET="$B/apt-fail" "$PKI" apply "$IMG" "$HOST" "172.16.0.0/12"
expect_grep "…ddibuntu-selfupdate packages a été appelé" '^selfupdate packages$' "$LOG"
expect_nogrep "…apt n'a pas été appelé" '^apt-get ' "$LOG"
expect_grep "…puis l'installation de la PKI se poursuit avec ce podman" '^podman ' "$LOG"
rm -f "$LOG"; rm -rf "$T_TMP/late"
check "paquet embarqué indisponible : apt prend le relais" env DDI_PKI_PODMAN="$T_TMP/late/podman" DDI_PKI_SELFUPDATE="$B/selfupdate-ko" DDI_PKI_APT_GET="$B/apt-ok" "$PKI" apply "$IMG" "$HOST" "172.16.0.0/12"
expect_grep "…selfupdate essayé en premier" '^selfupdate packages$' "$LOG"
expect_grep "…puis apt" 'install -y -qq podman' "$LOG"
rm -f "$LOG"
check "podman déjà présent : ni selfupdate ni apt" env DDI_PKI_SELFUPDATE="$B/selfupdate-ko" DDI_PKI_APT_GET="$B/apt-fail" "$PKI" apply "$IMG" "$HOST" "172.16.0.0/12"
expect_nogrep "…vérifié dans le journal" '^(selfupdate|apt-get) ' "$LOG"

echo "== État =="
rm -f "$T_TMP/healthy"; touch "$T_TMP/active"
"$PKI" status; expect_eq "actif, ne répond pas, démarré depuis peu : en démarrage" starting "$(st state)"
SINCE="-3 hours" "$PKI" status; expect_eq "actif, ne répond pas depuis 3 h : défaillant" unhealthy "$(st state)"
touch "$T_TMP/healthy"; "$PKI" status; expect_eq "répond ALLOK : sain" healthy "$(st state)"
expect_eq "version publiée" 9.6.3 "$(st version)"
expect_eq "nom public publié" "$HOST" "$(st hostname)"
rm -f "$T_TMP/active"; "$PKI" status; expect_eq "arrêté" stopped "$(st state)"
expect_nogrep "l'état ne contient aucun secret" 'PASSWORD|KEYSTOREPASS' "$T_TMP/run/pki-status.json"

echo "== Demandes de la console =="
req '{"action":"stop"}'; expect_eq "demande consommée" no "$([ -e "$T_TMP/gen/.pki-request" ] && echo yes || echo no)"
expect_eq "stop : ok" True "$(res ok)"
req '{"action":"start"}'; expect_eq "start : ok" True "$(res ok)"; expect_eq "…et le conteneur tourne" yes "$([ -f "$T_TMP/active" ] && echo yes || echo no)"
req '{"action":"restart"}'; expect_eq "restart : ok" True "$(res ok)"
req '{"action":"status"}'; expect_eq "status : ok" True "$(res ok)"
req 'pas du json'; expect_eq "JSON invalide refusé" False "$(res ok)"
req '{"action":"rm -rf /"}'; expect_eq "action inconnue refusée" False "$(res ok)"
req '{"action":"apply","image":"docker.io/evil/x:1.2.3","hostname":"pki.lab.test","nets":[]}'; expect_eq "image étrangère refusée" False "$(res ok)"
req '{"action":"apply","image":"'"$IMG"'","hostname":"pki.lab.test;id","nets":[]}'; expect_eq "nom piégé refusé" False "$(res ok)"
req '{"action":"apply","image":"'"$IMG"'","hostname":"pki.lab.test","nets":["10.0.0.0/8; reboot"]}'; expect_eq "réseau piégé refusé" False "$(res ok)"
req '{"action":"apply","image":"'"$IMG"'","hostname":"pki.lab.test","nets":["10.9.0.0/16"]}'; expect_eq "apply valide par la console : ok" True "$(res ok)"
expect_grep "…réseaux enregistrés" '"nets": "10\.9\.0\.0/16"' "$T_TMP/etc/instance.json"
printf '%s' '{"action":"stop"}' > "$T_TMP/gen/.pki-request"; ln -sf /etc/passwd "$T_TMP/gen/.pki-request" 2>/dev/null; "$PKI" request >/dev/null 2>&1
check "un lien symbolique en guise de demande n'est pas suivi" test ! -e "$T_TMP/gen/.pki-request" -a ! -L "$T_TMP/gen/.pki-request"

echo "== Désinstallation : les données restent =="
req '{"action":"uninstall"}'; expect_eq "uninstall : ok" True "$(res ok)"
check "unité Quadlet retirée" test ! -e "$Q"
check "instance retirée" test ! -e "$T_TMP/etc/instance.json"
check "secrets conservés" test -f "$T_TMP/etc/ejbca.env"
check "volume conservé" test -d "$T_TMP/data/persistent"
expect_grep "pare-feu refermé" '^fw set PKI_NETS $' "$LOG"
check_fail "réinstallation sous un autre nom public refusée (les clés dépendent du nom d'origine)" "$PKI" apply "$IMG" other.lab.test ""
check "réinstallation sous le nom d'origine : ok, mêmes secrets" "$PKI" apply "$IMG" "$HOST" ""
check "secrets inchangés après réinstallation" cmp "$T_TMP/etc/ejbca.env" "$T_TMP/env.before"

echo "== Relecture par le vrai générateur Quadlet de Podman =="
GEN=/usr/lib/systemd/system-generators/podman-system-generator
if [ -x "$GEN" ]; then
  d="$T_TMP/dry"; mkdir -p "$d"; cp "$Q" "$d/"
  # l'image épinglée n'a pas besoin d'exister : le générateur ne fait que traduire l'unité en service systemd
  QUADLET_UNIT_DIRS="$d" "$GEN" --dryrun > "$T_TMP/dry.out" 2>&1
  expect_grep "service généré : ddibuntu-ejbca.service" 'ddibuntu-ejbca\.service' "$T_TMP/dry.out"
  expect_grep "service généré : podman run avec l'image épinglée" '^ExecStart=.*podman run .*docker\.io/keyfactor/ejbca-ce@sha256:a{64}' "$T_TMP/dry.out"
  expect_grep "service généré : réseau de l'hôte" '--network=host' "$T_TMP/dry.out"
  expect_grep "service généré : fichier d'environnement" "--env-file $T_TMP/etc/ejbca\.env" "$T_TMP/dry.out"
  expect_grep "service généré : arrêt propre (délai de 90 s avant SIGKILL)" '--stop-timeout=90' "$T_TMP/dry.out"
  expect_grep "service généré : délai d'arrêt systemd supérieur" '^TimeoutStopSec=120$' "$T_TMP/dry.out"
  expect_grep "service généré : volume" ":/mnt/persistent" "$T_TMP/dry.out"
  expect_nogrep "aucune erreur du générateur" 'error|Error|invalid|unsupported' "$T_TMP/dry.out"
else
  note "podman-system-generator absent : relecture de l'unité par le générateur sautée"
fi

echo "== Pare-feu : port public de la PKI =="
FWX="$RFS/usr/local/sbin/ddibuntu-fw"
export DDI_FW_CONF="$T_TMP/fw.conf" DDI_FW_STATE="$T_TMP/fwstate"; mkdir -p "$T_TMP/fwstate"
"$FWX" set ADMIN_NETS 10.0.0.0/8 >/dev/null
"$FWX" set PKI_NETS "192.168.10.0/24, 2001:db8::/32" >/dev/null
"$FWX" render > "$T_TMP/fw.nft"
expect_grep "ensemble pki4 rempli" 'set pki4 \{' "$T_TMP/fw.nft"
expect_grep "port 8080 réservé à pki4" 'ip saddr @pki4 tcp dport 8080 accept' "$T_TMP/fw.nft"
expect_grep "port 8080 réservé à pki6" 'ip6 saddr @pki6 tcp dport 8080 accept' "$T_TMP/fw.nft"
expect_nogrep "8443 (administration d'EJBCA) jamais ouvert" '8443' "$T_TMP/fw.nft"
"$FWX" set PKI_NETS "" >/dev/null
"$FWX" render > "$T_TMP/fw0.nft"
expect_nogrep "sans réseau : aucune règle sur 8080" 'dport 8080' "$T_TMP/fw0.nft"
check_fail "réseau PKI invalide refusé par le pare-feu" "$FWX" set PKI_NETS "pas-un-reseau"
if command -v nft >/dev/null 2>&1; then check "nft -c valide le rendu avec réseaux PKI" bash -c "'$FWX' set PKI_NETS '10.5.0.0/16' >/dev/null && '$FWX' render | nft -c -f -"; fi

echo "== Minuteur de maintenance (CRL, état publié) =="
SYS="$RFS/etc/systemd/system"
check "unité du minuteur présente" test -f "$SYS/ddibuntu-pki-maint.timer"
check "unité de service présente" test -f "$SYS/ddibuntu-pki-maint.service"
expect_grep "le service lance « ddibuntu-pki maintain »" '^ExecStart=/usr/local/sbin/ddibuntu-pki maintain$' "$SYS/ddibuntu-pki-maint.service"
expect_grep "le service est une tâche ponctuelle" '^Type=oneshot$' "$SYS/ddibuntu-pki-maint.service"
expect_grep "le minuteur se déclenche toutes les 5 minutes" '^OnUnitActiveSec=5min$' "$SYS/ddibuntu-pki-maint.timer"
expect_grep "le minuteur démarre après l'amorçage" '^OnBootSec=' "$SYS/ddibuntu-pki-maint.timer"
expect_grep "le minuteur est installé avec les autres" '^WantedBy=timers.target$' "$SYS/ddibuntu-pki-maint.timer"
for f in src/iso/late.sh src/iso/update.sh src/rootfs/usr/local/sbin/ddibuntu-selfupdate; do
  check "le minuteur est activé par $(basename "$f")" grep -q 'ddibuntu-pki-maint.timer' "$(dirname "$0")/../$f"
done

finish
