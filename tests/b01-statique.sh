#!/usr/bin/env bash
# Batterie 01 — niveau « statique » : syntaxe de tous les fichiers et conformité des contenus.
# shellcheck disable=SC2086  # listes de fichiers volontairement découpées
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

echo "== Syntaxe shell =="
APPL="$RFS/usr/local/sbin/ddibuntu-apply $RFS/usr/local/sbin/ddibuntu-setup $RFS/usr/local/sbin/ddibuntu-fw $RFS/usr/local/bin/ddibuntu-menu $RFS/usr/local/lib/ddibuntu/common.sh $RFS/usr/local/lib/ddibuntu/lang/fr.sh $RFS/usr/local/lib/ddibuntu/lang/en.sh"
check "shellcheck : scripts de l'appliance" shellcheck -x -s bash $APPL
check "shellcheck : construction, late.sh, update.sh, assembleur" shellcheck -x -s bash "$ROOT/build-ddibuntu.sh" "$ROOT/src/iso/late.sh" "$ROOT/src/iso/update.sh" "$ROOT/tools/make-single.sh" "$ROOT/tools/make-chroot.sh"
check "shellcheck : tests (avertissements et erreurs)" shellcheck -x -P SCRIPTDIR -S warning -s bash "$ROOT"/tests/*.sh
check "bash -n : scripts de l'appliance" bash -c "for f in $APPL; do bash -n \$f || exit 1; done"
check "bash -n : script assemblé" bash -n "$DIST"
check "bash -n : profile.d (sh)" sh -n "$RFS/etc/profile.d/ddibuntu-menu.sh"

echo "== Compatibilité bash 3.2 (macOS) de la partie hôte du script =="
HOST="$T_TMP/host-part.sh"
awk '$0 == "#__DDIBUNTU_PAYLOAD_BELOW__" { exit } { print }' "$DIST" | grep -vE '^[[:space:]]*#' > "$HOST"
lint() { if grep -nE -- "$2" "$HOST" >"$T_TMP/lint"; then ko "bash 3.2 : $1" "$(head -3 "$T_TMP/lint" | tr '\n' ' ')"; else ok "bash 3.2 : pas de $1"; fi; }
lint "tableau associatif" 'declare -A|typeset -A|local -A'
lint "mapfile / readarray" 'mapfile|readarray'
lint "changement de casse \${v,,} \${v^^}" '\$\{[A-Za-z_0-9]+(,,?|\^\^?)\}'
lint "redirections &>> et |&" '&>>|\|&'
lint "test [[ -v ]]" '\[\[ +-v '
lint "nameref (local -n)" 'local -n|declare -n'
lint "coproc" 'coproc'
lint "readlink -f" 'readlink -f'
lint "sed -i" 'sed -i'
lint "transformations \${v@Q}" '\$\{[A-Za-z_0-9]+@[QEPAa]\}'
lint "printf %(...)T" "%\\([^)]*\\)T"
lint "case ;& ou ;;&" ';;&|;&'
lint "variables bash 5 (EPOCHSECONDS, BASHPID)" 'EPOCHSECONDS|BASHPID|SRANDOM'
lint "expansion de tableau [@] (piège set -u de bash 3.2)" '\[@\]'

echo "== Contenu embarqué =="
load_build_functions
P="$T_TMP/payload"
# shellcheck disable=SC2034  # SELF est lue par payload_extract
( SELF="$DIST"; payload_extract "$P" ) >/dev/null 2>&1
check "marqueur de contenu présent une seule fois" bash -c "[ \"\$(grep -c -x -F -- '#__DDIBUNTU_PAYLOAD_BELOW__' '$DIST')\" = 1 ]"
check "archive embarquée extraite" test -d "$P/rootfs"
for f in usr/local/sbin/ddibuntu-apply usr/local/sbin/ddibuntu-setup usr/local/sbin/ddibuntu-fw usr/local/bin/ddibuntu-menu; do
  expect_eq "mode 0755 : $f" 755 "$(stat -c %a "$P/rootfs/$f" 2>/dev/null)"
done
expect_eq "mode 0755 : iso/late.sh" 755 "$(stat -c %a "$P/iso/late.sh" 2>/dev/null)"
expect_eq "mode 0755 : iso/update.sh" 755 "$(stat -c %a "$P/iso/update.sh" 2>/dev/null)"
expect_eq "mode 0644 : common.sh" 644 "$(stat -c %a "$P/rootfs/usr/local/lib/ddibuntu/common.sh")"
check "aucune fin de ligne CRLF dans le contenu embarqué" bash -c "! grep -rlI \$'\\r' '$P'"
expect_eq "VERSION : script = contenu embarqué" "$(grep -m1 '^DDI_VERSION=' "$DIST" | cut -d'"' -f2)" "$(tr -d '\n' < "$P/VERSION")"
expect_eq "VERSION : fichier de l'appliance = source" "$(tr -d '\n' < "$ROOT/src/VERSION")" "$(tr -d '\n' < "$P/rootfs/usr/local/lib/ddibuntu/VERSION")"

check "script assemblé : le code de remplacement du modèle user-data garde son marqueur @@VERSION@@" grep -qF 'content//@@VERSION@@/' "$DIST"
check "script assemblé : le marqueur @@PASSHASH@@ est préservé dans le code" grep -qF 'tmpl//@@PASSHASH@@/' "$DIST"

echo "== Pare-feu livré =="
check "nftables.nft livré : syntaxe valide (nft -c)" nft -c -f "$P/rootfs/etc/ddibuntu/nftables.nft"
check "nftables.nft livré = rendu du pare-feu par défaut" bash -c "DDI_LIBDIR='$P/rootfs/usr/local/lib/ddibuntu' DDI_FW_CONF='$P/rootfs/etc/ddibuntu/firewall.conf' DDI_FW_STATE='$T_TMP/st' '$P/rootfs/usr/local/sbin/ddibuntu-fw' render | cmp - '$P/rootfs/etc/ddibuntu/nftables.nft'"
expect_grep "politique d'entrée : drop" 'hook input priority filter; policy drop' "$P/rootfs/etc/ddibuntu/nftables.nft"
expect_grep "table dédiée inet ddibuntu" '^table inet ddibuntu' "$P/rootfs/etc/ddibuntu/nftables.nft"
grep -vE '^[[:space:]]*#' "$P/rootfs/etc/nftables.conf" > "$T_TMP/nftables.conf.code"
expect_nogrep "aucun « flush ruleset » dans le code (les autres tables sont préservées)" 'flush ruleset' "$T_TMP/nftables.conf.code"
expect_grep "nftables.conf inclut le fichier de la table dédiée" '^include "/etc/ddibuntu/nftables.nft"$' "$T_TMP/nftables.conf.code"

echo "== SSH =="
SSHD="$T_TMP/sshd"; mkdir -p "$SSHD/sshd_config.d"
cp "$P/rootfs/etc/ssh/sshd_config.d/10-ddibuntu.conf" "$SSHD/sshd_config.d/"
mkdir -p /run/sshd   # prérequis de sshd -t sur le banc
ssh-keygen -q -t ed25519 -N '' -f "$SSHD/hostkey"
printf 'Include %s/sshd_config.d/*.conf\nHostKey %s/hostkey\nPidFile %s/sshd.pid\n' "$SSHD" "$SSHD" "$SSHD" > "$SSHD/sshd_config"
check "sshd -t : configuration valide" /usr/sbin/sshd -t -f "$SSHD/sshd_config"
/usr/sbin/sshd -T -f "$SSHD/sshd_config" > "$SSHD/effective" 2>/dev/null
for kv in "permitrootlogin no" "allowgroups ddiadmin" "maxauthtries 3" "x11forwarding no" "allowtcpforwarding no" "permitemptypasswords no" "kbdinteractiveauthentication no" "logingracetime 30"; do
  expect_grep "sshd effectif : $kv" "^$kv\$" "$SSHD/effective"
done

echo "== sysctl =="
expect_eq "sysctl : toutes les lignes au format « clé = valeur »" 0 "$(grep -vE '^(#|$)' "$P/rootfs/etc/sysctl.d/90-ddibuntu.conf" | grep -cvE '^[a-z0-9_.]+ = -?[0-9]+$')"
missing=""
while IFS= read -r key; do
  path="/proc/sys/$(printf '%s' "$key" | tr . /)"
  [ -e "$path" ] || missing="$missing $key"
done < <(grep -vE '^(#|$)' "$P/rootfs/etc/sysctl.d/90-ddibuntu.conf" | cut -d' ' -f1)
if [ ! -e /proc/net/if_inet6 ]; then
  v6=""; v4=""
  for k in $missing; do case "$k" in net.ipv6.*) v6="$v6 $k" ;; *) v4="$v4 $k" ;; esac; done
  missing="$v4"
  note "noyau du banc sans IPv6 : clés non vérifiables ici (valides sur Ubuntu 24.04) :$v6"
fi
if [ -z "$missing" ]; then ok "sysctl : toutes les clés vérifiables existent dans le noyau du banc"; else ko "sysctl : clés inconnues du noyau du banc" "$missing"; fi

echo "== Unité systemd =="
U="$P/rootfs/etc/systemd/system/ddibuntu-firstboot.service"
expect_grep "unité : exécute l'assistant en mode premier démarrage" '^ExecStart=/usr/local/sbin/ddibuntu-setup --first-boot$' "$U"
expect_grep "unité : démarre avant la console de connexion" '^Before=getty@tty1.service' "$U"
expect_grep "unité : ne tourne qu'avant la première configuration" '^ConditionPathExists=!/var/lib/ddibuntu/configured$' "$U"
expect_grep "unité : TERM défini (whiptail l'exige)" '^Environment=TERM=linux$' "$U"
check "unité : l'exécutable référencé existe dans le contenu embarqué" test -x "$P/rootfs/usr/local/sbin/ddibuntu-setup"
if command -v systemd-analyze >/dev/null 2>&1; then
    # l'exécutable de l'appliance n'existe pas sur le banc : on le remplace par /bin/true pour vérifier tout le reste
  sed 's|^ExecStart=/usr/local/sbin/ddibuntu-setup|ExecStart=/bin/true|' "$U" > "$T_TMP/ddibuntu-firstboot.service"
  check "systemd-analyze verify (ExecStart substitué par /bin/true)" systemd-analyze verify "$T_TMP/ddibuntu-firstboot.service"
fi

echo "== Unités de l'intégration (console, base, application privilégiée) =="
for u in ddibuntu-console.service ddibuntu-db-init.service ddibuntu-reload.service ddibuntu-reload.path; do
  expect_nogrep "unité $u : aucun retour chariot" $'\r' "$P/rootfs/etc/systemd/system/$u"
  if command -v systemd-analyze >/dev/null 2>&1; then
    sed -E 's#^ExecStart=/usr/local/(sbin|lib/ddibuntu)/[a-z-]+#ExecStart=/bin/true#' "$P/rootfs/etc/systemd/system/$u" > "$T_TMP/$u"
    check "systemd-analyze verify : $u" systemd-analyze verify "$T_TMP/$u"
  fi
done
expect_grep "console : exécutée sous un compte sans privilège" '^User=ddiconsole$' "$P/rootfs/etc/systemd/system/ddibuntu-console.service"
expect_grep "console : écriture limitée au dossier de dépôt" '^ReadWritePaths=/var/lib/ddibuntu/generated$' "$P/rootfs/etc/systemd/system/ddibuntu-console.service"
expect_grep "console : port 443 par capacité, pas par root" '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' "$P/rootfs/etc/systemd/system/ddibuntu-console.service"
expect_grep "console : élévation de privilèges interdite" '^NoNewPrivileges=yes$' "$P/rootfs/etc/systemd/system/ddibuntu-console.service"
# AF_NETLINK : sans lui, os.networkInterfaces() échoue (errno 97) et la page Cluster répond « Erreur interne » tant qu'aucun cluster n'existe (0.9.0)
expect_grep "console : familles d'adresses limitées, AF_NETLINK inclus (énumération des interfaces en lecture seule)" '^RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK$' "$P/rootfs/etc/systemd/system/ddibuntu-console.service"
expect_nogrep "console : aucune capacité réseau d'administration (CAP_NET_ADMIN) accordée" '^(Ambient|Bounding)?CapabilityBoundingSet=.*CAP_NET_ADMIN|^AmbientCapabilities=.*CAP_NET_ADMIN' "$P/rootfs/etc/systemd/system/ddibuntu-console.service"
expect_grep "pare-feu livré : DNS (UDP 53 et 67 DHCP) ouvert" 'udp dport \{ 53, 67 \} accept' "$P/rootfs/etc/ddibuntu/nftables.nft"
expect_grep "pare-feu livré : DNS TCP 53 ouvert" 'tcp dport \{ 53 \} accept' "$P/rootfs/etc/ddibuntu/nftables.nft"
expect_grep "pare-feu livré : la console (443) reste réservée aux réseaux d'administration" 'ip saddr @admin4 tcp dport \{ 22, 443 \} accept' "$P/rootfs/etc/ddibuntu/nftables.nft"
check "console embarquée dans le script assemblé (charge utile)" test -s "$P/console/console.tar.gz"

echo "== Installation automatique Subiquity =="
# shellcheck disable=SC2016  # le $ de l'empreinte doit rester littéral
sed 's|@@PASSHASH@@|$6$testsalt$abcdefghijklmnopqrstuvwxyz|; s|@@VERSION@@|0.0.0|' "$P/iso/user-data.tmpl" > "$T_TMP/user-data"
head -1 "$T_TMP/user-data" > "$T_TMP/first"
expect_eq "user-data : première ligne #cloud-config" "#cloud-config" "$(cat "$T_TMP/first")"
curl -fsSL -m 30 -o "$T_TMP/schema.json" https://raw.githubusercontent.com/canonical/subiquity/main/autoinstall-schema.json || cp /home/claude/tools/autoinstall-schema.json "$T_TMP/schema.json" 2>/dev/null
check "user-data : conforme au schéma officiel d'autoinstall Subiquity" python3 -c "
import json, sys, yaml, jsonschema
schema = json.load(open('$T_TMP/schema.json'))
doc = yaml.safe_load(open('$T_TMP/user-data'))
assert 'autoinstall' in doc, 'clé autoinstall absente'
jsonschema.validate(doc['autoinstall'], schema)
a = doc['autoinstall']
assert a['interactive-sections'] == [], 'aucune question pendant l installation'
assert a['refresh-installer']['update'] is False, 'pas de mise à jour de l installateur'
assert any('late.sh' in c for c in a['late-commands']), 'late.sh non appelé'
"
expect_nogrep "user-data : aucun mot de passe en clair (identité = empreinte)" '^\s+password: "[^$]' "$T_TMP/user-data"
check "meta-data : instance-id présent" grep -q '^instance-id:' "$P/iso/meta-data"

echo "== Lanceur Windows (PowerShell) =="
PS1DIR="$T_TMP/ps1out"
check "--makeps1 génère build-ddibuntu.ps1" bash "$DIST" --makeps1 --out "$PS1DIR"
PS1="$PS1DIR/build-ddibuntu.ps1"
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
PWSH=/home/claude/tools/pwsh/pwsh
if [ -x "$PWSH" ]; then
  check "PowerShell : aucune erreur d'analyse syntaxique" "$PWSH" -NoProfile -Command "\$e=\$null;\$t=\$null;[void][System.Management.Automation.Language.Parser]::ParseFile('$PS1',[ref]\$t,[ref]\$e); if (\$e.Count -ne 0) { \$e | ForEach-Object { \$_.Message }; exit 1 }"
  expect_eq "PowerShell : exécution réelle, empreinte embarquée vérifiée" 1 "$("$PWSH" -NoProfile -File "$PS1" -OutDir "$T_TMP" 2>&1 | grep -c 'SHA-256 verifie')"
  sed "s/^\\\$ExpectedSha256 = '[0-9a-f]*'/\$ExpectedSha256 = '$(printf '0%.0s' {1..64})'/" "$PS1" > "$T_TMP/tampered.ps1"
  "$PWSH" -NoProfile -File "$T_TMP/tampered.ps1" -OutDir "$T_TMP" >"$T_TMP/tamper.out" 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && grep -q 'empreinte SHA-256 du script embarque incorrecte' "$T_TMP/tamper.out"; then ok "PowerShell : script altéré refusé avant toute exécution"; else ko "PowerShell : script altéré refusé" "rc=$rc $(head -c 300 "$T_TMP/tamper.out")"; fi
else
  ko "PowerShell : analyseur indisponible sur le banc" "$PWSH absent"
fi
expect_grep "PS1 : conteneur amd64 forcé" 'docker run --rm --platform linux/amd64' "$PS1"
expect_eq "PS1 : uniquement des caractères ASCII (PowerShell 5.1 sans BOM)" 0 "$(LC_ALL=C grep -cP '[^\x00-\x7F]' "$PS1")"
want="$(sha256sum "$DIST" | cut -d' ' -f1)"
expect_grep "PS1 : empreinte SHA-256 = celle du script .sh" "ExpectedSha256 = '$want'" "$PS1"
# shellcheck disable=SC2016  # motif sed littéral
sed -n '/^\$PayloadB64 = @/,/^'"'"'@$/p' "$PS1" | sed '1d;$d' | tr -d '\n ' | base64 -d | gunzip > "$T_TMP/roundtrip.sh" 2>/dev/null
# régression 0.9.42 : ddibuntu-reload ne doit jamais changer les droits de /var/lib/ddibuntu (la console doit le traverser)
check "ddibuntu-reload : ne modifie pas les droits du dossier d'état" bash -c '! grep -nE "install -d -m 0[0-9]+ \"\$STATE\"" "$1"' _ "$ROOT/src/rootfs/usr/local/sbin/ddibuntu-reload"
check "PS1 : le script embarqué décompressé est identique octet pour octet" cmp "$T_TMP/roundtrip.sh" "$DIST"

finish
