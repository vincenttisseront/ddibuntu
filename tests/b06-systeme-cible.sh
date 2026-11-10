#!/usr/bin/env bash
# Batterie 06 — système cible. Un chroot Ubuntu 24.04 RÉEL (debootstrap), sans nftables ni whiptail :
#  1. le script de construction tourne dans une copie « conteneur propre » avec --in-container
#     (installation des outils, résolution des paquets relative à une base minimale, ISO produite) ;
#  2. late.sh déploie le contenu de l'ISO dans une autre copie jouant le système installé ;
#  3. on vérifie fichiers, paquets, services activés, configuration SSH réelle, comptes, et on démarre
#     vraiment sshd pour tester l'accès (clé SSH ; groupe ddiadmin ; root refusé).
# Limite : pas de PID 1 systemd dans le banc, donc l'assistant de premier démarrage n'est pas lancé ici.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=lib-iso.sh
. "$(dirname "$0")/lib-iso.sh"

BASE=/home/claude/cache/noble-min
WORKROOT=/home/claude/cache/work-b06
[ -f "$BASE/.ddibuntu-chroot-ok" ] || bash "$ROOT/tools/make-chroot.sh" >/dev/null 2>&1
if [ ! -f "$BASE/.ddibuntu-chroot-ok" ]; then ko "chroot de base Ubuntu 24.04 indisponible" "tools/make-chroot.sh a échoué"; finish; exit; fi

MOUNTED=""
bind() {   # bind DIR : monte /dev et /proc dans le chroot si le banc l'autorise
  mkdir -p "$1/dev" "$1/proc"
  if mount --bind /dev "$1/dev" 2>/dev/null && mount -t proc proc "$1/proc" 2>/dev/null; then MOUNTED="$MOUNTED $1"; return 0; fi
  return 1
}
unbind_all() {
  local d
  for d in $MOUNTED; do umount -l "$d/proc" 2>/dev/null; umount -l "$d/dev" 2>/dev/null; done
  MOUNTED=""
}
HOSTPG=0
if pg_lsclusters 2>/dev/null | grep -q online; then pg_ctlcluster 16 main stop -m fast 2>/dev/null && HOSTPG=1; fi
APP_PIDS=""; MHTTP=""
cleanup() {
  for p in $APP_PIDS; do kill "$p" 2>/dev/null; done
  [ -n "$MHTTP" ] && kill "$MHTTP" 2>/dev/null
  [ -n "${T:-}" ] && ip netns exec ddit-app chroot "$T" pg_ctlcluster 16 main stop -m immediate >/dev/null 2>&1
  sleep 1; ip netns del ddit-app 2>/dev/null; ip netns del ddit-cli 2>/dev/null
  if [ "$HOSTPG" = 1 ]; then pg_ctlcluster 16 main start 2>/dev/null; fi
  [ -f "$T_TMP/sshd.pid" ] && kill "$(cat "$T_TMP/sshd.pid")" 2>/dev/null
  pkill -f "sshd -D -e -p 222[23]" 2>/dev/null
  unbind_all
  # Garde-fou : ne JAMAIS supprimer un arbre où /dev de l'hôte serait encore monté
  if findmnt -R "$WORKROOT" >/dev/null 2>&1; then echo "ATTENTION : montages résiduels sous $WORKROOT, suppression refusée" >&2
  else rm -rf --one-file-system "$WORKROOT"; fi
  rm -rf "$T_TMP"
}
trap cleanup EXIT
rm -rf --one-file-system "$WORKROOT"; mkdir -p "$WORKROOT"
# policy-rc.d : comme curtin, aucun service ne démarre pendant l'installation des paquets
newchroot() { cp -a "$BASE" "$1"; cp /etc/resolv.conf "$1/etc/resolv.conf" 2>/dev/null; printf '#!/bin/sh\nexit 101\n' > "$1/usr/sbin/policy-rc.d"; chmod 755 "$1/usr/sbin/policy-rc.d"; bind "$1" || true; }

echo "== Chroot de base =="
expect_eq "base : nftables absent (la résolution de paquets sera donc réellement testée)" absent "$(chroot "$BASE" dpkg -s nftables >/dev/null 2>&1 && echo present || echo absent)"
expect_eq "base : whiptail absent" absent "$(chroot "$BASE" dpkg -s whiptail >/dev/null 2>&1 && echo present || echo absent)"

echo "== Construction dans un conteneur propre (--in-container) =="
B="$WORKROOT/builder"; newchroot "$B"
if [ -d "$B/proc/1" ]; then ok "montages /dev et /proc dans le chroot"; else note "montages /dev et /proc impossibles sur ce banc : tests exécutés sans"; fi
mkdir -p "$B/ddi/out"
cp "$DIST" "$B/ddi/build.sh"
make_fake_iso "$B/ddi/in.iso" normal
# Node vient d'un miroir local signé par une clé de test (vrai binaire node du banc) ; les paquets de l'appliance sont résolus dans le conteneur propre
NM="$WORKROOT/nodemirror"; make_node_mirror "$NM" real
MPORT=$((20000 + RANDOM % 20000))
( cd "$NM" && python3 -m http.server "$MPORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
MHTTP=$!; sleep 1
chroot "$B" env DDI_NODE_URL="http://127.0.0.1:$MPORT/node/latest-v22.x" DDI_NODE_KEYS_URL="http://127.0.0.1:$MPORT/keys" DDI_NODE_FPRS="$NODE_MIRROR_FPR" \
  bash /ddi/build.sh --in-container --out /ddi/out --iso /ddi/in.iso --allow-unverified --timeout 5 >"$T_TMP/cbuild.log" 2>&1; rc=$?
kill "$MHTTP" 2>/dev/null; MHTTP=""
expect_eq "build en conteneur propre : code retour 0" 0 "$rc"
[ "$rc" -eq 0 ] || tail -15 "$T_TMP/cbuild.log"
expect_grep "outils de construction installés dans le conteneur" 'Installation des outils de construction dans le conteneur' "$T_TMP/cbuild.log"
expect_grep "paquets embarqués : socle + PostgreSQL, BIND, Kea" 'Paquets embarqués : nftables whiptail postgresql postgresql-client bind9 bind9-utils bind9-dnsutils kea-dhcp4-server kea-admin python3 open-vm-tools' "$T_TMP/cbuild.log"
expect_grep "Node vérifié par signature pendant la construction" 'Signature Node valide' "$T_TMP/cbuild.log"
ISO="$B/ddi/out/ddibuntu-$(tr -d '\n' < "$ROOT/src/VERSION")-amd64.iso"
check "ISO produite dans le conteneur" test -s "$ISO"
CD="$WORKROOT/cdrom"; mkdir -p "$CD"
xorriso -osirrox on -indev "$ISO" -extract /ddibuntu "$CD/ddibuntu" >/dev/null 2>&1; chmod -R u+w "$CD"
ls "$CD/ddibuntu/debs" > "$T_TMP/debs.list" 2>/dev/null
for p in nftables_ libnftables1_ whiptail_ libnewt0.52_ postgresql-16_ postgresql-common_ postgresql-client-16_ libpq5_ bind9_ bind9-utils_ bind9-dnsutils_ kea-dhcp4-server_ kea-admin_ kea-common_ python3_ libpython3.12-stdlib_ open-vm-tools_; do expect_grep "paquet embarqué : $p*" "^$p" "$T_TMP/debs.list"; done
n_debs="$(grep -c '\.deb$' "$T_TMP/debs.list")"
if [ "$n_debs" -ge 40 ] && [ "$n_debs" -le 300 ]; then ok "nombre de paquets embarqués plausible ($n_debs)"; else ko "nombre de paquets embarqués" "$n_debs"; fi
check "debs/SHA256SUMS valide" bash -c "cd '$CD/ddibuntu/debs' && sha256sum -c --quiet SHA256SUMS"
expect_grep "MANIFEST liste les paquets embarqués" 'nftables_' "$CD/ddibuntu/MANIFEST.txt"
expect_grep "MANIFEST : version de Node et somme" '^Node\.js : node-v22\.99\.0-linux-x64\.tar\.gz \(SHA-256 [0-9a-f]{64}, signature vérifiée\)' "$CD/ddibuntu/MANIFEST.txt"
check "ISO : Node et console embarqués avec leurs sommes" bash -c "cd '$CD/ddibuntu' && sha256sum -c --quiet payloads.sha256"
du -sh "$CD/ddibuntu/debs" | cut -f1 > "$T_TMP/debs.size"

echo "== Déploiement par late.sh sur un système cible =="
T="$WORKROOT/target"; newchroot "$T"
chroot "$T" useradd -m -s /bin/bash ddisetup          # compte d'installation créé par Subiquity
late() { DDI_CDROM="$1" DDI_TARGET="$2" DDI_INTARGET=chroot bash "$1/ddibuntu/late.sh"; }
late "$CD" "$T" >"$T_TMP/late.log" 2>&1; rc=$?
expect_eq "late.sh : code retour 0" 0 "$rc"
[ "$rc" -eq 0 ] || tail -15 "$T_TMP/late.log"
expect_grep "late.sh : se termine par la version" 'terminé : DDI-Buntu [0-9.]+' "$T_TMP/late.log"
expect_eq "nftables installé depuis l'ISO (absent avant)" present "$(chroot "$T" dpkg -s nftables >/dev/null 2>&1 && echo present || echo absent)"
expect_eq "whiptail installé depuis l'ISO (absent avant)" present "$(chroot "$T" dpkg -s whiptail >/dev/null 2>&1 && echo present || echo absent)"
expect_eq "nftables correctement configuré (dpkg : état « ii »)" ii "$(chroot "$T" dpkg-query -W -f='${db:Status-Abbrev}' nftables | tr -d ' ')"
check "nft s'exécute dans le système cible" chroot "$T" nft --version
check "whiptail s'exécute dans le système cible" chroot "$T" whiptail --version
expect_eq "cache temporaire des paquets supprimé" no "$([ -e "$T/var/cache/ddibuntu-debs" ] && echo yes || echo no)"
for f in usr/local/sbin/ddibuntu-apply usr/local/sbin/ddibuntu-setup usr/local/sbin/ddibuntu-fw usr/local/bin/ddibuntu-menu; do
  expect_eq "installé 0755 root:root : $f" "755 root root" "$(stat -c '%a %U %G' "$T/$f")"
done
expect_eq "common.sh installé 0644 root:root" "644 root root" "$(stat -c '%a %U %G' "$T/usr/local/lib/ddibuntu/common.sh")"
expect_eq "VERSION installée = version de l'ISO" "$(tr -d '\n' < "$CD/ddibuntu/VERSION")" "$(tr -d '\n' < "$T/usr/local/lib/ddibuntu/VERSION")"
expect_eq "installed-version écrit" "$(tr -d '\n' < "$CD/ddibuntu/VERSION")" "$(tr -d '\n' < "$T/var/lib/ddibuntu/installed-version")"
expect_eq "groupe ddiadmin créé" ddiadmin "$(chroot "$T" getent group ddiadmin | cut -d: -f1)"
expect_eq "unité ddibuntu-firstboot activée" enabled "$(systemctl --root="$T" is-enabled ddibuntu-firstboot.service 2>/dev/null)"
expect_eq "nftables.service activé" enabled "$(systemctl --root="$T" is-enabled nftables.service 2>/dev/null)"
for u in postgresql.service named.service ddibuntu-db-init.service ddibuntu-console.service ddibuntu-reload.path; do
  expect_eq "service activé au démarrage : $u" enabled "$(systemctl --root="$T" is-enabled "$u" 2>/dev/null)"
done
expect_eq "Kea désactivé tant qu'aucune étendue n'est déployée" disabled "$(systemctl --root="$T" is-enabled kea-dhcp4-server.service 2>/dev/null)"
for u in ddibuntu-console.service ddibuntu-db-init.service ddibuntu-reload.service ddibuntu-reload.path; do
  check "systemd-analyze verify (système cible réel) : $u" systemd-analyze verify --root="$T" "/etc/systemd/system/$u"
done
expect_eq "open-vm-tools installé (VMware : arrêt propre, adresse IP remontée)" ii "$(chroot "$T" dpkg-query -W -f='${db:Status-Abbrev}' open-vm-tools 2>/dev/null | tr -d ' ')"
expect_eq "Node installé et exécutable" ok "$(chroot "$T" /opt/ddibuntu/node/bin/node -e 'console.log("ok")' 2>/dev/null)"
expect_eq "compte de service ddiconsole sans shell de connexion" /usr/sbin/nologin "$(chroot "$T" getent passwd ddiconsole | cut -d: -f7)"
expect_eq "console installée en root:root (non modifiable par son propre compte)" "root:root" "$(chroot "$T" stat -c '%U:%G' /opt/ddibuntu/console/app/server/index.mjs)"
expect_eq "Ctrl+Alt+Suppr masqué" masked "$(systemctl --root="$T" is-enabled ctrl-alt-del.target 2>/dev/null)"
check "systemd-analyze verify de l'unité (racine = système cible, base systemd réelle)" systemd-analyze verify --root="$T" /etc/systemd/system/ddibuntu-firstboot.service
check "pare-feu livré : nft -c dans le système cible (via /etc/nftables.conf)" chroot "$T" nft -c -f /etc/nftables.conf
check "rendu par défaut dans le système cible = fichier livré" bash -c "chroot '$T' /usr/local/sbin/ddibuntu-fw render | cmp - '$T/etc/ddibuntu/nftables.nft'"

echo "== late.sh : idempotence et refus =="
late "$CD" "$T" >"$T_TMP/late2.log" 2>&1; rc=$?
expect_eq "seconde exécution de late.sh : code retour 0" 0 "$rc"
# archive corrompue
CD2="$WORKROOT/cd2"; cp -a "$CD" "$CD2"; printf 'X' >> "$CD2/ddibuntu/rootfs.tar"
T2="$WORKROOT/t2"; newchroot "$T2"
late "$CD2" "$T2" >"$T_TMP/late3.log" 2>&1; rc=$?
expect_eq "rootfs.tar corrompu : installation refusée" 1 "$rc"
expect_grep "rootfs.tar corrompu : message explicite" 'rootfs.tar corrompu' "$T_TMP/late3.log"
expect_eq "rootfs.tar corrompu : rien n'a été déployé" no "$([ -e "$T2/usr/local/sbin/ddibuntu-fw" ] && echo yes || echo no)"
# paquet corrompu
CD3="$WORKROOT/cd3"; cp -a "$CD" "$CD3"; first="$(ls "$CD3/ddibuntu/debs"/*.deb | head -1)"; printf 'X' >> "$first"
T3="$WORKROOT/t3"; newchroot "$T3"
late "$CD3" "$T3" >"$T_TMP/late4.log" 2>&1; rc=$?
expect_eq "paquet corrompu : installation refusée" 1 "$rc"
expect_grep "paquet corrompu : message explicite" 'paquets embarqués corrompus' "$T_TMP/late4.log"
expect_eq "paquet corrompu : rien n'a été déployé" no "$([ -e "$T3/usr/local/sbin/ddibuntu-fw" ] && echo yes || echo no)"
expect_eq "paquet corrompu : nftables non installé" absent "$(chroot "$T3" dpkg -s nftables >/dev/null 2>&1 && echo present || echo absent)"
# dépendance manquante : l'échec doit être bruyant, jamais masqué
CD4="$WORKROOT/cd4"; cp -a "$CD" "$CD4"; rm -f "$CD4/ddibuntu/debs"/libnftables1_*.deb
( cd "$CD4/ddibuntu/debs" && sha256sum ./*.deb | sed 's| \./| |' > SHA256SUMS )
T4="$WORKROOT/t4"; newchroot "$T4"
late "$CD4" "$T4" >"$T_TMP/late5.log" 2>&1; rc=$?
expect_eq "dépendance manquante : installation refusée (échec non masqué)" 1 "$rc"
expect_grep "dépendance manquante : message explicite" 'installation des paquets embarqués impossible' "$T_TMP/late5.log"
expect_eq "dépendance manquante : fichiers de l'appliance non déployés" no "$([ -e "$T4/usr/local/sbin/ddibuntu-fw" ] && echo yes || echo no)"
check_fail "late.sh sans dossier /ddibuntu : refusé" env DDI_CDROM="$WORKROOT/vide" DDI_TARGET="$T" DDI_INTARGET=chroot bash "$CD/ddibuntu/late.sh"

echo "== SSH réel dans le système cible =="
chroot "$T" bash -c 'mkdir -p /run/sshd; ssh-keygen -A >/dev/null 2>&1'
check "sshd -t dans le système cible (configuration Ubuntu + durcissement)" chroot "$T" /usr/sbin/sshd -t
chroot "$T" /usr/sbin/sshd -T > "$T_TMP/sshd.T" 2>/dev/null
for kv in "permitrootlogin no" "allowgroups ddiadmin" "maxauthtries 3" "allowtcpforwarding no" "x11forwarding no" "banner /etc/issue.net"; do
  expect_grep "sshd réel : $kv" "^$kv\$" "$T_TMP/sshd.T"
done

echo "== Compte administrateur (ddibuntu-apply installé, mode hors-ligne sur le système cible) =="
CFG="$T_TMP/admin.cfg"
printf "LANGUAGE='fr'\nHOSTNAME='ddi01'\nNET_MODE='static'\nNET_IFACE='ens192'\nNET_ADDR='127.0.0.1/8'\nNET_GW='127.0.0.2'\nADMIN_NETS='127.0.0.0/8'\nADMIN_USER='jdupont'\n" > "$CFG"
PW='Correct-Horse-Battery-9'
printf '%s\n' "$PW" | DDI_ROOT="$T" DDI_LIBDIR="$T/usr/local/lib/ddibuntu" DDI_FW_BIN="$T/usr/local/sbin/ddibuntu-fw" "$T/usr/local/sbin/ddibuntu-apply" --config "$CFG" --password-stdin >"$T_TMP/adm.log" 2>&1; rc=$?
expect_eq "apply installé : code retour 0" 0 "$rc"
[ "$rc" -eq 0 ] || cat "$T_TMP/adm.log"
expect_eq "compte jdupont créé" jdupont "$(chroot "$T" id -un jdupont 2>/dev/null)"
chroot "$T" id -nG jdupont > "$T_TMP/groups" 2>/dev/null
expect_grep "jdupont dans le groupe sudo" '(^| )sudo( |$)' "$T_TMP/groups"
expect_grep "jdupont dans le groupe ddiadmin (SSH autorisé)" '(^| )ddiadmin( |$)' "$T_TMP/groups"
expect_grep "mot de passe stocké sous forme d'empreinte (yescrypt ou sha512)" '^jdupont:\$(y|6)\$' "$T/etc/shadow"
expect_eq "mot de passe défini (passwd -S = P)" P "$(chroot "$T" passwd -S jdupont | awk '{print $2}')"
if grep -rIlF -- "$PW" "$T/etc" "$T/var" "$T/home" "$T/root" "$T/tmp" 2>/dev/null | grep -q .; then ko "le mot de passe en clair n'apparaît nulle part dans le système cible" "$(grep -rIlF -- "$PW" "$T/etc" "$T/var" "$T/home" "$T/root" "$T/tmp" 2>/dev/null | head -3 | tr '\n' ' ')"; else ok "le mot de passe en clair n'apparaît nulle part dans le système cible"; fi
if grep -qF -- "$PW" "$T_TMP/adm.log"; then ko "le mot de passe n'apparaît pas dans la sortie d'apply"; else ok "le mot de passe n'apparaît pas dans la sortie d'apply"; fi
expect_eq "compte d'installation ddisetup supprimé" absent "$(grep -q '^ddisetup:' "$T/etc/passwd" && echo present || echo absent)"
expect_eq "répertoire personnel de ddisetup supprimé" no "$([ -e "$T/home/ddisetup" ] && echo yes || echo no)"
expect_grep "réseau d'administration dans le pare-feu du système cible" 'elements = \{ 127\.0\.0\.0/8 \}' "$T/etc/ddibuntu/nftables.nft"
check "pare-feu du système cible : nft -c après apply" chroot "$T" nft -c -f /etc/nftables.conf
expect_grep "/etc/issue du système cible : version" "^DDI-Buntu $(tr -d '\n' < "$CD/ddibuntu/VERSION") " "$T/etc/issue"
expect_eq "ligne de commande non interactive : aucun menu (profile.d silencieux sans terminal)" ok "$(chroot "$T" su -s /bin/bash -l jdupont -c 'echo ok' 2>/dev/null | tail -1)"
printf '%s\n' "$PW" | DDI_ROOT="$T" DDI_LIBDIR="$T/usr/local/lib/ddibuntu" DDI_FW_BIN="$T/usr/local/sbin/ddibuntu-fw" "$T/usr/local/sbin/ddibuntu-apply" --config "$CFG" --password-stdin >"$T_TMP/adm2.log" 2>&1; rc=$?
expect_eq "apply rejoué sur un système déjà configuré : code retour 0" 0 "$rc"

echo "== sshd démarré pour de vrai =="
ssh-keygen -q -t ed25519 -N '' -f "$T_TMP/k_admin"; ssh-keygen -q -t ed25519 -N '' -f "$T_TMP/k_other"
chroot "$T" useradd -m -s /bin/bash autre; chroot "$T" bash -c 'echo "autre:Autre-Mdp-12345" | chpasswd'
for u in jdupont autre; do
  mkdir -p "$T/home/$u/.ssh"
  if [ "$u" = jdupont ]; then cp "$T_TMP/k_admin.pub" "$T/home/$u/.ssh/authorized_keys"; else cp "$T_TMP/k_other.pub" "$T/home/$u/.ssh/authorized_keys"; fi
  chroot "$T" chown -R "$u:$u" "/home/$u/.ssh"; chmod 700 "$T/home/$u/.ssh"; chmod 600 "$T/home/$u/.ssh/authorized_keys"
done
mkdir -p "$T/root/.ssh"; cp "$T_TMP/k_admin.pub" "$T/root/.ssh/authorized_keys"
chroot "$T" /usr/sbin/sshd -D -e -p 2222 -o ListenAddress=127.0.0.1 >"$T_TMP/sshd.log" 2>&1 &
echo $! > "$T_TMP/sshd.pid"
sleep 2
SSHBASE="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5"
SSHO="$SSHBASE -p 2222"   # ssh : le PREMIER -p l'emporte, d'où une base sans port
# shellcheck disable=SC2086
if timeout 20 ssh $SSHO -i "$T_TMP/k_admin" jdupont@127.0.0.1 true 2>"$T_TMP/ssh1.err"; then
  ok "SSH réel : jdupont (groupe ddiadmin) se connecte par clé"
  # shellcheck disable=SC2086
  expect_eq "SSH réel : commande exécutée sur le système cible" jdupont "$(timeout 20 ssh $SSHO -i "$T_TMP/k_admin" jdupont@127.0.0.1 id -un 2>/dev/null)"
  # shellcheck disable=SC2086
  if timeout 20 ssh $SSHO -i "$T_TMP/k_other" autre@127.0.0.1 true 2>/dev/null; then ko "SSH réel : un compte hors groupe ddiadmin doit être refusé"; else ok "SSH réel : compte hors groupe ddiadmin refusé (AllowGroups)"; fi
  # shellcheck disable=SC2086
  if timeout 20 ssh $SSHO -i "$T_TMP/k_admin" root@127.0.0.1 true 2>/dev/null; then ko "SSH réel : root doit être refusé"; else ok "SSH réel : connexion root refusée (PermitRootLogin no)"; fi
  # Le client ouvre toujours son port local : seul le trafic à travers le tunnel prouve le refus.
  # On redirige vers le sshd lui-même et on tente de lire sa bannière « SSH-2.0 ».
  tunnel_banner() {   # $1 = port du serveur à joindre, $2 = port local du tunnel
    # sorties de ssh -f dans un fichier et stdin sur /dev/null : il ne doit pas hériter du tube de $(...)
    # shellcheck disable=SC2086
    timeout 20 ssh $SSHBASE -p "$1" -i "$T_TMP/k_admin" -N -L "$2:127.0.0.1:$1" jdupont@127.0.0.1 -f </dev/null >"$T_TMP/tun.$2.out" 2>&1 || { echo "ECHEC-SSH:$(head -c 200 "$T_TMP/tun.$2.out" | tr '\n' ' ')" > "$T_TMP/tun.$2.diag"; return 1; }
    sleep 1
    ( exec 3<>"/dev/tcp/127.0.0.1/$2"; timeout 3 head -c 4 <&3 ) 2>/dev/null
    pkill -f "ssh .*-L $2:" 2>/dev/null; true
  }
  chroot "$T" /usr/sbin/sshd -D -e -p 2223 -o ListenAddress=127.0.0.1 -o AllowTcpForwarding=yes >"$T_TMP/sshd2.log" 2>&1 &
  echo $! > "$T_TMP/sshd2.pid"; sleep 2
  expect_eq "témoin positif : avec AllowTcpForwarding yes, la bannière traverse le tunnel" "SSH-" "$(tunnel_banner 2223 18081)"
  expect_eq "AllowTcpForwarding no (configuration livrée) : rien ne traverse le tunnel" "" "$(tunnel_banner 2222 18080)"
  [ -f "$T_TMP/tun.18081.diag" ] && note "diagnostic tunnel 2223 : $(cat "$T_TMP/tun.18081.diag") / sshd2 : $(tail -c 300 "$T_TMP/sshd2.log" | tr '\n' ' ')"
  kill "$(cat "$T_TMP/sshd2.pid")" 2>/dev/null
else
  note "sshd n'a pas pu être démarré ou joint dans ce banc : tests de connexion réelle non exécutés ($(head -c 200 "$T_TMP/ssh1.err" | tr '\n' ' '))"
  ko "SSH réel : connexion par clé d'un administrateur" "$(head -c 300 "$T_TMP/ssh1.err" | tr '\n' ' ') / sshd: $(head -c 300 "$T_TMP/sshd.log" | tr '\n' ' ')"
fi
pkill -f 'ssh .*-L 18080' 2>/dev/null

echo "== Appliance simulée : PostgreSQL, console HTTPS, BIND et Kea dans un espace de noms réseau =="
APP=ddit-app; CLI=ddit-cli
ip netns add "$APP" 2>/dev/null; ip netns add "$CLI" 2>/dev/null
ip link add va type veth peer name vc; ip link set va netns "$APP"; ip link set vc netns "$CLI"
ip -n "$APP" addr add 192.168.10.2/24 dev va; ip -n "$APP" link set va up; ip -n "$APP" link set lo up
ip -n "$CLI" addr add 192.168.10.50/24 dev vc; ip -n "$CLI" link set vc up; ip -n "$CLI" link set lo up
inapp() { ip netns exec "$APP" chroot "$T" "$@"; }
incli() { ip netns exec "$CLI" "$@"; }
CERT="$T/etc/ddibuntu/tls/console.crt"; JAR="$T_TMP/jar"; URL="https://192.168.10.2:8443/api"; CSRF=""
api() { local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then incli curl -sS -m 30 --cacert "$CERT" -b "$JAR" -c "$JAR" -X "$m" -H 'content-type: application/json' -H "x-csrf-token: $CSRF" -d "$d" "$URL$p"
  else incli curl -sS -m 30 --cacert "$CERT" -b "$JAR" -c "$JAR" -X "$m" -H "x-csrf-token: $CSRF" "$URL$p"; fi
}
inapp mkdir -p /run/named /run/kea /run/postgresql; inapp chown bind:bind /run/named; inapp chown postgres:postgres /run/postgresql

echo "-- PostgreSQL et initialisation (rien n'est téléchargé) --"
inapp pg_lsclusters > "$T_TMP/pgcl.txt" 2>&1
expect_grep "cluster PostgreSQL 16/main créé à l'installation des paquets" '^16 +main' "$T_TMP/pgcl.txt"
inapp pg_ctlcluster 16 main start >"$T_TMP/pgstart.log" 2>&1; rc=$?
expect_eq "PostgreSQL démarre dans l'espace de noms de l'appliance" 0 "$rc"
for _ in $(seq 30); do inapp pg_isready -q -h 127.0.0.1 && break; sleep 1; done
check "PostgreSQL répond" inapp pg_isready -q -h 127.0.0.1
if ! inapp pg_isready -q -h 127.0.0.1; then echo "--- journal PostgreSQL du chroot :"; tail -12 "$T/var/log/postgresql/postgresql-16-main.log" 2>/dev/null | cut -c1-200; cat "$T_TMP/pgstart.log" | head -5; fi
inapp env DDI_CONSOLE_PORT=8443 /usr/local/sbin/ddibuntu-db-init >"$T_TMP/dbinit.log" 2>&1; rc=$?
expect_eq "ddibuntu-db-init : code retour 0" 0 "$rc"; [ "$rc" -eq 0 ] || tail -8 "$T_TMP/dbinit.log"
ENVF="$T/etc/ddibuntu/console.env"
expect_eq "console.env : 0640 root:ddiconsole (lisible par le seul compte de service)" "640 root ddiconsole" "$(inapp stat -c '%a %U %G' /etc/ddibuntu/console.env)"
expect_eq "clé TLS : 0640 root:ddiconsole" "640 root ddiconsole" "$(inapp stat -c '%a %U %G' /etc/ddibuntu/tls/console.key)"
expect_eq "jeton de première configuration : 0600 root" "600 root" "$(inapp stat -c '%a %U' /var/lib/ddibuntu/setup-token)"
expect_eq "clé TSIG des mises à jour dynamiques : 0640 root:bind" "640 root bind" "$(inapp stat -c '%a %U %G' /etc/bind/ddi-ddns.key)"
expect_eq "clé de chiffrement des secrets : 32 caractères ou plus" yes "$(awk -F= '$1=="DDI_SECRET_KEY"{print (length($2)>=32?"yes":"no")}' "$ENVF")"
expect_eq "rôles PostgreSQL ddi et kea créés" "ddi kea" "$(inapp runuser -u postgres -- psql -Atc "select string_agg(rolname, ' ' order by rolname) from pg_roles where rolname in ('ddi','kea')")"
expect_eq "tables Kea créées (lease4)" t "$(inapp runuser -u postgres -- psql -d ddibuntu -Atc "select to_regclass('public.lease4') is not null")"
expect_eq "base ddibuntu : propriétaire ddi" ddi "$(inapp runuser -u postgres -- psql -Atc "select pg_get_userbyid(datdba) from pg_database where datname = 'ddibuntu'")"
before="$(sha256sum "$ENVF" | cut -d' ' -f1)"
inapp env DDI_CONSOLE_PORT=8443 /usr/local/sbin/ddibuntu-db-init >"$T_TMP/dbinit2.log" 2>&1; rc=$?
expect_eq "ddibuntu-db-init rejoué : sans effet (idempotent)" "0 $before" "$rc $(sha256sum "$ENVF" | cut -d' ' -f1)"
expect_grep "ddibuntu-db-init rejoué : message « déjà initialisé »" 'déjà initialisé' "$T_TMP/dbinit2.log"
openssl x509 -in "$CERT" -noout -text > "$T_TMP/cert.txt" 2>/dev/null
expect_grep "certificat TLS : adresse de l'appliance dans les noms alternatifs" 'IP Address:192\.168\.10\.2' "$T_TMP/cert.txt"
expect_grep "certificat TLS : clé elliptique P-256" 'prime256v1' "$T_TMP/cert.txt"

echo "-- Console web (HTTPS, compte sans privilège) --"
ip netns exec "$APP" chroot "$T" runuser -u ddiconsole -- env PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin bash -c 'set -a; . /etc/ddibuntu/console.env; set +a; exec /usr/local/lib/ddibuntu/console-start' >"$T_TMP/console.log" 2>&1 &
APP_PIDS="$APP_PIDS $!"
for _ in $(seq 40); do incli curl -sS -m 3 --cacert "$CERT" -o /dev/null "$URL/health" 2>/dev/null && break; sleep 1; done
expect_eq "console : /api/health en HTTPS, certificat vérifié sans -k" ok "$(api GET /health | jq -r .status 2>/dev/null)"
[ "$(api GET /health | jq -r .status 2>/dev/null)" = ok ] || { echo "journal console :"; head -c 600 "$T_TMP/console.log"; }
check_fail "console : le HTTP en clair est refusé sur le port TLS" incli curl -sS -m 4 -o /dev/null "http://192.168.10.2:8443/api/health"
incli curl -sSI -m 5 --cacert "$CERT" "https://192.168.10.2:8443/api/health" > "$T_TMP/hdr.txt" 2>&1
expect_grep "console : en-tête HSTS (cookies Secure par défaut)" '^[sS]trict-[tT]ransport-[sS]ecurity:' "$T_TMP/hdr.txt"
cuid="$(inapp id -u ddiconsole)"
# le processus qui ÉCOUTE sur 8443 (et non un parent éventuel) : c'est lui dont l'identité compte
lsn="$(ip netns exec "$APP" ss -ltnpH 'sport = :8443' 2>/dev/null)"
npid="$(printf '%s\n' "$lsn" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
nuid="$(awk '/^Uid:/{print $2}' "/proc/${npid:-0}/status" 2>/dev/null)"
procs=""; for p in $(pgrep -f 'index\.m[j]s|console-start'); do procs="$procs [$p uid=$(awk '/^Uid:/{print $2}' /proc/$p/status 2>/dev/null) $(tr '\0' ' ' < /proc/$p/cmdline | cut -c1-70)]"; done
if [ -n "$nuid" ] && [ "$nuid" = "$cuid" ] && [ "$nuid" != 0 ]; then ok "console : le processus qui écoute sur 8443 tourne sous le compte ddiconsole (uid $nuid), pas root"; else ko "console : le processus qui écoute sur 8443 tourne sous le compte ddiconsole, pas root" "écoute=[$npid] uid=[$nuid] attendu=[$cuid] processus:$procs"; fi
TOKEN="$(cat "$T/var/lib/ddibuntu/setup-token")"
expect_eq "première configuration : jeton erroné refusé" bad_setup_token "$(api POST /setup/admin '{"token":"faux","username":"admin","password":"Correct-Horse-Battery-9"}' | jq -r '.data.code')"
expect_eq "première configuration : bon jeton accepté" true "$(api POST /setup/admin "{\"token\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"Correct-Horse-Battery-9\"}" | jq -r '.ok')"
expect_eq "première configuration : une seule fois" already_configured "$(api POST /setup/admin "{\"token\":\"$TOKEN\",\"username\":\"autre\",\"password\":\"Correct-Horse-Battery-9\"}" | jq -r '.data.code')"
CSRF="$(api POST /auth/login '{"username":"admin","password":"Correct-Horse-Battery-9"}' | jq -r .csrf)"
expect_eq "connexion administrateur" yes "$([ -n "$CSRF" ] && [ "$CSRF" != null ] && echo yes || echo no)"

echo "-- Configuration par l'API : IPAM, DNS, DHCP, filtrage --"
SUB="$(api POST /ipam/subnets '{"cidr":"192.168.10.0/24","name":"LAN","gateway":"192.168.10.1"}' | jq -r .id)"
ZID="$(api POST /dns/zones '{"name":"lab.test","type":"primary"}' | jq -r .id)"
for r in '"@","NS","ns1.lab.test."' '"ns1","A","192.168.10.2"' '"www","A","192.168.10.80"'; do
  IFS=, read -r n ty rd <<<"$r"; api POST /dns/records "{\"zone_id\":$ZID,\"name\":$n,\"type\":$ty,\"rdata\":$rd}" >/dev/null
done
SC="$(api POST /dhcp/scopes "{\"subnet_id\":$SUB,\"name\":\"LAN\",\"lease_time\":600,\"options\":{\"routers\":[\"192.168.10.1\"],\"dnsServers\":[\"192.168.10.2\"],\"domainName\":\"lab.test\"}}" | jq -r .id)"
api POST "/dhcp/scopes/$SC/pools" '{"start":"192.168.10.100","end":"192.168.10.150"}' >/dev/null
api POST "/dhcp/scopes/$SC/reservations" '{"mac":"aa:bb:cc:00:00:50","ip":"192.168.10.60","hostname":"imprimante"}' >/dev/null
LID="$(api POST /filter/lists '{"name":"Pubs","category":"ads","format":"domains"}' | jq -r .id)"
api POST "/filter/lists/$LID/import" '{"content":"bloque.example.net\n"}' >/dev/null
api PUT /filter/settings '{"rpzEnabled":true,"rpzAction":"nxdomain","sinkhole4":"0.0.0.0","sinkhole6":"::"}' >/dev/null
RES="$(api POST /system/apply '{"deploy":true}')"
echo "$RES" | jq -r '.results[] | "   \(.name): \(.ok)"' 2>/dev/null | head -8
expect_eq "validation par les outils officiels DANS l'appliance : tout est accepté" true "$(echo "$RES" | jq -r '[.results[].ok] | all')"
expect_eq "déploiement effectué" true "$(echo "$RES" | jq -r '.deployed')"
GENDIR="$T/var/lib/ddibuntu/generated"
check "marqueur .deployed écrit (déclencheur de l'unité .path)" test -s "$GENDIR/.deployed"
expect_eq "dépôt : fichiers appartenant au compte de service" ddiconsole "$(inapp stat -c %U /var/lib/ddibuntu/generated/named.conf.zones)"
expect_grep "named.conf déployé : chemin d'exécution des zones (≠ dossier de dépôt)" 'file "/var/lib/bind/ddibuntu/db\.lab\.test"' "$GENDIR/named.conf.zones"
expect_grep "named.conf déployé : filtrage RPZ avec déclencheurs QNAME immédiats" 'qname-wait-recurse no' "$GENDIR/named.conf.options"

echo "-- Application privilégiée de la configuration (ddibuntu-reload) --"
prev_local="$(sha256sum "$T/etc/bind/named.conf.local" | cut -d' ' -f1)"
inapp env DDI_RELOAD_NOSERVICES=1 /usr/local/sbin/ddibuntu-reload >"$T_TMP/reload.log" 2>&1; rc=$?
expect_eq "ddibuntu-reload : code retour 0" 0 "$rc"; [ "$rc" -eq 0 ] || tail -6 "$T_TMP/reload.log"
expect_grep "named.conf.local installé avec la zone" 'zone "lab\.test"' "$T/etc/bind/named.conf.local"
expect_eq "fichier de zone installé : bind:bind 0640" "bind:bind 640" "$(inapp stat -c '%U:%G %a' /var/lib/bind/ddibuntu/db.lab.test)"
expect_eq "kea-dhcp4.conf installé : root:_kea 0640 (contient le mot de passe de la base)" "root:_kea 640" "$(inapp stat -c '%U:%G %a' /etc/kea/kea-dhcp4.conf)"
check "named-checkconf accepte la VRAIE configuration BIND d'Ubuntu avec la nôtre" inapp named-checkconf /etc/bind/named.conf
expect_eq "sauvegarde de l'ancienne configuration conservée" yes "$([ -f "$T/var/lib/ddibuntu/backup/named.conf.local.prev" ] && echo yes || echo no)"
[ "$prev_local" != "$(sha256sum "$T/etc/bind/named.conf.local" | cut -d' ' -f1)" ] && ok "la configuration BIND a bien changé" || ko "la configuration BIND a bien changé"

echo "-- Frontière de privilèges : contenu hostile refusé, rien d'installé --"
hostile() {   # hostile "nom" fichier-à-modifier "commande sed"
  local n="$1" f="$2" cmd="$3" d="/tmp/evil-$RANDOM"
  cp -a "$GENDIR" "$T$d"
  # fichier déposé par l'« attaquant » (la console) : accepté par named-checkconf (qui ne charge pas les zones), mais déclarant une zone hors du dossier autorisé
  printf 'zone "evil.test" { type primary; file "/etc/passwd"; };\n' > "$T$d/extra.conf"
  cmd="${cmd//@D@/$d}"; sed -i "$cmd" "$T$d/$f"
  local b1 b2 k1 k2; b1="$(sha256sum "$T/etc/bind/named.conf.local" "$T/etc/bind/named.conf.options" "$T"/var/lib/bind/ddibuntu/db.* | sha256sum)"; k1="$(sha256sum "$T/etc/kea/kea-dhcp4.conf")"
  inapp env DDI_GENERATED_DIR="$d" DDI_RELOAD_NOSERVICES=1 /usr/local/sbin/ddibuntu-reload >"$T_TMP/h.log" 2>&1; local rc=$?
  b2="$(sha256sum "$T/etc/bind/named.conf.local" "$T/etc/bind/named.conf.options" "$T"/var/lib/bind/ddibuntu/db.* | sha256sum)"; k2="$(sha256sum "$T/etc/kea/kea-dhcp4.conf")"
  if [ "$rc" -ne 0 ] && [ "$b1" = "$b2" ] && [ "$k1" = "$k2" ]; then ok "refusé et rien d'installé : $n"; else ko "refusé et rien d'installé : $n" "rc=$rc $(head -c 200 "$T_TMP/h.log")"; fi
}
hostile "include d'un fichier arbitraire (named.conf.options)" named.conf.options '1i include "/etc/shadow";'
hostile "include d'un fichier contrôlé par l'attaquant (contournerait les contrôles du fichier principal)" named.conf.zones '1i include "@D@/extra.conf";'
hostile "directive controls" named.conf.zones '1i controls { inet 0.0.0.0 port 953 allow { any; } keys { "k"; }; };'
hostile "chemin de zone hors du dossier d'exécution" named.conf.zones '0,/file "[^"]*"/s##file "/etc/shadow"#'
hostile "plugin BIND" named.conf.options '1i plugin query "/tmp/evil.so";'
hostile "hooks-libraries Kea (exécution de code)" kea-dhcp4.conf 's/"subnet4"/"hooks-libraries": [{"library": "\/tmp\/evil.so"}], "subnet4"/'
hostile "socket de contrôle Kea hors de /run/kea" kea-dhcp4.conf 's#/run/kea/kea4-ctrl-socket#/tmp/ctrl#'
hostile "base de baux Kea distante" kea-dhcp4.conf 's#"host": "127.0.0.1"#"host": "10.9.9.9"#'
hostile "\$INCLUDE dans un fichier de zone" zones/db.lab.test '1i $INCLUDE /etc/passwd'
hostile "zone sans NS : named-checkzone refuse, retour arrière" zones/db.lab.test '/ IN NS /d'
check "après tous ces refus, la configuration saine peut toujours être appliquée" inapp env DDI_RELOAD_NOSERVICES=1 /usr/local/sbin/ddibuntu-reload

echo "-- DNS réel : BIND de l'appliance répond --"
ip netns exec "$APP" chroot "$T" /usr/sbin/named -u bind -f -c /etc/bind/named.conf >"$T_TMP/named.log" 2>&1 &
APP_PIDS="$APP_PIDS $!"
for _ in $(seq 30); do [ -n "$(incli chroot "$T" dig +short +time=1 +tries=1 @192.168.10.2 www.lab.test A 2>/dev/null)" ] && break; sleep 1; done
expect_eq "dig www.lab.test A -> 192.168.10.80 (réponse faisant autorité)" 192.168.10.80 "$(incli chroot "$T" dig +short +time=2 +tries=1 @192.168.10.2 www.lab.test A 2>/dev/null)"
[ "$(incli chroot "$T" dig +short +time=2 +tries=1 @192.168.10.2 www.lab.test A 2>/dev/null)" = 192.168.10.80 ] || { echo "journal named :"; tail -12 "$T_TMP/named.log" | cut -c1-200; }
expect_eq "dig ns1.lab.test A -> 192.168.10.2" 192.168.10.2 "$(incli chroot "$T" dig +short +time=2 +tries=1 @192.168.10.2 ns1.lab.test A 2>/dev/null)"
expect_grep "dig SOA lab.test : numéro de série daté (AAAAMMJJnn)" '^ns1\.lab\.test\. hostmaster\.lab\.test\. [0-9]{10} ' <(incli chroot "$T" dig +short +time=2 +tries=1 @192.168.10.2 lab.test SOA 2>/dev/null)
expect_eq "nom inexistant dans la zone : NXDOMAIN" 1 "$(incli chroot "$T" dig +noall +comments +time=2 +tries=1 @192.168.10.2 absent.lab.test A 2>/dev/null | grep -c 'status: NXDOMAIN')"
expect_eq "FILTRAGE : un domaine d'une liste de blocage reçoit NXDOMAIN de la politique RPZ" 1 "$(incli chroot "$T" dig +noall +comments +time=3 +tries=1 @192.168.10.2 bloque.example.net A 2>/dev/null | grep -c 'status: NXDOMAIN')"
expect_eq "FILTRAGE : un sous-domaine du domaine bloqué l'est aussi (joker RPZ)" 1 "$(incli chroot "$T" dig +noall +comments +time=3 +tries=1 @192.168.10.2 www.bloque.example.net A 2>/dev/null | grep -c 'status: NXDOMAIN')"
echo "-- Cockpit : le journal RÉEL de BIND est lu par la console sans privilège --"
cp "$T/var/log/named/query.log" "$ART/bind-query.log.sample" 2>/dev/null; cp "$T/etc/bind/named.conf.options" "$ART/bind-named.conf.options.sample" 2>/dev/null; true
expect_eq "journal BIND : /var/log/named appartient à bind:ddiconsole (0750)" "bind ddiconsole 750" "$(inapp stat -c '%U %G %a' /var/log/named)"
check "journal BIND : lisible par le compte ddiconsole" inapp runuser -u ddiconsole -- test -r /var/log/named/query.log
expect_grep "journal BIND : la réécriture RPZ est journalisée au format attendu par l'analyseur" 'rpz QNAME NXDOMAIN rewrite [^ ]*bloque\.example\.net' "$T/var/log/named/query.log"
for _ in $(seq 25); do [ "$(api GET '/cockpit/queries?status=blocked&domain=bloque.example.net' | jq -r '.items | length' 2>/dev/null)" = 2 ] && break; sleep 1; done
expect_eq "cockpit : la console a lu SEULE le journal réel : 2 requêtes bloquées (domaine et sous-domaine)" 2 "$(api GET '/cockpit/queries?status=blocked&domain=bloque.example.net' | jq -r '.items | length')"
expect_grep "cockpit : la raison du blocage est identifiée (liste ou règle)" '^(list:|blacklist)' <(api GET '/cockpit/queries?status=blocked&domain=bloque.example.net' | jq -r '.items[].reason')
expect_eq "cockpit : type de requête extrait du journal réel" A "$(api GET '/cockpit/queries?status=blocked&domain=bloque.example.net' | jq -r '.items[0].qtype')"
expect_grep "cockpit : adresse du client extraite du journal réel" '^192\.168\.10\.[0-9]+$' <(api GET '/cockpit/queries?status=blocked&domain=bloque.example.net' | jq -r '.items[0].client')
expect_eq "cockpit : une requête autorisée (www.lab.test) est journalisée comme telle, sans doublon" 1 "$([ "$(api GET '/cockpit/queries?status=allowed&domain=www.lab.test' | jq -r '.items | length')" -ge 1 ] && echo 1 || echo 0)"
# Témoin : l'ancien test « NXDOMAIN » pouvait réussir SANS RPZ (example.net n'est pas résoluble sans réseau). Un nom voisin NON bloqué
# doit être journalisé comme requête mais jamais réécrit : seule la ligne « rewrite » du journal prouve que le RPZ a agi.
incli chroot "$T" dig +noall +comments +time=3 +tries=1 @192.168.10.2 temoin.example.net A >/dev/null 2>&1; sleep 1
expect_eq "RPZ : le nom voisin non bloqué est journalisé comme requête" 1 "$([ "$(grep -c 'query: temoin\.example\.net IN A' "$T/var/log/named/query.log")" -ge 1 ] && echo 1 || echo 0)"
expect_eq "RPZ : le nom voisin non bloqué n'est JAMAIS réécrit (le blocage vient bien de la politique)" 0 "$(grep -c 'rewrite temoin\.example\.net' "$T/var/log/named/query.log")"
expect_eq "cockpit : le résumé compte les blocages réels" 1 "$([ "$(api GET '/cockpit/summary?range=1h' | jq -r '.blocked')" -ge 2 ] && echo 1 || echo 0)"
# named est lancé avec -f (comme en production) : la journalisation suit la configuration (fichier), pas stderr (-g la forcerait)
expect_grep "journal BIND : la réécriture RPZ est tracée dans le fichier configuré (source des statistiques et du cockpit)" 'rpz QNAME NXDOMAIN rewrite' "$T/var/log/named/query.log"

echo "-- DHCP réel : échange DISCOVER / OFFER / REQUEST / ACK avec Kea --"
ip netns exec "$APP" chroot "$T" /usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf >"$T_TMP/kea.log" 2>&1 &
APP_PIDS="$APP_PIDS $!"
for _ in $(seq 40); do grep -q 'DHCP4_STARTED' "$T_TMP/kea.log" 2>/dev/null && break; sleep 1; done
expect_grep "Kea démarre avec la configuration générée (base de baux PostgreSQL)" 'DHCP4_STARTED' "$T_TMP/kea.log"
[ -n "$(grep -m1 DHCP4_STARTED "$T_TMP/kea.log")" ] || tail -8 "$T_TMP/kea.log" | cut -c1-220
sleep 2
dh="$(incli python3 "$ROOT/tests/dhcp_client.py" vc aa:bb:cc:00:00:99 2>&1)"
echo "$dh" > "$T_TMP/dhcp1.json"
expect_eq "DISCOVER -> OFFER : une adresse de la plage 192.168.10.100-150" yes "$(jq -r '.offer.yiaddr' "$T_TMP/dhcp1.json" 2>/dev/null | awk -F. '$1==192&&$2==168&&$3==10&&$4>=100&&$4<=150{print "yes"}')"
expect_eq "OFFER : passerelle (option 3) = 192.168.10.1" '["192.168.10.1"]' "$(jq -c '.offer.routers' "$T_TMP/dhcp1.json" 2>/dev/null)"
expect_eq "OFFER : serveur DNS (option 6) = l'appliance" '["192.168.10.2"]' "$(jq -c '.offer.dns' "$T_TMP/dhcp1.json" 2>/dev/null)"
expect_eq "OFFER : domaine (option 15) et durée de bail (option 51)" "lab.test 600" "$(jq -r '"\(.offer.domain) \(.offer.lease)"' "$T_TMP/dhcp1.json" 2>/dev/null)"
expect_eq "REQUEST -> ACK : bail confirmé pour la même adresse" "5 $(jq -r '.offer.yiaddr' "$T_TMP/dhcp1.json" 2>/dev/null)" "$(jq -r '"\(.ack.type) \(.ack.yiaddr)"' "$T_TMP/dhcp1.json" 2>/dev/null)"
dh2="$(incli python3 "$ROOT/tests/dhcp_client.py" vc aa:bb:cc:00:00:50 2>&1)"; echo "$dh2" > "$T_TMP/dhcp2.json"
expect_eq "RÉSERVATION : l'adresse réservée dans l'IPAM (192.168.10.60) est attribuée à la MAC réservée" "192.168.10.60 5" "$(jq -r '"\(.ack.yiaddr) \(.ack.type)"' "$T_TMP/dhcp2.json" 2>/dev/null)"
sleep 1
leases="$(api GET /dhcp/leases)"
expect_eq "console : les baux réels (table Kea dans PostgreSQL) apparaissent" "true 2" "$(echo "$leases" | jq -r '"\(.available) \(.items | length)"')"
expect_eq "console : bail de la MAC réservée visible (adresse et MAC)" "192.168.10.60" "$(echo "$leases" | jq -r '.items[] | select(.mac=="aa:bb:cc:00:00:50") | .ip')"

finish
