#!/bin/bash
# late.sh — exécuté par Subiquity (late-commands) dans l'environnement d'installation.
# Vérifie les empreintes, installe les paquets embarqués, déploie les fichiers de l'appliance,
# active ses services. Tout échec arrête l'installation : aucun succès n'est masqué.
#
# Variables de test : DDI_CDROM, DDI_TARGET, DDI_INTARGET=chroot
set -euo pipefail

CDROM="${DDI_CDROM:-/cdrom}"
TARGET="${DDI_TARGET:-/target}"
INTARGET="${DDI_INTARGET:-curtin}"
SRC="$CDROM/ddibuntu"

log() { printf 'ddibuntu-late: %s\n' "$*"; }
fail() { printf 'ddibuntu-late: ERREUR : %s\n' "$*" >&2; exit 1; }

in_target() {
  case "$INTARGET" in
    curtin) curtin in-target --target="$TARGET" -- "$@" ;;
    chroot) chroot "$TARGET" "$@" ;;
    *) fail "DDI_INTARGET invalide : $INTARGET" ;;
  esac
}

[ -d "$SRC" ] || fail "dossier $SRC introuvable"
[ -d "$TARGET" ] || fail "système cible $TARGET introuvable"

log "vérification de l'archive des fichiers de l'appliance"
( cd "$SRC" && sha256sum -c --quiet rootfs.tar.sha256 ) || fail "rootfs.tar corrompu"

if ls "$SRC"/debs/*.deb >/dev/null 2>&1; then
  log "vérification et installation des paquets embarqués"
  ( cd "$SRC/debs" && sha256sum -c --quiet SHA256SUMS ) || fail "paquets embarqués corrompus"
  mkdir -p "$TARGET/var/cache/ddibuntu-debs"
  cp "$SRC"/debs/*.deb "$TARGET/var/cache/ddibuntu-debs/"
  in_target bash -c 'dpkg -i --skip-same-version /var/cache/ddibuntu-debs/*.deb' || fail "installation des paquets embarqués impossible"
  rm -rf "$TARGET/var/cache/ddibuntu-debs"
fi

log "déploiement des fichiers de l'appliance"
tar -xpf "$SRC/rootfs.tar" --numeric-owner -C "$TARGET"
mkdir -p "$TARGET/var/lib/ddibuntu"
cp "$SRC/VERSION" "$TARGET/var/lib/ddibuntu/installed-version"

log "console web, moteur Node et comptes de service"
if [ -f "$SRC/payloads.sha256" ]; then ( cd "$SRC" && sha256sum -c --quiet payloads.sha256 ) || fail "charge utile (console ou Node) corrompue"; fi
mkdir -p "$TARGET/opt/ddibuntu/console"
tar -xzf "$SRC/console.tar.gz" --no-same-owner -C "$TARGET/opt/ddibuntu/console"
if [ -f "$SRC/node-linux-x64.tar.gz" ]; then
  mkdir -p "$TARGET/opt/ddibuntu/node"
  tar -xzf "$SRC/node-linux-x64.tar.gz" --no-same-owner --strip-components=1 -C "$TARGET/opt/ddibuntu/node"
fi
chown -R 0:0 "$TARGET/opt/ddibuntu"
in_target groupadd -f ddiconsole
in_target bash -c 'id ddiconsole >/dev/null 2>&1 || useradd --system --gid ddiconsole --home-dir /var/lib/ddibuntu --shell /usr/sbin/nologin ddiconsole'
mkdir -p "$TARGET/var/lib/ddibuntu/generated"
in_target chown ddiconsole:ddiconsole /var/lib/ddibuntu/generated
chmod 0750 "$TARGET/var/lib/ddibuntu/generated"

log "services et durcissement"
in_target groupadd -f ddiadmin
in_target systemctl enable ddibuntu-firstboot.service nftables.service postgresql.service named.service \
  ddibuntu-db-init.service ddibuntu-console.service ddibuntu-reload.path ddibuntu-selfupdate.path ddibuntu-update-check.timer
# Kea ne démarre qu'après un déploiement contenant au moins une étendue (ddibuntu-reload l'active alors)
in_target systemctl disable kea-dhcp4-server.service
# Cluster : etcd et Patroni ne démarrent QUE sur ordre de « ddibuntu-cluster » (le paquet etcd démarrerait sinon un magasin en clair sur 127.0.0.1)
in_target groupadd -f ddicluster
in_target systemctl disable etcd.service patroni.service 2>/dev/null || true
in_target systemctl mask ctrl-alt-del.target

log "contrôles finaux"
for f in usr/local/sbin/ddibuntu-apply usr/local/sbin/ddibuntu-setup usr/local/sbin/ddibuntu-fw \
         usr/local/bin/ddibuntu-menu usr/local/lib/ddibuntu/common.sh etc/ddibuntu/nftables.nft \
         etc/ssh/sshd_config.d/10-ddibuntu.conf etc/sysctl.d/90-ddibuntu.conf \
         usr/local/sbin/ddibuntu-db-init usr/local/sbin/ddibuntu-reload usr/local/lib/ddibuntu/console-start \
         usr/local/sbin/ddibuntu-selfupdate usr/local/sbin/ddibuntu-cluster etc/ddibuntu/update.conf etc/ddibuntu/update-pubkey.pem \
         opt/ddibuntu/console/app/server/index.mjs; do
  [ -f "$TARGET/$f" ] || fail "fichier attendu absent après déploiement : /$f"
done
[ -L "$TARGET/etc/systemd/system/ctrl-alt-del.target" ] || fail "ctrl-alt-del.target n'est pas masqué"
# Le lien est absolu (relatif à la racine de la cible) : « -e » le résoudrait sur l'installateur, d'où « -L »
[ -L "$TARGET/etc/systemd/system/multi-user.target.wants/ddibuntu-firstboot.service" ] || fail "assistant de premier démarrage non activé"
[ -L "$TARGET/etc/systemd/system/sysinit.target.wants/nftables.service" ] || fail "pare-feu nftables non activé au démarrage"
[ -L "$TARGET/etc/systemd/system/multi-user.target.wants/ddibuntu-console.service" ] || fail "console web non activée"
[ -L "$TARGET/etc/systemd/system/multi-user.target.wants/ddibuntu-reload.path" ] || fail "application de la configuration non activée"
if [ -f "$SRC/node-linux-x64.tar.gz" ]; then [ -x "$TARGET/opt/ddibuntu/node/bin/node" ] || fail "Node absent après déploiement"; fi
log "terminé : DDI-Buntu $(cat "$SRC/VERSION")"
