#!/usr/bin/env bash
# make-chroot.sh — prépare (une fois) un chroot Ubuntu 24.04 minimal, SANS nftables ni whiptail,
# servant de système cible de substitution et d'image « conteneur propre » pour les tests.
# Usage : tools/make-chroot.sh [DOSSIER]   (défaut : /home/claude/cache/noble-min)
set -euo pipefail
DEST="${1:-/home/claude/cache/noble-min}"
if [[ -f "$DEST/.ddibuntu-chroot-ok" ]]; then echo "chroot déjà prêt : $DEST"; exit 0; fi
export DEBIAN_FRONTEND=noninteractive
command -v debootstrap >/dev/null 2>&1 || apt-get install -y -qq --no-install-recommends debootstrap >/dev/null
rm -rf "$DEST"; mkdir -p "$(dirname "$DEST")"
debootstrap --variant=minbase \
  --include=systemd,systemd-sysv,openssh-server,python3-minimal,sudo,iproute2,ca-certificates \
  noble "$DEST" http://archive.ubuntu.com/ubuntu
if chroot "$DEST" dpkg -s nftables >/dev/null 2>&1 || chroot "$DEST" dpkg -s whiptail >/dev/null 2>&1; then
  echo "ERREUR : nftables ou whiptail déjà présents dans le chroot de base : le test d'embarquement serait sans valeur" >&2; exit 1
fi
touch "$DEST/.ddibuntu-chroot-ok"
echo "chroot prêt : $DEST ($(du -sh "$DEST" | cut -f1))"
