#!/bin/bash
# update.sh — mode « mise à jour » : met à niveau une installation DDI-Buntu EXISTANTE depuis l'ISO, sans rien effacer.
# Lancé par Subiquity (early-commands, entrée « Update » du menu GRUB) AVANT toute étape de stockage.
#
# Garanties :
#   - jamais de partitionnement ni de formatage : le système existant est seulement monté ;
#   - données conservées : PostgreSQL, /var/lib/ddibuntu, /etc/ddibuntu (secrets, TLS, pare-feu), comptes, réseau ;
#   - paquets : seuls ceux qui sont absents ou plus anciens que ceux de l'ISO sont installés (jamais de rétrogradation),
#     les fichiers de configuration modifiés sont conservés (--force-confold) ;
#   - version plus ancienne que l'installée : refus (sauf « ddi-force » sur la ligne de commande du noyau) ;
#   - les fichiers remplacés sont sauvegardés dans /var/lib/ddibuntu/update-backup/ ;
#   - ce script NE REND JAMAIS la main à l'installateur (qui effacerait le disque) : succès = arrêt de la machine,
#     échec = message puis attente. Retirer l'ISO avant de rallumer.
#
# Variables de test : DDI_CDROM, DDI_TARGET, DDI_INTARGET=chroot, DDI_SKIP_MOUNT=1 (cible déjà montée), DDI_TEST=1 (rend la main)
set -uo pipefail

CDROM="${DDI_CDROM:-/cdrom}"
TARGET="${DDI_TARGET:-/target}"
SRC="$CDROM/ddibuntu"
TEST="${DDI_TEST:-0}"
LOG=/tmp/ddibuntu-update.log
CMDLINE="$(cat /proc/cmdline 2>/dev/null || true)"
STATE_REL=var/lib/ddibuntu
MOUNTED=0

say() {
  local m; m="ddibuntu-update: $*"
  printf '%s\n' "$m" | tee -a "$LOG"
  if [ "$TEST" = 0 ]; then { printf '%s\r\n' "$m" > /dev/tty1; } 2>/dev/null || true; fi
}
FAILMSG=""
fail() { FAILMSG="$*"; return 1; }

cleanup_mounts() {
  [ "$TEST" = 0 ] || return 0
  sync
  if [ "$MOUNTED" = 1 ]; then umount -R "$TARGET" 2>/dev/null || umount -R -l "$TARGET" 2>/dev/null || true; fi
  return 0
}

# ---- 1. Contrôle de l'ISO -------------------------------------------------------------------------------------------
check_media() {
  [ -d "$SRC" ] || { fail "dossier $SRC introuvable"; return; }
  ( cd "$SRC" && sha256sum -c --quiet rootfs.tar.sha256 ) || { fail "rootfs.tar corrompu (ISO endommagée)"; return; }
  if [ -f "$SRC/payloads.sha256" ]; then ( cd "$SRC" && sha256sum -c --quiet payloads.sha256 ) || { fail "console ou Node corrompus (ISO endommagée)"; return; }; fi
  if ls "$SRC"/debs/*.deb >/dev/null 2>&1; then ( cd "$SRC/debs" && sha256sum -c --quiet SHA256SUMS ) || { fail "paquets embarqués corrompus (ISO endommagée)"; return; }; fi
  [ -f "$SRC/console.tar.gz" ] || { fail "console.tar.gz absente de l'ISO"; return; }
  return 0
}

# ---- 2. Recherche et montage de l'installation existante ------------------------------------------------------------
is_ddi_root() { [ -d "$1/opt/ddibuntu" ] && [ -x "$1/usr/local/sbin/ddibuntu-apply" ]; }

find_root() {
  local forced dev fs probe n=0 found="" cands=""
  forced="${DDI_ROOT_DEV:-}"
  for w in $CMDLINE; do case "$w" in ddi-root=*) forced="${w#ddi-root=}" ;; esac; done
  if command -v vgchange >/dev/null 2>&1; then vgchange -ay >/dev/null 2>&1 || true; fi
  probe="$(mktemp -d /tmp/ddi-probe.XXXXXX)"
  if [ -n "$forced" ]; then
    cands="$forced"
  else
    cands="$(lsblk -rno PATH,FSTYPE 2>/dev/null | awk '$2=="ext4"||$2=="xfs"||$2=="btrfs"{print $1}')"
  fi
  for dev in $cands; do
    fs="$(lsblk -rno FSTYPE "$dev" 2>/dev/null | head -1)"
    if mount -o ro "$dev" "$probe" 2>/dev/null; then
      if is_ddi_root "$probe"; then found="$found $dev"; n=$((n + 1)); fi
      umount "$probe" 2>/dev/null || true
    else
      say "ignoré (montage impossible) : $dev ($fs)"
    fi
  done
  rmdir "$probe" 2>/dev/null || true
  case "$n" in
    0) fail "aucune installation DDI-Buntu trouvée sur les disques (mode mise à jour : rien n'a été modifié)"; return ;;
    1) ROOT_DEV="${found# }" ;;
    *) fail "plusieurs installations DDI-Buntu trouvées :$found — redémarrer et ajouter « ddi-root=/dev/... » au noyau (touche e dans le menu GRUB)"; return ;;
  esac
  say "installation trouvée : $ROOT_DEV"
  mkdir -p "$TARGET"
  mount "$ROOT_DEV" "$TARGET" || { fail "montage de $ROOT_DEV en lecture-écriture impossible"; return; }
  MOUNTED=1
  # /boot, /boot/efi, /var… séparés : montés comme sur le système (fstab), avec les périphériques de l'installateur
  for d in dev proc sys run; do mount --rbind "/$d" "$TARGET/$d" && mount --make-rslave "$TARGET/$d" 2>/dev/null; done
  chroot "$TARGET" mount -a 2>/dev/null || say "avertissement : « mount -a » incomplet dans le système cible (swap ou volumes non montés ?)"
  return 0
}

in_target() { if [ "${DDI_INTARGET:-chroot}" = chroot ]; then chroot "$TARGET" "$@"; else fail "DDI_INTARGET invalide"; fi; }

# ---- 3. Versions ----------------------------------------------------------------------------------------------------
check_versions() {
  NEW_VER="$(tr -d '\n' < "$SRC/VERSION")"
  OLD_VER="$(tr -d '\n' < "$TARGET/$STATE_REL/installed-version" 2>/dev/null || true)"
  [ -n "$OLD_VER" ] || OLD_VER="$(tr -d '\n' < "$TARGET/usr/local/lib/ddibuntu/VERSION" 2>/dev/null || true)"
  [ -n "$OLD_VER" ] || OLD_VER="inconnue"
  say "version installée : $OLD_VER ; version de l'ISO : $NEW_VER"
  if [ "$OLD_VER" != inconnue ] && [ "$OLD_VER" != "$NEW_VER" ] && [ "$(printf '%s\n%s\n' "$OLD_VER" "$NEW_VER" | sort -V | head -1)" = "$NEW_VER" ]; then
    case " $CMDLINE " in
      *" ddi-force "*) say "avertissement : retour à une version plus ancienne ($NEW_VER < $OLD_VER), forcé par ddi-force" ;;
      *) fail "l'ISO ($NEW_VER) est plus ancienne que l'installation ($OLD_VER) : refus. Ajouter « ddi-force » au noyau pour forcer."; return ;;
    esac
  fi
  local avail
  avail="$(df -Pk "$TARGET" | awk 'NR==2{print $4}')"
  [ "${avail:-0}" -ge 1048576 ] || { fail "moins de 1 Go libre sur le système installé"; return; }
  return 0
}

# ---- 4. Sauvegarde des fichiers remplacés ---------------------------------------------------------------------------
backup_current() {
  local b="$TARGET/$STATE_REL/update-backup" stamp list f
  stamp="$(date -u +%Y%m%dT%H%M%SZ)-$OLD_VER"
  mkdir -p "$b/$stamp" && chmod 0700 "$TARGET/$STATE_REL/update-backup" "$b/$stamp"
  list="$(mktemp /tmp/ddi-list.XXXXXX)"
  tar -tf "$SRC/rootfs.tar" | sed 's,^\./,,' | sed 's,/$,,' | awk 'NF && $0 != "."' | while IFS= read -r f; do
    if [ -e "$TARGET/$f" ] || [ -L "$TARGET/$f" ]; then
      [ -d "$TARGET/$f" ] && [ ! -L "$TARGET/$f" ] || printf '%s\n' "$f"
    fi
  done > "$list"
  for f in opt/ddibuntu/console opt/ddibuntu/node; do [ -d "$TARGET/$f" ] && printf '%s\n' "$f" >> "$list"; done
  [ ! -f "$TARGET/$STATE_REL/installed-version" ] || printf '%s\n' "$STATE_REL/installed-version" >> "$list"
  tar -C "$TARGET" -czf "$b/$stamp/replaced-files.tar.gz" --numeric-owner -T "$list" || { rm -f "$list"; fail "sauvegarde des fichiers remplacés impossible"; return; }
  rm -f "$list"
  BACKUP_DIR="$b/$stamp"
  say "sauvegarde : /$STATE_REL/update-backup/$stamp/replaced-files.tar.gz"
  # conserve les 3 dernières sauvegardes
  find "$b" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | tail -n +4 | while IFS= read -r f; do rm -rf "$f"; done
  return 0
}

# ---- 5. Paquets : seulement les plus récents que l'installé ----------------------------------------------------------
update_packages() {
  ls "$SRC"/debs/*.deb >/dev/null 2>&1 || { say "aucun paquet embarqué : paquets inchangés"; return 0; }
  local deb pkg ver cur sel="" n=0
  for deb in "$SRC"/debs/*.deb; do
    pkg="$(dpkg-deb -f "$deb" Package)"; ver="$(dpkg-deb -f "$deb" Version)"
    # shellcheck disable=SC2016  # ${Version} est le format de dpkg-query, pas une variable
    cur="$(chroot "$TARGET" dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    if [ -z "$cur" ] || dpkg --compare-versions "$ver" gt "$cur"; then
      sel="$sel $(basename "$deb")"; n=$((n + 1)); say "  paquet $pkg : ${cur:-absent} -> $ver"
    fi
  done
  if [ "$n" -eq 0 ]; then say "paquets déjà à jour"; return 0; fi
  mkdir -p "$TARGET/var/cache/ddibuntu-debs"
  for deb in $sel; do cp "$SRC/debs/$deb" "$TARGET/var/cache/ddibuntu-debs/"; done
  # aucun service ne doit être démarré/redémarré pendant la mise à jour (le système cible n'est pas démarré)
  local pc="$TARGET/usr/sbin/policy-rc.d" pcbak=""
  if [ -e "$pc" ]; then pcbak="$pc.ddi-orig"; mv -f "$pc" "$pcbak"; fi
  printf '#!/bin/sh\nexit 101\n' > "$pc"; chmod 0755 "$pc"
  # shellcheck disable=SC2016
  DEBIAN_FRONTEND=noninteractive chroot "$TARGET" bash -c 'dpkg --force-confold --force-confdef -i /var/cache/ddibuntu-debs/*.deb'
  local rc=$?
  rm -f "$pc"; [ -z "$pcbak" ] || mv -f "$pcbak" "$pc"
  rm -rf "$TARGET/var/cache/ddibuntu-debs"
  [ "$rc" -eq 0 ] || { fail "installation des paquets impossible (code $rc) ; voir $LOG"; return; }
  return 0
}

# ---- 6. Fichiers de l'appliance, console, Node ----------------------------------------------------------------------
deploy_files() {
  local ex=()
  # réglages d'administration : conservés tels quels (pare-feu et règles déjà rendues)
  [ ! -e "$TARGET/etc/ddibuntu/firewall.conf" ] || ex+=(--exclude=./etc/ddibuntu/firewall.conf)
  [ ! -e "$TARGET/etc/ddibuntu/nftables.nft" ] || ex+=(--exclude=./etc/ddibuntu/nftables.nft)
  [ ! -e "$TARGET/etc/ddibuntu/update.conf" ] || ex+=(--exclude=./etc/ddibuntu/update.conf)
  [ ! -e "$TARGET/etc/ddibuntu/backup.conf" ] || ex+=(--exclude=./etc/ddibuntu/backup.conf)
  tar -xpf "$SRC/rootfs.tar" --numeric-owner "${ex[@]}" -C "$TARGET" || { fail "déploiement des fichiers de l'appliance impossible"; return; }

  local app="$TARGET/opt/ddibuntu"
  mkdir -p "$app"
  rm -rf "$app/console.new" "$app/console.old"; mkdir -p "$app/console.new"
  tar -xzf "$SRC/console.tar.gz" --no-same-owner -C "$app/console.new" || { rm -rf "$app/console.new"; fail "extraction de la console impossible"; return; }
  [ -f "$app/console.new/app/server/index.mjs" ] || { rm -rf "$app/console.new"; fail "console de l'ISO incomplète"; return; }
  [ ! -d "$app/console" ] || mv "$app/console" "$app/console.old"
  mv "$app/console.new" "$app/console"
  if [ -f "$SRC/node-linux-x64.tar.gz" ]; then
    rm -rf "$app/node.new" "$app/node.old"; mkdir -p "$app/node.new"
    tar -xzf "$SRC/node-linux-x64.tar.gz" --no-same-owner --strip-components=1 -C "$app/node.new" || { rm -rf "$app/node.new"; fail "extraction de Node impossible"; return; }
    [ -x "$app/node.new/bin/node" ] || { rm -rf "$app/node.new"; fail "Node de l'ISO incomplet"; return; }
    [ ! -d "$app/node" ] || mv "$app/node" "$app/node.old"
    mv "$app/node.new" "$app/node"
  fi
  chown -R 0:0 "$app"
  rm -rf "$app/console.old" "$app/node.old"

  # comptes, unités, pare-feu : idempotents, sans toucher aux données
  in_target groupadd -f ddiconsole || { fail "groupe ddiconsole impossible à créer"; return; }
  in_target groupadd -f ddiadmin || { fail "groupe ddiadmin impossible à créer"; return; }
  in_target bash -c 'id ddiconsole >/dev/null 2>&1 || useradd --system --gid ddiconsole --home-dir /var/lib/ddibuntu --shell /usr/sbin/nologin ddiconsole' || { fail "compte ddiconsole impossible"; return; }
  in_target systemctl enable ddibuntu-firstboot.service nftables.service postgresql.service named.service \
    ddibuntu-db-init.service ddibuntu-console.service ddibuntu-reload.path ddibuntu-ad-request.path ddibuntu-cluster-setup.path ddibuntu-backup-request.path ddibuntu-backup.timer ddibuntu-health.timer ddibuntu-selfupdate.path ddibuntu-update-check.timer >/dev/null 2>&1 || { fail "activation des services impossible"; return; }
  # dépôt des sauvegardes : propriété de postgres (l'archivage des journaux WAL s'y écrit sous ce compte)
  mkdir -p "$TARGET/var/lib/ddibuntu/backup/base" "$TARGET/var/lib/ddibuntu/backup/wal"
  in_target chown -R postgres:postgres /var/lib/ddibuntu/backup 2>/dev/null || say "avertissement : dépôt de sauvegarde non attribué à postgres (sera corrigé par le minuteur)"
  chmod 0750 "$TARGET/var/lib/ddibuntu/backup" "$TARGET/var/lib/ddibuntu/backup/base" "$TARGET/var/lib/ddibuntu/backup/wal"
  # règles du pare-feu : re-rendues depuis firewall.conf conservé (écrites, non appliquées avant le redémarrage)
  in_target /usr/local/sbin/ddibuntu-fw write >/dev/null 2>&1 || say "avertissement : règles du pare-feu non re-rendues (anciennes règles conservées)"
  cp "$SRC/VERSION" "$TARGET/$STATE_REL/installed-version"
  printf '%s -> %s le %s\n' "$OLD_VER" "$NEW_VER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$TARGET/$STATE_REL/update-history"
  return 0
}

verify_result() {
  local f
  for f in usr/local/sbin/ddibuntu-apply usr/local/sbin/ddibuntu-setup usr/local/sbin/ddibuntu-fw usr/local/bin/ddibuntu-menu \
           usr/local/lib/ddibuntu/common.sh usr/local/lib/ddibuntu/console-start opt/ddibuntu/console/app/server/index.mjs; do
    [ -f "$TARGET/$f" ] || { fail "fichier attendu absent après mise à jour : /$f"; return; }
  done
  [ "$(tr -d '\n' < "$TARGET/$STATE_REL/installed-version")" = "$NEW_VER" ] || { fail "version installée non écrite"; return; }
  return 0
}

run() {
  : > "$LOG"
  say "MODE MISE À JOUR DDI-Buntu — aucun disque ne sera effacé"
  check_media || return 1
  if [ "${DDI_SKIP_MOUNT:-0}" = 1 ]; then [ -d "$TARGET" ] || { fail "cible $TARGET introuvable"; return 1; }; else find_root || return 1; fi
  check_versions || return 1
  backup_current || return 1
  update_packages || return 1
  deploy_files || return 1
  verify_result || return 1
  cp "$LOG" "$TARGET/$STATE_REL/update-$(date -u +%Y%m%dT%H%M%SZ).log" 2>/dev/null || true
  return 0
}

if run; then
  say "TERMINÉ : $OLD_VER -> $NEW_VER. Données conservées. Sauvegarde : ${BACKUP_DIR#"$TARGET"}"
  cleanup_mounts
  [ "$TEST" = 0 ] || exit 0
  say "La machine va s'ARRÊTER. Retirez l'ISO (ou le support USB) puis rallumez-la : le menu de l'ISO propose d'effacer le disque."
  sleep 20
  eject "${CDROM}" 2>/dev/null || true
  systemctl poweroff 2>/dev/null || poweroff -f 2>/dev/null || true
else
  say "ÉCHEC DE LA MISE À JOUR : $FAILMSG"
  say "Le système existant n'a pas été effacé. Journal : $LOG. Éteignez la machine (bouton d'alimentation) et retirez l'ISO."
  cleanup_mounts
  [ "$TEST" = 0 ] || exit 1
fi
# Ne jamais rendre la main à l'installateur : il effacerait le disque.
while :; do sleep 3600; done
