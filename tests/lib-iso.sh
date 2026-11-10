#!/usr/bin/env bash
# lib-iso.sh — génération de l'ISO de SUBSTITUTION utilisée par les batteries 05 et 07.
# Ce n'est pas l'ISO Canonical : elle reproduit sa disposition de démarrage (MBR hybride, GPT avec
# partition EFI ajoutée, grub.cfg de même structure) pour valider la chaîne de construction.
# shellcheck disable=SC2154  # T_TMP vient de lib.sh
make_fake_iso() {   # $1 = fichier ISO, $2 = variante : normal | sans-menuentry | sans-noyau
  local tree="$T_TMP/tree.$$.$RANDOM"
  mkdir -p "$tree/boot/grub" "$tree/casper" "$tree/.disk"
  [ "$2" = "sans-noyau" ] || { head -c 65536 /dev/urandom > "$tree/casper/vmlinuz"; head -c 32768 /dev/urandom > "$tree/casper/initrd"; }
  echo "Ubuntu-Server 24.04.9 LTS (substitution de test)" > "$tree/.disk/info"
  if [ "$2" = "sans-menuentry" ]; then
    printf 'set timeout=30\nset default=0\n' > "$tree/boot/grub/grub.cfg"
  else
    {
      printf 'serial --unit=0 --speed=115200\nterminal_input console serial\nterminal_output console serial\n'
      printf 'if loadfont /boot/grub/font.pf2 ; then\n\tset gfxmode=auto\nfi\n'
      printf 'set menu_color_normal=white/black\nset menu_color_highlight=black/light-gray\nset timeout=30\n'
      printf 'menuentry "Try or Install Ubuntu Server" {\n\tset gfxpayload=keep\n\tlinux\t/casper/vmlinuz   ---\n\tinitrd\t/casper/initrd\n}\n'
      printf 'menuentry "Ubuntu Server with the HWE kernel" {\n\tset gfxpayload=keep\n\tlinux\t/casper/hwe-vmlinuz   ---\n\tinitrd\t/casper/hwe-initrd\n}\n'
    } > "$tree/boot/grub/grub.cfg"
  fi
  # Disposition de type Ubuntu 22.04/24.04 : MBR hybride, GPT avec partition EFI ajoutée après l'ISO,
  # démarrage BIOS (El Torito grub) et UEFI (El Torito pointant sur la partition ajoutée).
  # grub-mkrescue ne fournit que les modules GRUB et l'image EFI ; sa propre disposition (HFS+, APM)
  # n'est pas celle d'Ubuntu et fait échouer le « replay » (défaut du banc, constaté).
  local stage="$T_TMP/stage.$RANDOM"
  grub-mkrescue -o "$stage.iso" "$tree" >/dev/null 2>&1 || return 1
  mkdir -p "$stage"; xorriso -osirrox on -indev "$stage.iso" -extract / "$stage" >/dev/null 2>&1; chmod -R u+w "$stage"
  mv "$stage/efi.img" "$stage.efi.img"; rm -rf "$stage/System" "$stage/mach_kernel" "$stage/boot.catalog" "$stage/efi"
  xorriso -as mkisofs -r -V "Ubuntu-Server 24.04 LTS amd64" -o "$1" \
    --grub2-mbr /usr/lib/grub/i386-pc/boot_hybrid.img --protective-msdos-label -partition_cyl_align off \
    -partition_offset 16 --mbr-force-bootable \
    -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "$stage.efi.img" -appended_part_as_gpt \
    -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
    -c /boot.catalog -b /boot/grub/i386-pc/eltorito.img -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
    -eltorito-alt-boot -e '--interval:appended_partition_2:::' -no-emul-boot "$stage" >/dev/null 2>&1
}

# Miroir Node.js factice, signé avec une clé de TEST (la vraie signature de nodejs.org n'est pas joignable depuis le banc).
# $1 = dossier du miroir ; $2 = tiny (faux binaire) | real (copie du node du banc) ; exporte NODE_MIRROR_FPR et NODE_MIRROR_GH
make_node_mirror() {
  local m="$1" kind="$2"
  NODE_MIRROR_GH="$T_TMP/nodegpg.$RANDOM"
  mkdir -p "$m/node/latest-v22.x" "$m/keys" "$NODE_MIRROR_GH"; chmod 700 "$NODE_MIRROR_GH"
  gpg --homedir "$NODE_MIRROR_GH" --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "Node test <node@test.invalid>" ed25519 sign never 2>/dev/null
  NODE_MIRROR_FPR="$(gpg --homedir "$NODE_MIRROR_GH" --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"
  gpg --homedir "$NODE_MIRROR_GH" --armor --export "$NODE_MIRROR_FPR" > "$m/keys/$NODE_MIRROR_FPR.asc"
  local td="$T_TMP/nodetree.$RANDOM" name="node-v22.99.0-linux-x64"
  mkdir -p "$td/$name/bin"
  if [ "$kind" = real ]; then cp "$(command -v node)" "$td/$name/bin/node"; else printf '#!/bin/sh\necho v22.99.0\n' > "$td/$name/bin/node"; chmod 755 "$td/$name/bin/node"; fi
  tar -czf "$m/node/latest-v22.x/$name.tar.gz" -C "$td" "$name"
  { printf '%s  %s\n' "$(printf 'a%.0s' {1..64})" "node-v22.99.0-linux-arm64.tar.gz"
    printf '%s  %s\n' "$(printf 'b%.0s' {1..64})" "node-v22.99.0-linux-x64.tar.xz"
    printf '%s  %s.tar.gz\n' "$(sha256sum "$m/node/latest-v22.x/$name.tar.gz" | cut -d' ' -f1)" "$name"; } > "$m/node/latest-v22.x/SHASUMS256.txt"
  gpg --homedir "$NODE_MIRROR_GH" --batch --pinentry-mode loopback --passphrase '' --local-user "$NODE_MIRROR_FPR" --clearsign \
    --output "$m/node/latest-v22.x/SHASUMS256.txt.asc" "$m/node/latest-v22.x/SHASUMS256.txt" 2>/dev/null
  rm -f "$m/node/latest-v22.x/SHASUMS256.txt"
}
