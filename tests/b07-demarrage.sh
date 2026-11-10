#!/usr/bin/env bash
# Batterie 07 — démarrage réel de l'ISO produite sous QEMU, en BIOS (SeaBIOS) puis en UEFI (OVMF).
# Preuve : le menu GRUB (lu sur la console série ET capturé à l'écran) propose en première position
# « Install DDI-Buntu … (automatic - ERASES the target disk) », sélectionnée par défaut, avec le
# compte à rebours demandé ; à l'expiration, GRUB lance bien l'entrée (erreur de noyau attendue :
# le noyau de la substitution est factice).
# Limite : ISO de SUBSTITUTION, pas celle de Canonical : l'installateur Subiquity n'est pas démarré.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=lib-iso.sh
. "$(dirname "$0")/lib-iso.sh"

OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
SHOTS="$ART/captures"; mkdir -p "$SHOTS"; rm -f "$SHOTS"/*.png
VER="$(tr -d '\n' < "$ROOT/src/VERSION")"
python3 -c 'import PIL' 2>/dev/null || pip install -q --break-system-packages pillow >/dev/null 2>&1
if ! python3 -c 'import PIL' 2>/dev/null; then ko "Pillow indisponible : captures impossibles"; finish; exit; fi
QPID=""
cleanup() { [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; pkill -f "qemu-system-x86_64.*ddit-b07" 2>/dev/null; rm -rf "$T_TMP"; }
trap cleanup EXIT

echo "== Construction des deux ISO (menu figé, puis compte à rebours de 5 s) =="
make_fake_iso "$T_TMP/in.iso" normal
for t in -1 5; do
  bash "$DIST" --no-docker --iso "$T_TMP/in.iso" --allow-unverified --skip-debs --skip-node --timeout "$t" --out "$T_TMP/out$t" >"$T_TMP/b$t.log" 2>&1
  check "ISO construite (--timeout $t)" test -s "$T_TMP/out$t/ddibuntu-$VER-amd64.iso"
done
ISO_WAIT="$T_TMP/out-1/ddibuntu-$VER-amd64.iso"; ISO_AUTO="$T_TMP/out5/ddibuntu-$VER-amd64.iso"

boot() {   # boot MODE ISO NOM : lance QEMU en tâche de fond, journal série dans $T_TMP/NOM.serial
  local mode="$1" iso="$2" name="$3" opts
  rm -f "$T_TMP/$name.sock" "$T_TMP/$name.serial"
  if [ "$mode" = uefi ]; then
    cp "$OVMF_VARS" "$T_TMP/$name.vars"
    opts="-machine q35 -drive if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE -drive if=pflash,format=raw,unit=1,file=$T_TMP/$name.vars"
  else
    opts="-machine pc"
  fi
  # shellcheck disable=SC2086
  qemu-system-x86_64 -name "ddit-b07-$name" $opts -accel tcg -m 768 -cdrom "$iso" -boot d -display none -no-reboot \
    -serial "file:$T_TMP/$name.serial" -monitor "unix:$T_TMP/$name.sock,server,nowait" >"$T_TMP/$name.qemu.log" 2>&1 </dev/null &
  QPID=$!
}
wait_for() {   # wait_for FICHIER MOTIF SECONDES
  for _ in $(seq "$3"); do grep -aq -- "$2" "$1" 2>/dev/null && return 0; sleep 1; done
  return 1
}
stop() { kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null; QPID=""; }
plain() { sed 's/\x1b\[[0-9;?]*[A-Za-z]//g; s/\r//g' "$1" | tr -d '\000'; }

check_menu() {   # check_menu MODE : démarre l'ISO au menu figé, contrôle série + capture
  local mode="$1"
  boot "$mode" "$ISO_WAIT" "wait-$mode"
  if wait_for "$T_TMP/wait-$mode.serial" "Install DDI-Buntu" 240; then ok "[$mode] le menu GRUB s'affiche sur la console série"; else
    ko "[$mode] le menu GRUB s'affiche sur la console série" "$(plain "$T_TMP/wait-$mode.serial" | tail -c 300 | tr '\n' ' ') / $(head -c 200 "$T_TMP/wait-$mode.qemu.log")"; stop; return
  fi
  sleep 3
  plain "$T_TMP/wait-$mode.serial" > "$T_TMP/wait-$mode.txt"
  expect_grep "[$mode] entrée « Install DDI-Buntu $VER (automatic - ERASES the target disk) »" "Install DDI-Buntu $VER \(automatic - ERASES the target disk\)" "$T_TMP/wait-$mode.txt"
  expect_grep "[$mode] l'entrée DDI-Buntu est la sélectionnée (marqueur *)" '\*Install DDI-Buntu' "$T_TMP/wait-$mode.txt"
  # la console série concatène les entrées sur une ligne : on compare des positions en octets
  a="$(grep -aob 'Install DDI-Buntu' "$T_TMP/wait-$mode.txt" | head -1 | cut -d: -f1)"; b="$(grep -aob 'Try or Install Ubuntu Server' "$T_TMP/wait-$mode.txt" | head -1 | cut -d: -f1)"
  if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then ok "[$mode] l'entrée DDI-Buntu précède les entrées d'origine"; else ko "[$mode] ordre des entrées" "a=$a b=$b"; fi
  expect_grep "[$mode] entrées d'origine conservées (HWE)" 'Ubuntu Server with the HWE kernel' "$T_TMP/wait-$mode.txt"
  expect_nogrep "[$mode] --timeout -1 : aucun compte à rebours (menu figé)" 'executed automatically' "$T_TMP/wait-$mode.txt"
  out="$(python3 "$ROOT/tests/qemu-shot.py" "$T_TMP/wait-$mode.sock" "$SHOTS/demarrage-$mode.png" 2>&1)"
  read -r dim ncol nlit <<<"$out"
  if [ -s "$SHOTS/demarrage-$mode.png" ] && [ "${ncol:-0}" -ge 2 ] && [ "${nlit:-0}" -gt 1000 ]; then ok "[$mode] capture d'écran non vide ($dim, $ncol couleurs, $nlit pixels allumés)"; else ko "[$mode] capture d'écran non vide" "$out"; fi
  stop
}
check_auto() {   # check_auto MODE : compte à rebours puis lancement automatique de l'entrée
  local mode="$1"
  boot "$mode" "$ISO_AUTO" "auto-$mode"
  if wait_for "$T_TMP/auto-$mode.serial" "executed automatically in" 240; then ok "[$mode] compte à rebours « executed automatically in … » affiché"; else
    ko "[$mode] compte à rebours affiché" "$(plain "$T_TMP/auto-$mode.serial" | tail -c 300 | tr '\n' ' ')"; stop; return
  fi
  plain "$T_TMP/auto-$mode.serial" > "$T_TMP/auto-$mode.txt"
  expect_grep "[$mode] compte à rebours = 5 s (valeur de --timeout)" 'automatically in [45]s' "$T_TMP/auto-$mode.txt"
  if wait_for "$T_TMP/auto-$mode.serial" "error:" 60; then ok "[$mode] à l'expiration GRUB lance l'entrée (erreur de noyau attendue : noyau factice)"; else ko "[$mode] lancement automatique à l'expiration" "$(plain "$T_TMP/auto-$mode.serial" | tail -c 300 | tr '\n' ' ')"; fi
  stop
}

echo "== Démarrage BIOS (SeaBIOS) =="
check_menu bios
check_auto bios
echo "== Démarrage UEFI (OVMF) =="
if [ -f "$OVMF_CODE" ] && [ -f "$OVMF_VARS" ]; then
  check_menu uefi
  check_auto uefi
else
  ko "firmware OVMF absent : démarrage UEFI non testé" "$OVMF_CODE"
fi
note "ISO de substitution : le menu GRUB est prouvé, pas l'installateur Subiquity"
finish
