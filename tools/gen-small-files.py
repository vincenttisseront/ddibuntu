#!/usr/bin/env python3
"""Écrit les petits fichiers de l'overlay rootfs (outil de développement, non livré dans l'ISO)."""
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def w(path, content, mode=0o644):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(full, mode)


w("usr/local/bin/ddibuntu-menu", r'''#!/bin/bash
# ddibuntu-menu — menu console affiché après la connexion d'un administrateur.
set -uo pipefail

DDI_LIBDIR="${DDI_LIBDIR:-/usr/local/lib/ddibuntu}"
# shellcheck source=/dev/null
. "$DDI_LIBDIR/common.sh"
export TERM="${TERM:-linux}"
[ -t 0 ] && [ -t 1 ] || exit 0

ddi_cfg_reset
if [ -f "$DDI_CONFFILE" ]; then ddi_cfg_read "$DDI_CONFFILE"; fi
ddi_load_lang "${CFG_LANGUAGE:-fr}"

wt_yesno() { whiptail --title "$M_TITLE" --yesno "$1" 12 74; }

show_status() {
  local fw ssh
  fw="$(systemctl is-active nftables 2>/dev/null || true)"
  ssh="$(systemctl is-active ssh 2>/dev/null || true)"
  whiptail --title "$M_TITLE" --msgbox "$(ddi_fmt "$M_STATUS_FMT" "$(ddi_version)" "$(hostname)" "$fw" "$ssh" "$(ip -br address | grep -v '^lo ')")" 20 74
}

# Depuis une session SSH, tout changement de pare-feu est annulé sans confirmation (anti-verrouillage).
setup() {
  if [ -n "${SSH_CONNECTION:-}" ]; then
    sudo /usr/local/sbin/ddibuntu-setup --fw-confirm 60 "$@"
  else
    sudo /usr/local/sbin/ddibuntu-setup "$@"
  fi
}

while :; do
  choice="$(whiptail --title "$M_TITLE" --cancel-button "$M_MENU_QUIT" \
    --menu "$(ddi_fmt "$M_MENU_PROMPT" "$(ddi_version)" "$(hostname)")" 20 74 9 \
    status "$M_MENU_STATUS" \
    network "$M_MENU_NETWORK" \
    adminnets "$M_MENU_ADMINNETS" \
    language "$M_MENU_LANGUAGE" \
    password "$M_MENU_PASSWORD" \
    logs "$M_MENU_LOGS" \
    reboot "$M_MENU_REBOOT" \
    shutdown "$M_MENU_SHUTDOWN" \
    shell "$M_MENU_SHELL" 3>&1 1>&2 2>&3)" || break
  case "$choice" in
    status)    show_status ;;
    network)   setup --network ;;
    adminnets) setup --adminnets ;;
    language)  setup --language; ddi_cfg_reset; ddi_cfg_read "$DDI_CONFFILE"; ddi_load_lang "${CFG_LANGUAGE:-fr}" ;;
    password)  passwd ;;
    logs)      sudo journalctl -n 300 --no-pager | less ;;
    reboot)    if wt_yesno "$M_CONFIRM_REBOOT"; then sudo systemctl reboot; fi ;;
    shutdown)  if wt_yesno "$M_CONFIRM_SHUTDOWN"; then sudo systemctl poweroff; fi ;;
    shell)     break ;;
  esac
done
''', 0o755)

w("etc/profile.d/ddibuntu-menu.sh", '''# DDI-Buntu : menu console à la connexion interactive d'un administrateur (groupe ddiadmin).
if [ -z "${DDI_MENU_DONE:-}" ] && [ -x /usr/local/bin/ddibuntu-menu ] && [ -t 0 ] && [ -t 1 ]; then
  case " $(id -nG 2>/dev/null) " in
    *" ddiadmin "*) DDI_MENU_DONE=1; export DDI_MENU_DONE; /usr/local/bin/ddibuntu-menu ;;
  esac
fi
''')

w("etc/ssh/sshd_config.d/10-ddibuntu.conf", '''# DDI-Buntu — durcissement SSH. Chargé avant 50-cloud-init.conf : la première valeur l'emporte.
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowGroups ddiadmin
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 4
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
''')

w("etc/sysctl.d/90-ddibuntu.conf", '''# DDI-Buntu — durcissement du noyau et de la pile réseau (l'appliance n'est pas un routeur).
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
''')

w("etc/nftables.conf", '''#!/usr/sbin/nft -f
# DDI-Buntu : le pare-feu vit dans une table dédiée (inet ddibuntu), générée par ddibuntu-fw.
# Pas de « flush ruleset » : les tables des autres composants ne sont jamais effacées.
include "/etc/ddibuntu/nftables.nft"
''')

w("etc/cloud/cloud.cfg.d/99-ddibuntu.cfg", '''# DDI-Buntu : le réseau est géré par ddibuntu-apply, pas par cloud-init.
network: {config: disabled}
''')

w("etc/systemd/system/ddibuntu-firstboot.service", '''[Unit]
Description=DDI-Buntu first-boot setup wizard
ConditionPathExists=!/var/lib/ddibuntu/configured
After=systemd-user-sessions.service plymouth-quit-wait.service
Before=getty@tty1.service getty.target

[Service]
Type=oneshot
Environment=TERM=linux
ExecStart=/usr/local/sbin/ddibuntu-setup --first-boot
StandardInput=tty-force
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
RemainAfterExit=yes
TimeoutStartSec=infinity

[Install]
WantedBy=multi-user.target
''')

print("fichiers écrits")
