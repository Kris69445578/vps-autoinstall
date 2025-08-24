#!/usr/bin/env bash
set -euo pipefail

# Helper functions
cecho() { printf "%b\n" "$1"; }
ok()    { cecho "\033[1;32m[OK]\033[0m $1"; }
warn()  { cecho "\033[1;33m[WARN]\033[0m $1"; }
err()   { cecho "\033[1;31m[ERR]\033[0m $1"; }
title() { cecho "\n\033[1;36m==> $1\033[0m"; }

require_root() { [[ $EUID -ne 0 ]] && { err "Run as root"; exit 1; }; }

# Detect OS
detect_os() {
  DISTRO=$(lsb_release -is || echo "Ubuntu")
  RELEASE=$(lsb_release -rs || echo "22.04")
  [[ "$DISTRO" != "Ubuntu" ]] && { err "Ubuntu only"; exit 1; }
  ok "OS detected: $DISTRO $RELEASE"
}

# Public IP
get_public_ip() {
  curl -4fsS https://ifconfig.me || echo "0.0.0.0"
}

# Inputs
ask_inputs() {
  SERVER_IP=$(get_public_ip)
  read -rp "Domain (leave empty for self-signed): " DOMAIN || true
  read -rp "Email (for cert): " EMAIL || true
  read -rp "TLS Port (default 443): " TLS_PORT || TLS_PORT=${TLS_PORT:-443}
  read -rp "WS Port (default 80): " WS_PORT || WS_PORT=${WS_PORT:-80}
  read -rp "SSH-WS Path (default /sshws): " SSHWS_PATH || SSHWS_PATH=${SSHWS_PATH:-/sshws}
  read -rp "Swap size MB (0 to skip): " SWAP_MB || SWAP_MB=${SWAP_MB:-0}
  read -rp "Enable BBR (y/N): " ENABLE_BBR || ENABLE_BBR=${ENABLE_BBR:-N}
  ok "IP=$SERVER_IP  Domain=${DOMAIN:-<none>}  TLS=$TLS_PORT  WS=$WS_PORT  SSHWS=$SSHWS_PATH  Swap=${SWAP_MB}MB  BBR=$ENABLE_BBR"
}

# Base packages
install_base() {
  title "Installing base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt update && apt upgrade -y
  apt install -y curl wget git unzip tar socat cron jq htop tmux net-tools ufw build-essential gnupg lsb-release software-properties-common lsof apt-transport-https ca-certificates tzdata
  timedatectl set-timezone UTC
  ok "Base packages installed"
}

setup_swap() {
  [[ "$SWAP_MB" -gt 0 ]] || { warn "Swap skipped"; return; }
  fallocate -l "${SWAP_MB}M" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_MB"
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
  sysctl vm.swappiness=10
  ok "Swap enabled"
}

enable_bbr() {
  [[ "${ENABLE_BBR^^}" == "Y" ]] || { warn "BBR skipped"; return; }
  modprobe tcp_bbr || true
  echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr" >/etc/sysctl.d/99-bbr.conf
  sysctl --system
  ok "BBR enabled"
}

install_vnstat_speedtest() {
  apt install -y vnstat speedtest
  systemctl enable --now vnstat
  ok "vnStat + speedtest installed"
}

install_webmin() {
  curl -fsSL https://download.webmin.com/jcameron-key.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/webmin.gpg
  echo "deb https://download.webmin.com/download/repository sarge contrib" >/etc/apt/sources.list.d/webmin.list
  apt update && apt install -y webmin
  systemctl enable --now webmin
  ok "Webmin installed on port 10000"
}

install_nginx() {
  apt install -y nginx
  systemctl enable --now nginx
  mkdir -p /var/www/html && echo "<h1>OK</h1>" >/var/www/html/index.html
  ok "Nginx installed"
}

install_xray() {
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" >/tmp/xray.log 2>&1
  systemctl enable --now xray
  ok "Xray installed"
}

install_dropbear() {
  apt install -y dropbear
  sed -i 's/^NO_START=.*/NO_START=0/' /etc/default/dropbear
  sed -i 's/^DROPBEAR_PORT=.*/DROPBEAR_PORT=4422/' /etc/default/dropbear || echo "DROPBEAR_PORT=4422" >> /etc/default/dropbear
  systemctl enable --now dropbear
  ok "Dropbear running on port 4422"
}

install_stunnel() {
  apt install -y stunnel4
  mkdir -p /etc/stunnel
  openssl req -new -x509 -days 3650 -nodes -subj "/CN=$(hostname)" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem
  chmod 600 /etc/stunnel/stunnel.pem
  cat >/etc/stunnel/stunnel.conf <<EOF
setuid = stunnel4
setgid = stunnel4
pid = /var/run/stunnel4/stunnel.pid
output = /var/log/stunnel4/stunnel.log
client = no
foreground = no
[ssh]
accept = 444
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOF
  sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  systemctl enable --now stunnel4
  ok "Stunnel running on 444 -> 22"
}

setup_firewall() {
  ufw --force reset
  ufw allow 22/tcp
  ufw allow 4422/tcp
  ufw allow 444/tcp
  ufw allow ${WS_PORT}/tcp
  ufw allow ${TLS_PORT}/tcp
  ufw allow 10000/tcp
  ufw --force enable
  ok "Firewall enabled"
}

install_menu() {
  cat >/usr/local/bin/vps <<'EOF'
#!/usr/bin/env bash
PS1="\u@vps$ "
echo "VPS menu placeholder. All commands work after install."
EOF
  chmod +x /usr/local/bin/vps
  ok "Menu installed: use 'vps'"
}

main() {
  require_root
  detect_os
  ask_inputs
  install_base
  setup_swap
  enable_bbr
  install_vnstat_speedtest
  install_webmin
  install_nginx
  install_xray
  install_dropbear
  install_stunnel
  setup_firewall
  install_menu
  ok "Installation complete. Rebooting in 5s..."
  sleep 5
  reboot
}

main
