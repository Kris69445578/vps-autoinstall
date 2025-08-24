curl -fsSL https://raw.githubusercontent.com/anyplaceholder/code-drops/main/ubuntu-vps-autoinstall.sh -o ubuntu-vps-autoinstall.sh || cat > ubuntu-vps-autoinstall.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  Ubuntu 20.04 / 22.04 VPS One-Click Installer
#  Services: Nginx, Xray (VMESS/VLESS/Trojan/SS), SSH over WebSocket, Dropbear,
#            Stunnel4, vnStat, speedtest-cli, Webmin, acme.sh (TLS), BBR, Swap
#  Menu command: vps
#  Version: 3.0  (Last Update)
# =============================================================================

# ----------- Helper -----------
cecho() { printf "%b\n" "$1"; }
ok()    { cecho "\033[1;32m[OK]\033[0m $1"; }
warn()  { cecho "\033[1;33m[WARN]\033[0m $1"; }
err()   { cecho "\033[1;31m[ERR]\033[0m $1"; }
title() { cecho "\n\033[1;36m==> $1\033[0m"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then err "Run as root (sudo -i)"; exit 1; fi
}

detect_os() {
  if ! command -v lsb_release >/dev/null 2>&1; then apt-get update -y && apt-get install -y lsb-release; fi
  DISTRO=$(lsb_release -is || echo "Ubuntu")
  CODENAME=$(lsb_release -cs || echo "focal")
  RELEASE=$(lsb_release -rs || echo "20.04")
  if [[ "$DISTRO" != "Ubuntu" ]]; then err "This script supports Ubuntu only."; exit 1; fi
  if [[ "$RELEASE" != "20.04" && "$RELEASE" != "22.04" ]]; then
    warn "Detected Ubuntu $RELEASE. Proceeding (tested on 20.04/22.04)."
  fi
  ok "OS: $DISTRO $RELEASE ($CODENAME)"
}

get_public_ip() {
  curl -4fsS --max-time 5 https://ifconfig.me || curl -4fsS --max-time 5 https://ipinfo.io/ip || curl -4fsS --max-time 5 https://api.ipify.org || echo "0.0.0.0"
}

# ----------- Ask (non-blocking defaults) -----------
ask_inputs() {
  title "Basic Settings"
  SERVER_IP=${SERVER_IP:-"$(get_public_ip)"}
  read -rp " Domain (leave empty to use self-signed): " DOMAIN || true
  read -rp " Email for cert (optional, used by acme.sh): " EMAIL || true

  # Ports
  read -rp " TLS Port for Xray (default 443): " TLS_PORT || true
  TLS_PORT=${TLS_PORT:-443}
  read -rp " WS (non-TLS) Port (default 80): " WS_PORT || true
  WS_PORT=${WS_PORT:-80}
  read -rp " SSH-WS path (default /sshws): " SSHWS_PATH || true
  SSHWS_PATH=${SSHWS_PATH:-/sshws}

  # Optional features
  read -rp " Create swap? size in MB (0 to skip, e.g. 1024): " SWAP_MB || true
  SWAP_MB=${SWAP_MB:-0}
  read -rp " Enable BBR (y/N): " ENABLE_BBR || true
  ENABLE_BBR=${ENABLE_BBR:-N}

  ok "IP=$SERVER_IP  DOMAIN=${DOMAIN:-<none>}  TLS_PORT=$TLS_PORT  WS_PORT=$WS_PORT  SSHWS_PATH=$SSHWS_PATH  SWAP=${SWAP_MB}MB  BBR=$ENABLE_BBR"
}

# ----------- Base setup -----------
install_base() {
  title "Installing base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y \
    curl wget git unzip tar socat cron jq coreutils htop tmux net-tools ufw \
    build-essential software-properties-common ca-certificates gnupg lsof \
    lsb-release apt-transport-https
  ok "Base packages installed"

  title "Time & locale"
  apt-get install -y tzdata
  timedatectl set-timezone UTC || true
  ok "Timezone set to UTC (change with: timedatectl set-timezone Europe/Berlin)"
}

setup_swap() {
  if [[ "$SWAP_MB" -gt 0 ]]; then
    title "Configuring swap (${SWAP_MB}MB)"
    if ! swapon --show | grep -q "/swapfile"; then
      fallocate -l "${SWAP_MB}M" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_MB"
      chmod 600 /swapfile
      mkswap /swapfile
      swapon /swapfile
      echo "/swapfile none swap sw 0 0" >> /etc/fstab
      sysctl vm.swappiness=10
      echo "vm.swappiness=10" >/etc/sysctl.d/99-swap.conf
      ok "Swap enabled"
    else
      warn "Swap already present, skipping"
    fi
  else
    warn "Swap skipped"
  fi
}

enable_bbr() {
  if [[ "${ENABLE_BBR^^}" == "Y" ]]; then
    title "Enabling BBR"
    modprobe tcp_bbr || true
    echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
    sysctl --system
    ok "BBR enabled (verify: sysctl net.ipv4.tcp_congestion_control)"
  else
    warn "BBR skipped"
  fi
}

# ----------- Monitoring tools -----------
install_vnstat_speedtest() {
  title "Installing vnStat & speedtest-cli"
  apt-get install -y vnstat
  systemctl enable --now vnstat
  # Official Ookla speedtest
  if ! command -v speedtest >/dev/null 2>&1; then
    curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
    apt-get install -y speedtest
  fi
  ok "vnStat + speedtest ready"
}

# ----------- Webmin -----------
install_webmin() {
  title "Installing Webmin"
  curl -fsSL https://download.webmin.com/jcameron-key.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/webmin.gpg
  echo "deb https://download.webmin.com/download/repository sarge contrib" >/etc/apt/sources.list.d/webmin.list
  apt-get update -y
  apt-get install -y webmin
  systemctl enable --now webmin
  ok "Webmin installed (default port 10000)"
}

# ----------- Nginx -----------
install_nginx() {
  title "Installing Nginx"
  apt-get install -y nginx
  systemctl enable --now nginx
  # Minimal site; reverse proxy for WS paths will be added after TLS decision.
  mkdir -p /var/www/html
  echo "<h1>OK</h1>" >/var/www/html/index.html
  ok "Nginx installed"
}

# ----------- acme.sh (TLS) -----------
install_acme_issue_cert() {
  if [[ -z "${DOMAIN:-}" ]]; then
    warn "No domain provided — will use self-signed for Xray TLS."
    return 0
  fi
  title "Installing acme.sh and issuing certificate for ${DOMAIN}"
  curl -fsSL https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}"
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  # Stop Nginx temporarily for standalone validation
  systemctl stop nginx || true
  ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 --force
  mkdir -p /etc/ssl/xray
  ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --ecc \
    --key-file       /etc/ssl/xray/privkey.pem \
    --fullchain-file /etc/ssl/xray/fullchain.pem \
    --reloadcmd     "systemctl reload nginx || true; systemctl reload xray || true"
  systemctl start nginx || true
  ok "Certificate obtained & installed"
}

# ----------- Xray (core) -----------
install_xray() {
  title "Installing Xray-core"
  bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/tmp/xray-install.log 2>&1
  systemctl stop xray || true
  mkdir -p /etc/xray /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log
  ok "Xray installed"
}

# Generate random UUIDs and passwords
generate_ids() {
  VMESS_ID=$(cat /proc/sys/kernel/random/uuid)
  VLESS_ID=$(cat /proc/sys/kernel/random/uuid)
  TROJAN_PW=$(openssl rand -hex 16)
  SS_PW=$(openssl rand -hex 16)
  SS_METHOD="chacha20-ietf-poly1305"
}

# Xray config supporting: VMESS+WS, VLESS+WS, Trojan+TLS, Shadowsocks+2022/TLS, SSH over WS->dokodemo to 127.0.0.1:22
write_xray_config() {
  title "Writing Xray config"
  generate_ids

  if [[ -n "${DOMAIN:-}" && -f /etc/ssl/xray/privkey.pem ]]; then
    CERT_KEY="/etc/ssl/xray/privkey.pem"
    CERT_FULL="/etc/ssl/xray/fullchain.pem"
    TLS_ENABLED=true
  else
    # Self-signed
    mkdir -p /etc/ssl/xray
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout /etc/ssl/xray/privkey.pem -out /etc/ssl/xray/fullchain.pem \
      -days 3650 -subj "/CN=$(hostname)"
    CERT_KEY="/etc/ssl/xray/privkey.pem"
    CERT_FULL="/etc/ssl/xray/fullchain.pem"
    TLS_ENABLED=false
  fi

  cat >/etc/xray/config.json <<JSON
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "vmess-ws",
      "port": ${WS_PORT},
      "listen": "0.0.0.0",
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "${VMESS_ID}", "alterId": 0 } ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "vless-ws",
      "port": ${WS_PORT},
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": { "clients": [ { "id": "${VLESS_ID}" } ], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } }
    },
    {
      "tag": "ssh-ws",
      "port": ${WS_PORT},
      "listen": "0.0.0.0",
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": 22, "network": "tcp", "followRedirect": false },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "${SSHWS_PATH}" } }
    },
    {
      "tag": "trojan-tls",
      "port": ${TLS_PORT},
      "listen": "0.0.0.0",
      "protocol": "trojan",
      "settings": { "clients": [ { "password": "${TROJAN_PW}" } ] },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": { "alpn": ["h2","http/1.1"], "certificates": [ { "certificateFile": "${CERT_FULL}", "keyFile": "${CERT_KEY}" } ] }
      }
    },
    {
      "tag": "ss-tls",
      "port": ${TLS_PORT},
      "listen": "0.0.0.0",
      "protocol": "shadowsocks",
      "settings": { "clients": [ { "method": "${SS_METHOD}", "password": "${SS_PW}" } ], "network": "tcp,udp" },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": { "alpn": ["http/1.1"], "certificates": [ { "certificateFile": "${CERT_FULL}", "keyFile": "${CERT_KEY}" } ] }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "blocked" } ]
}
JSON

  systemctl enable --now xray
  systemctl restart xray
  ok "Xray configured"

  # Save client info
  mkdir -p /etc/vpspanel
  cat >/etc/vpspanel/clients.txt <<INFO
# ======== XRAY CLIENTS ========
VMESS (WS): id=${VMESS_ID}, ws path=/vmess, host=${DOMAIN:-$SERVER_IP}, port=${WS_PORT}, tls=no
VLESS (WS): id=${VLESS_ID}, ws path=/vless, host=${DOMAIN:-$SERVER_IP}, port=${WS_PORT}, tls=no
TROJAN (TLS): password=${TROJAN_PW}, host=${DOMAIN:-$SERVER_IP}, port=${TLS_PORT}, tls=yes
SHADOWSOCKS (TLS): method=${SS_METHOD}, password=${SS_PW}, host=${DOMAIN:-$SERVER_IP}, port=${TLS_PORT}, tls=yes
SSH over WS: ws path=${SSHWS_PATH}, host=${DOMAIN:-$SERVER_IP}, port=${WS_PORT}
INFO
}

# ----------- Dropbear -----------
install_dropbear() {
  title "Installing Dropbear"
  apt-get install -y dropbear
  sed -i 's/^NO_START=.*$/NO_START=0/' /etc/default/dropbear || true
  sed -i 's/^DROPBEAR_PORT=.*$/DROPBEAR_PORT=4422/' /etc/default/dropbear || echo "DROPBEAR_PORT=4422" >> /etc/default/dropbear
  systemctl enable --now dropbear
  ok "Dropbear on port 4422"
}

# ----------- Stunnel4 -----------
install_stunnel() {
  title "Installing Stunnel4"
  apt-get install -y stunnel4
  mkdir -p /etc/stunnel
  openssl req -new -x509 -days 3650 -nodes -subj "/CN=$(hostname)" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem
  chmod 600 /etc/stunnel/stunnel.pem
  cat >/etc/stunnel/stunnel.conf <<CONF
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
CONF
  sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  systemctl enable --now stunnel4
  ok "Stunnel on 444 -> 22"
}

# ----------- Nginx reverse proxy for WS paths -----------
configure_nginx() {
  title "Configuring Nginx"
  cat >/etc/nginx/sites-available/vpspanel.conf <<NGX
server {
    listen ${WS_PORT};
    server_name ${DOMAIN:-_};
    location / {
        root /var/www/html;
        index index.html;
    }
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
    location ${SSHWS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
NGX
  ln -sf /etc/nginx/sites-available/vpspanel.conf /etc/nginx/sites-enabled/vpspanel.conf
  nginx -t
  systemctl reload nginx
  ok "Nginx reverse proxy ready"
}

# ----------- Firewall -----------
setup_firewall() {
  title "Configuring UFW"
  ufw allow 22/tcp
  ufw allow 4422/tcp   # Dropbear
  ufw allow 444/tcp    # Stunnel
  ufw allow ${WS_PORT}/tcp
  ufw allow ${TLS_PORT}/tcp
  ufw allow 10000/tcp  # Webmin
  ufw --force enable
  ok "Firewall enabled"
}

# ----------- Menu -----------
install_menu() {
  title "Installing menu command (vps)"
  cat >/usr/local/bin/vps <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

draw_line() { printf "%s\n" "┌────────────────────────────────────────────────────────────┐"; }
draw_line2(){ printf "%s\n" "└────────────────────────────────────────────────────────────┘"; }

val_or() { [[ -n "${1:-}" ]] && echo "$1" || echo "$2"; }

OS=$(lsb_release -d | awk -F"\t" '{print $2}')
KERNEL=$(uname -r)
CPU_NAME=$(lscpu | awk -F: '/Model name/ {sub(/^[ \t]+/, "", $2); print $2; exit}')
CPU_INFO=$(lscpu | awk -F: '/^CPU\(s\)/ {sub(/^[ \t]+/, "", $2); print $2; exit}')
TOTAL_RAM=$(free -h --si | awk '/Mem:/ {print $2}')
UPTIME=$(uptime -p)
DOMAIN=$(hostname -f 2>/dev/null || hostname)
IPVPS=$(curl -s https://ifconfig.me || echo "0.0.0.0")

if command -v vnstat >/dev/null 2>&1; then
  DAILY_BW=$(vnstat --oneline | awk -F\; '{print $11}')
  TOTAL_BW=$(vnstat --oneline | awk -F\; '{print $10}')
else
  DAILY_BW="-"; TOTAL_BW="-"
fi

is_on() { systemctl is-active --quiet "$1" && echo "ON" || echo "OFF"; }

SSH_STATUS=$(is_on ssh)
NGINX_STATUS=$(is_on nginx)
XRAY_STATUS=$(is_on xray)
TROJAN_STATUS=$(is_on xray)     # trojan via xray inbound
DROPBEAR_STATUS=$(is_on dropbear)
SSHWS_STATUS=$(is_on xray)      # via xray+nginx
STUNNEL_STATUS=$(is_on stunnel4)

clear
draw_line
printf " │                  Server Informations\n │\n"
printf " │  OS Linux        : %s\n" "$OS"
printf " │  Kernel          : %s\n" "$KERNEL"
printf " │  CPU Name        : %s\n" "$CPU_NAME"
printf " │  CPU Info        : %s Cores\n" "$CPU_INFO"
printf " │  Total RAM       : %s\n" "$TOTAL_RAM"
printf " │  System Uptime   : %s\n" "$UPTIME"
printf " │  Current Domain  : %s\n" "$DOMAIN"
printf " │  IP-VPS          : %s\n" "$IPVPS"
printf " │  Daily Bandwidth : %s\n" "$DAILY_BW"
printf " │  Total Bandwidth : %s\n" "$TOTAL_BW"
draw_line2
printf "      SSH : %s  NGINX : %s   XRAY : %s  TROJAN : %s\n" "$SSH_STATUS" "$NGINX_STATUS" "$XRAY_STATUS" "$TROJAN_STATUS"
printf "      DROPBEAR : %s  SSH-WS : %s  Stunnel : %s\n" "$DROPBEAR_STATUS" "$SSHWS_STATUS" "$STUNNEL_STATUS"

draw_line
cat <<'MENU'
     [01] SSHWS       [0]
     [02] VMESS       [0]
     [03] VLESS       [0]
     [04] TROJAN      [0]
     [05] SHADOWSOCKS [0]
     [06] EXP FILES
     [07] AUTO REBOOT
     [08] REBOOT
     [09] RESTART (nginx + xray)
     [11] ADD HOST/DOMAIN (info only)
     [12] RENEW CERT (acme.sh)
     [13] EDIT BANNER (/etc/issue)
     [14] RUNNING STATUS (systemctl)
     [15] USER BANDWIDTH (vnstat)
     [16] SPEEDTEST
     [17] CHECK BANDWIDTH (vnstat top)
     [18] LIMIT SPEED (tc qdisc)
     [19] WEBMIN (open port 10000)
     [20] INFO SCRIPT
     [21] CLEAR LOG
     [22] TASK MANAGER (htop)
     [23] DNS CHANGER (systemd-resolved)
     [24] NETFLIX CHECKER (curl)
     [25] TENDANG (kick SSH sessions)
     [55] XRAY-CORE MENU (show clients)
     [66] INSTALL BBRPLUS (already handled)
     [77] SWAPRAM MENU (info)
     [88] BACKUP (/etc/xray)
     [99] RESTORE (/etc/xray)
     [x ] EXIT
MENU
draw_line2
printf "┌─────────────────────────────────────┐\n │  Version       : 3.0 Last Update\n└─────────────────────────────────────┘\n"

read -rp " Select menu option: " opt
case "$opt" in
  07) echo "0 4 * * * /sbin/reboot" | crontab - ; echo "Auto reboot daily 04:00 set."; sleep 2;;
  08) reboot;;
  09) systemctl restart nginx xray; echo "Services restarted."; sleep 2;;
  12) if [[ -x "$HOME/.acme.sh/acme.sh" ]]; then "$HOME/.acme.sh/acme.sh" --renew -d "$(hostname -f 2>/dev/null || hostname)" --ecc --force; systemctl reload xray nginx; echo "Cert renew attempted."; else echo "acme.sh not installed."; fi; sleep 2;;
  13) ${EDITOR:-nano} /etc/issue;;
  14) systemctl --type=service --state=running | sed -n '1,80p'; read -n1 -r -p "Press any key...";;
  15) vnstat; read -n1 -r -p "Press any key...";;
  16) speedtest; read -n1 -r -p "Press any key...";;
  17) vnstat -t; read -n1 -r -p "Press any key...";;
  18) echo "Example: limit to 20mbit on eth0: tc qdisc add dev eth0 root tbf rate 20mbit burst 32kbit latency 400ms"; read -n1 -r -p "Press any key...";;
  19) echo "Open https://$HOSTNAME:10000/ (allow in firewall)."; sleep 2;;
  20) cat /etc/vpspanel/clients.txt || echo "No client info."; read -n1 -r -p "Press any key...";;
  21) journalctl --vacuum-time=1d; : > /var/log/xray/access.log; : > /var/log/xray/error.log; echo "Logs cleared."; sleep 2;;
  22) htop;;
  23) echo "Set DNS to 1.1.1.1/1.0.0.1 -> resolvectl dns eth0 1.1.1.1 1.0.0.1"; read -n1 -r -p "Press any key...";;
  24) curl -s https://www.netflix.com/title/80018499 -I | head -n 5; read -n1 -r -p "Press any key...";;
  25) pkill -KILL -u $(id -u); echo "Disconnected SSH users (self might drop).";;
  55) cat /etc/vpspanel/clients.txt; read -n1 -r -p "Press any key...";;
  66) echo "BBR configured during install if chosen."; sleep 2;;
  77) swapon --show || echo "No swap."; read -n1 -r -p "Press any key...";;
  88) tar czf /root/xray-backup.tgz /etc/xray && echo "Backup -> /root/xray-backup.tgz";;
  99) if [[ -f /root/xray-backup.tgz ]]; then tar xzf /root/xray-backup.tgz -C /; systemctl restart xray nginx; echo "Restored."; else echo "No backup found."; fi;;
  x|X) exit 0;;
  *) echo "Option not implemented in demo panel."; sleep 2;;
esac
BASH
  chmod +x /usr/local/bin/vps
  ok "Menu installed. Use: vps"
}

# ----------- Final info -----------
print_summary() {
  title "Installation complete"
  echo "Domain     : ${DOMAIN:-<none>}"
  echo "Server IP  : ${SERVER_IP}"
  echo "TLS Port   : ${TLS_PORT}"
  echo "WS Port    : ${WS_PORT}"
  echo "SSH-WS Path: ${SSHWS_PATH}"
  echo "Menu       : vps"
  echo "Webmin     : https://${DOMAIN:-$SERVER_IP}:10000/"
  echo
  echo "Client details saved at /etc/vpspanel/clients.txt"
}

# ==================== MAIN ====================
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
install_acme_issue_cert
write_xray_config
configure_nginx
install_dropbear
install_stunnel
setup_firewall
install_menu
print_summary
exit 0
EOF
bash ubuntu-vps-autoinstall.sh
