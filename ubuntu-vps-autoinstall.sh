#!/usr/bin/env bash
# Auto VPS Setup for Ubuntu 22.04
# Features: Xray-core (VLESS/VMess/Trojan over WS+TLS), Nginx reverse proxy, ACME TLS,
# simple SSH account manager, and menu utility.
# Tested on: Ubuntu 22.04 (Jammy)
# Run as root:  bash auto-vps-setup-ubuntu2204.sh
set -euo pipefail

# ------------------------ Helper Functions ------------------------
log() { echo -e "\e[1;32m[+] $*\e[0m"; }
warn() { echo -e "\e[1;33m[!] $*\e[0m"; }
err() { echo -e "\e[1;31m[x] $*\e[0m" >&2; }
die() { err "$*"; exit 1; }

require_root() {
  [[ $EUID -eq 0 ]] || die "Run as root: sudo -i && bash $0"
}

require_ubuntu_2204() {
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
    warn "This script is intended for Ubuntu 22.04. Detected: ${PRETTY_NAME:-unknown}."
    read -rp "Continue anyway? [y/N]: " ans
    [[ "${ans,,}" == "y" ]] || die "Aborted."
  fi
}

cmd_exist() { command -v "$1" >/dev/null 2>&1; }

# ------------------------ Variables ------------------------
XRAY_VER="latest"
XRAY_DIR="/etc/xray"
NGINX_DIR="/etc/nginx"
CERT_DIR="/etc/ssl/xray"
ACME_HOME="/root/.acme.sh"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
WWW_ROOT="/var/www/html"
IPV4="$(curl -4s https://api.ipify.org || true)"

# ------------------------ Interactive Input ------------------------
ask_inputs() {
  echo
  log "Basic configuration"
  if [[ -z "$DOMAIN" ]]; then
    read -rp "Enter your domain pointing to this server (A record): " DOMAIN
  fi
  if [[ -z "$EMAIL" ]]; then
    read -rp "Enter your email for Let's Encrypt notices (optional): " EMAIL || true
  fi
  [[ -n "$DOMAIN" ]] || die "Domain is required for TLS (e.g., example.com)."
  log "Using domain: $DOMAIN"
  if [[ -n "$IPV4" ]]; then
    log "Detected public IPv4: $IPV4"
  fi
}

# ------------------------ Install Base Packages ------------------------
install_base() {
  log "Updating and installing packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y --no-install-recommends \
    curl wget ca-certificates gnupg2 lsb-release apt-transport-https \
    unzip jq socat cron nano ufw nginx
  systemctl enable --now cron
  systemctl enable --now nginx
}

# ------------------------ ACME / TLS ------------------------
install_acme() {
  if [[ ! -d "$ACME_HOME" ]]; then
    log "Installing acme.sh..."
    curl -s https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}"
  fi
  # Ensure socat exists (for standalone HTTP)
  "$ACME_HOME"/acme.sh --upgrade --auto-upgrade
}

issue_cert() {
  mkdir -p "$CERT_DIR"
  log "Stopping Nginx temporarily to issue a certificate (standalone mode)..."
  systemctl stop nginx || true
  "$ACME_HOME"/acme.sh --issue --standalone -d "$DOMAIN" || {
    warn "Standalone issuance failed. Trying webroot mode via Nginx."
    # configure temporary webroot
    systemctl start nginx
    "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" -w "$WWW_ROOT" || die "Certificate issuance failed."
  }
  "$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --key-file "$CERT_DIR/privkey.pem" \
    --reloadcmd "systemctl reload nginx || true; systemctl reload xray || true"
  chmod 600 "$CERT_DIR/privkey.pem"
  log "TLS certificate installed at $CERT_DIR."
}

# ------------------------ Xray-core ------------------------
install_xray() {
  log "Installing Xray-core (${XRAY_VER})..."
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  systemctl stop xray || true
}

# ------------------------ Config Generation ------------------------
gen_ids() {
  VLESS_ID="$(/usr/local/bin/xray uuid)"
  VMESS_ID="$(/usr/local/bin/xray uuid)"
  TROJAN_PSW="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
  echo "$VLESS_ID" > /etc/xray/.vless_id
  echo "$VMESS_ID" > /etc/xray/.vmess_id
  echo "$TROJAN_PSW" > /etc/xray/.trojan_pw
}

write_xray_config() {
  log "Writing Xray configuration..."
  cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$(cat /etc/xray/.vless_id)", "email": "vless@${DOMAIN}" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": [ { "id": "$(cat /etc/xray/.vmess_id)", "alterId": 0, "email": "vmess@${DOMAIN}" } ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/vmess" }
      }
    },
    {
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": [ { "password": "$(cat /etc/xray/.trojan_pw)", "email": "trojan@${DOMAIN}" } ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/trojan" }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" }, { "protocol": "blackhole", "tag": "blocked" } ]
}
EOF
}

write_nginx_config() {
  log "Configuring Nginx reverse proxy..."
  cat > "$NGINX_DIR/sites-available/xray.conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root /var/www/html;
    index index.html;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/ssl/xray/fullchain.pem;
    ssl_certificate_key /etc/ssl/xray/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    root /var/www/html;
    index index.html;
    location / { try_files \$uri \$uri/ =404; }
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
  rm -f "$NGINX_DIR/sites-enabled/default" || true
  ln -sf "$NGINX_DIR/sites-available/xray.conf" "$NGINX_DIR/sites-enabled/xray.conf"
  mkdir -p "$WWW_ROOT"
  echo "OK" > "$WWW_ROOT/index.html"
  nginx -t
  systemctl restart nginx
}

# ------------------------ UFW Firewall ------------------------
setup_firewall() {
  log "Configuring UFW..."
  ufw allow OpenSSH || true
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  echo "y" | ufw enable || true
  ufw status verbose || true
}

# ------------------------ Menu Utilities ------------------------
install_menu() {
  log "Installing management menu..."
  cat > /usr/local/bin/vps-menu <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
XRAY_DIR="/etc/xray"
DOMAIN="$(grep -m1 server_name /etc/nginx/sites-available/xray.conf | awk '{print $2}' | tr -d ';')"

line() { printf "%s\n" "------------------------------------------------------------"; }
pause() { read -rp "Press Enter to continue..."; }

add_ssh_user() {
  read -rp "Username: " u
  read -rp "Password: " p
  read -rp "Valid days (e.g., 30): " d
  id -u "$u" >/dev/null 2>&1 && { echo "User exists."; return; }
  useradd -m -s /bin/bash "$u"
  echo "$u:$p" | chpasswd
  chage -E $(date -d "+$d days" +%F) "$u"
  echo "Created SSH user: $u, expires in $d days."
}

list_ssh_users() {
  awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd
}

del_ssh_user() {
  read -rp "Username to delete: " u
  userdel -r "$u" 2>/dev/null && echo "Deleted $u" || echo "Error deleting user $u"
}

add_client_generic() {
  local proto="$1" path="$2" key="$3" tag="$4"
  local email idfield pwfield newitem
  read -rp "Client email (label): " email
  if [[ "$proto" == "trojan" ]]; then
    read -rp "Password (leave empty to generate): " pw || true
    [[ -n "${pw:-}" ]] || pw="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    newitem="{\"password\":\"$pw\",\"email\":\"$email\"}"
  else
    local uuid
    uuid=$(/usr/local/bin/xray uuid)
    if [[ "$proto" == "vmess" ]]; then
      newitem="{\"id\":\"$uuid\",\"alterId\":0,\"email\":\"$email\"}"
    else
      newitem="{\"id\":\"$uuid\",\"email\":\"$email\"}"
    fi
  fi
  tmp="$(mktemp)"
  # Use jq to add the new client to the config
  jq --argjson item "$newitem" --arg proto "$proto" \
    '(.inbounds[] | select(.protocol == $proto) | .settings.clients) += [$item]' \
    "$XRAY_DIR/config.json" > "$tmp"
  
  if [ $? -eq 0 ]; then
    mv "$tmp" "$XRAY_DIR/config.json"
    systemctl reload xray
    echo
    line
    echo "Client created for $proto:"
    if [[ "$proto" == "trojan" ]]; then
      echo "trojan://$pw@$DOMAIN:443?security=tls&type=ws&path=$path#$email"
    elif [[ "$proto" == "vmess" ]]; then
      # Build VMess JSON link
      vmess_json=$(jq -n --arg v "$uuid" --arg h "$DOMAIN" --arg p "$path" \
        '{v: "2", ps: $email, add: $h, port: "443", id: $v, aid: "0", net: "ws", type: "", host: $h, path: $p, tls: "tls"}')
      echo "vmess://$(echo "$vmess_json" | base64 -w0)"
    else
      echo "vless://$uuid@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$path&host=$DOMAIN#$email"
    fi
    line
  else
    err "Failed to add client"
    rm -f "$tmp"
  fi
}

menu() {
  clear
  echo
  echo "==================== VPS Management Menu ===================="
  echo "Domain: $DOMAIN"
  line
  echo "[01] Add SSH user"
  echo "[02] List SSH users"
  echo "[03] Delete SSH user"
  echo "[04] Add VLESS client"
  echo "[05] Add VMESS client"
  echo "[06] Add TROJAN client"
  echo "[07] Show base links"
  echo "[08] Show service status"
  echo "[09] Restart Xray service"
  echo "[00] Exit"
  line
  read -rp "Select menu: " ans
  case "$ans" in
    1|01) add_ssh_user; pause;;
    2|02) list_ssh_users; pause;;
    3|03) del_ssh_user; pause;;
    4|04) add_client_generic "vless" "/vless" "id" "VLESS"; pause;;
    5|05) add_client_generic "vmess" "/vmess" "id" "VMESS"; pause;;
    6|06) add_client_generic "trojan" "/trojan" "password" "TROJAN"; pause;;
    7|07)
      echo "VLESS base: vless://$(cat /etc/xray/.vless_id)@$DOMAIN:443?encryption=none&security=tls&type=ws&path=/vless&host=$DOMAIN#base"
      vmjson=$(jq -n --arg v "$(cat /etc/xray/.vmess_id)" --arg h "$DOMAIN" '{v:"2",ps:"base",add:$h,port:"443",id:$v,aid:"0",net:"ws",type:"",host:$h,path:"/vmess",tls:"tls"}')
      echo "VMESS base: vmess://$(echo "$vmjson" | base64 -w0)"
      echo "TROJAN base: trojan://$(cat /etc/xray/.trojan_pw)@$DOMAIN:443?security=tls&type=ws&path=/trojan#base"
      pause;;
    8|08) systemctl status xray --no-pager; systemctl status nginx --no-pager; pause;;
    9|09) systemctl restart xray; echo "Xray service restarted"; pause;;
    0|00) exit 0;;
    *) echo "Invalid option"; pause;;
  esac
  menu
}
menu
EOS
  chmod +x /usr/local/bin/vps-menu
}

# ------------------------ Systemd & Start ------------------------
start_services() {
  log "Starting services..."
  systemctl daemon-reload
  systemctl enable --now xray
  systemctl restart nginx
}

# ------------------------ Summary ------------------------
print_summary() {
  echo
  echo "============================================================"
  echo " Setup complete"
  echo "------------------------------------------------------------"
  echo " Domain        : $DOMAIN"
  echo " Web root      : $WWW_ROOT"
  echo " Cert path     : $CERT_DIR"
  echo " Xray config   : $XRAY_DIR/config.json"
  echo " Menu utility  : vps-menu"
  echo "------------------------------------------------------------"
  echo " Base clients:"
  echo "  - VLESS : vless://$(cat /etc/xray/.vless_id)@$DOMAIN:443?encryption=none&security=tls&type=ws&path=/vless&host=$DOMAIN#base"
  vmjson=$(jq -n --arg v "$(cat /etc/xray/.vmess_id)" --arg h "$DOMAIN" '{v:"2",ps:"base",add:$h,port:"443",id:$v,aid:"0",net:"ws",type:"",host:$h,path:"/vmess",tls:"tls"}')
  echo "  - VMESS : vmess://$(echo "$vmjson" | base64 -w0)"
  echo "  - TROJAN: trojan://$(cat /etc/xray/.trojan_pw)@$DOMAIN:443?security=tls&type=ws&path=/trojan#base"
  echo "============================================================"
}

# ------------------------ Main ------------------------
main() {
  require_root
  require_ubuntu_2204
  ask_inputs
  install_base
  install_acme
  issue_cert
  install_xray
  gen_ids
  write_xray_config
  write_nginx_config
  setup_firewall
  start_services
  install_menu
  print_summary
  log "All done. Use 'vps-menu' to manage users."
}
main "$@"
