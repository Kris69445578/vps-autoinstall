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
  
  # Enable services
  systemctl enable --now cron
  systemctl enable --now nginx
}

# ------------------------ ACME / TLS ------------------------
install_acme() {
  if [[ ! -d "$ACME_HOME" ]]; then
    log "Installing acme.sh..."
    curl -s https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}"
    # Add acme.sh to PATH
    export PATH="$HOME/.acme.sh:$PATH"
  fi
  # Ensure socat exists (for standalone HTTP)
  "$ACME_HOME"/acme.sh --upgrade --auto-upgrade
}

issue_cert() {
  mkdir -p "$CERT_DIR"
  log "Stopping Nginx temporarily to issue a certificate (standalone mode)..."
  systemctl stop nginx || true
  
  # Try standalone mode first
  if "$ACME_HOME"/acme.sh --issue --standalone -d "$DOMAIN" --force; then
    log "Certificate issued successfully using standalone mode"
  else
    warn "Standalone issuance failed. Trying webroot mode via Nginx."
    # configure temporary webroot
    systemctl start nginx
    if "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" -w "$WWW_ROOT" --force; then
      log "Certificate issued successfully using webroot mode"
    else
      die "Certificate issuance failed."
    fi
  fi
  
  # Install certificate
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
  # Download and run the installation script
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  
  # Check if xray is installed correctly
  if [[ ! -f "/usr/local/bin/xray" ]]; then
    err "Xray installation failed. Trying alternative method..."
    
    # Alternative installation method
    apt-get install -y unzip
    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    TEMP_DIR="$(mktemp -d)"
    curl -L -o "$TEMP_DIR/xray.zip" "$DOWNLOAD_URL"
    unzip "$TEMP_DIR/xray.zip" -d "$TEMP_DIR"
    install -m 755 "$TEMP_DIR/xray" /usr/local/bin/
    install -d /usr/local/share/xray/
    install -m 644 "$TEMP_DIR"/*.dat /usr/local/share/xray/
    install -d /etc/xray/
    install -m 644 "$TEMP_DIR/config.json" /etc/xray/
    install -d /var/log/xray/
    
    # Create systemd service
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    rm -rf "$TEMP_DIR"
  fi
  
  systemctl stop xray || true
}

# ------------------------ Config Generation ------------------------
gen_ids() {
  # Check if xray binary exists and is executable
  if [[ -f "/usr/local/bin/xray" ]]; then
    VLESS_ID="$(/usr/local/bin/xray uuid)"
    VMESS_ID="$(/usr/local/bin/xray uuid)"
  else
    # Fallback to OpenSSL if xray is not available
    warn "Xray binary not found, using OpenSSL for UUID generation"
    VLESS_ID="$(openssl rand -hex 16 | awk '{print substr($0,1,8)"-"substr($0,9,4)"-"substr($0,13,4)"-"substr($0,17,4)"-"substr($0,21,12)}')"
    VMESS_ID="$(openssl rand -hex 16 | awk '{print substr($0,1,8)"-"substr($0,9,4)"-"substr($0,13,4)"-"substr($0,17,4)"-"substr($0,21,12)}')"
  fi
  
  TROJAN_PSW="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
  echo "$VLESS_ID" > /etc/xray/.vless_id
  echo "$VMESS_ID" > /etc/xray/.vmess_id
  echo "$TROJAN_PSW" > /etc/xray/.trojan_pw
}

write_xray_config() {
  log "Writing Xray configuration..."
  cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$(cat /etc/xray/.vless_id)",
            "email": "vless@${DOMAIN}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$(cat /etc/xray/.vmess_id)",
            "alterId": 0,
            "email": "vmess@${DOMAIN}"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$(cat /etc/xray/.trojan_pw)",
            "email": "trojan@${DOMAIN}"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/trojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
  
  # Create log directory and set permissions
  mkdir -p /var/log/xray
  chown -R nobody:nogroup /var/log/xray
  chmod -R 755 /var/log/xray
}

write_nginx_config() {
  log "Configuring Nginx reverse proxy..."
  
  # Create nginx config
  cat > "$NGINX_DIR/sites-available/xray.conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root /var/www/html;
    index index.html;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
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
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Block access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/ssl/xray/fullchain.pem;
    ssl_certificate_key /etc/ssl/xray/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
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
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Block access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
  
  # Enable the site
  rm -f "$NGINX_DIR/sites-enabled/default" || true
  ln -sf "$NGINX_DIR/sites-available/xray.conf" "$NGINX_DIR/sites-enabled/xray.conf"
  
  # Create web root
  mkdir -p "$WWW_ROOT"
  echo "OK" > "$WWW_ROOT/index.html"
  chown -R www-data:www-data "$WWW_ROOT"
  
  # Test and reload nginx
  nginx -t && systemctl restart nginx
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
  read -srp "Password: " p
  echo
  read -rp "Valid days (e.g., 30): " d
  id -u "$u" >/dev/null 2>&1 && { echo "User exists."; return; }
  useradd -m -s /bin/bash "$u"
  echo "$u:$p" | chpasswd
  chage -E $(date -d "+$d days" +%F) "$u"
  echo "Created SSH user: $u, expires in $d days."
}

list_ssh_users() {
  echo "SSH Users:"
  awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd
}

del_ssh_user() {
  read -rp "Username to delete: " u
  if id -u "$u" >/dev/null 2>&1; then
    userdel -r "$u" 2>/dev/null && echo "Deleted $u" || echo "Error deleting user $u"
  else
    echo "User $u does not exist."
  fi
}

add_client_generic() {
  local proto="$1" path="$2" key="$3" tag="$4"
  local email uuid pw newitem tmp
  
  read -rp "Client email (label): " email
  if [[ "$proto" == "trojan" ]]; then
    read -rp "Password (leave empty to generate): " pw || true
    [[ -n "${pw:-}" ]] || pw="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    newitem="{\"password\":\"$pw\",\"email\":\"$email\"}"
  else
    if [[ -f "/usr/local/bin/xray" ]]; then
      uuid=$(/usr/local/bin/xray uuid)
    else
      # Fallback to OpenSSL
      uuid=$(openssl rand -hex 16 | awk '{print substr($0,1,8)"-"substr($0,9,4)"-"substr($0,13,4)"-"substr($0,17,4)"-"substr($0,21,12)}')
    fi
    
    if [[ "$proto" == "vmess" ]]; then
      newitem="{\"id\":\"$uuid\",\"alterId\":0,\"email\":\"$email\"}"
    else
      newitem="{\"id\":\"$uuid\",\"email\":\"$email\"}"
    fi
  fi
  
  tmp="$(mktemp)"
  # Use jq to add the new client to the config
  if jq --argjson item "$newitem" --arg proto "$proto" \
    '(.inbounds[] | select(.protocol == $proto) | .settings.clients) += [$item]' \
    "$XRAY_DIR/config.json" > "$tmp"; then
    mv "$tmp" "$XRAY_DIR/config.json"
    systemctl reload xray
    echo
    line
    echo "Client created for $proto:"
    if [[ "$proto" == "trojan" ]]; then
      echo "trojan://$pw@$DOMAIN:443?security=tls&type=ws&path=$path#$email"
      echo
      echo "QR Code:"
      echo "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=trojan://$pw@$DOMAIN:443?security=tls&type=ws&path=$path#$email"
    elif [[ "$proto" == "vmess" ]]; then
      # Build VMess JSON link
      vmess_json=$(jq -n --arg v "$uuid" --arg h "$DOMAIN" --arg p "$path" --arg em "$email" \
        '{v: "2", ps: $em, add: $h, port: "443", id: $v, aid: "0", net: "ws", type: "", host: $h, path: $p, tls: "tls"}')
      vmess_encoded=$(echo "$vmess_json" | base64 -w0)
      echo "vmess://$vmess_encoded"
      echo
      echo "QR Code:"
      echo "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=vmess://$vmess_encoded"
    else
      echo "vless://$uuid@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$path&host=$DOMAIN#$email"
      echo
      echo "QR Code:"
      echo "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=vless://$uuid@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$path&host=$DOMAIN#$email"
    fi
    line
  else
    err "Failed to add client"
    rm -f "$tmp"
  fi
}

show_service_status() {
  echo "Xray status:"
  systemctl is-active xray && systemctl status xray --no-pager --lines=5 || echo "Xray is not running"
  echo
  echo "Nginx status:"
  systemctl is-active nginx && systemctl status nginx --no-pager --lines=5 || echo "Nginx is not running"
}

menu() {
  while true; do
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
    echo "[10] Restart Nginx service"
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
      8|08) show_service_status; pause;;
      9|09) systemctl restart xray; echo "Xray service restarted"; pause;;
      10|10) systemctl restart nginx; echo "Nginx service restarted"; pause;;
      0|00) exit 0;;
      *) echo "Invalid option"; pause;;
    esac
  done
}
menu
EOS
  chmod +x /usr/local/bin/vps-menu
  
  # Create a simple alias for easy access
  echo "alias menu='vps-menu'" >> /root/.bashrc
  source /root/.bashrc
}

# ------------------------ Systemd & Start ------------------------
start_services() {
  log "Starting services..."
  systemctl daemon-reload
  systemctl enable xray
  systemctl start xray
  systemctl restart nginx
  
  # Check if services are running
  if systemctl is-active --quiet xray; then
    log "Xray service started successfully"
  else
    err "Xray service failed to start"
    journalctl -u xray --no-pager -n 10
  fi
  
  if systemctl is-active --quiet nginx; then
    log "Nginx service started successfully"
  else
    err "Nginx service failed to start"
    journalctl -u nginx --no-pager -n 10
  fi
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
