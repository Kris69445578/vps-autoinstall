#!/usr/bin/env bash
# Auto VPS Setup for Ubuntu 22.04
# Features: Xray-core (VLESS/VMess/Trojan over WS+TLS), Nginx, ACME TLS, SSH management, Fail2Ban, and menu utility.
# Run as root: sudo -i && bash auto-vps-setup-ubuntu2204.sh

set -euo pipefail

# ------------------------ Helper Functions ------------------------
log() {
    echo -e "\e[1;32m[+] $(date '+%Y-%m-%d %H:%M:%S') $*\e[0m" | tee -a /var/log/vps-setup.log
}
warn() {
    echo -e "\e[1;33m[!] $(date '+%Y-%m-%d %H:%M:%S') $*\e[0m" | tee -a /var/log/vps-setup.log
}
err() {
    echo -e "\e[1;31m[x] $(date '+%Y-%m-%d %H:%M:%S') $*\e[0m" >&2 | tee -a /var/log/vps-setup.log
}
die() {
    err "$*"
    exit 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Run as root: sudo -i && bash $0"
    fi
}

require_ubuntu_2204() {
    if ! grep -qs "Ubuntu 22.04" /etc/os-release; then
        warn "This script is intended for Ubuntu 22.04. Detected: $(grep PRETTY_NAME /etc/os-release | cut -d '"' -f 2)."
        read -rp "Continue anyway? [y/N]: " ans
        if [[ "${ans,,}" != "y" ]]; then
            die "Aborted."
        fi
    fi
}

cmd_exist() {
    command -v "$1" >/dev/null 2>&1
}

validate_domain() {
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        die "Invalid domain format. Example: example.com"
    fi
    if ! ping -c 1 "$DOMAIN" &>/dev/null; then
        warn "Domain $DOMAIN does not resolve to this server. Proceeding anyway..."
    fi
}

validate_email() {
    if [[ -n "$EMAIL" && ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        warn "Invalid email format. Proceeding without email for ACME."
        EMAIL=""
    fi
}

# ------------------------ Variables ------------------------
XRAY_VER="latest"
XRAY_DIR="/etc/xray"
NGINX_DIR="/etc/nginx"
CERT_DIR="/etc/ssl/xray"
ACME_HOME="/root/.acme.sh"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
WWW_ROOT="/var/www/html"
IPV4="$(curl -4s https://api.ipify.org || echo "127.0.0.1")"

# ------------------------ Interactive Input ------------------------
ask_inputs() {
    echo
    log "Basic configuration"
    while [[ -z "$DOMAIN" ]]; do
        read -rp "Enter your domain pointing to this server (A record): " DOMAIN
    done
    read -rp "Enter your email for Let's Encrypt notices (optional): " EMAIL || true
    validate_domain
    validate_email
    log "Using domain: $DOMAIN"
    log "Detected public IPv4: $IPV4"
}

# ------------------------ Install Base Packages ------------------------
install_base() {
    log "Updating and installing packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get upgrade -y
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates gnupg2 lsb-release apt-transport-https \
        unzip jq socat cron nano ufw nginx fail2ban
    systemctl enable --now cron
    systemctl enable --now nginx
}

# ------------------------ ACME / TLS ------------------------
install_acme() {
    if [[ ! -d "$ACME_HOME" ]]; then
        log "Installing acme.sh..."
        curl -s https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}"
    fi
    "$ACME_HOME/acme.sh" --upgrade --auto-upgrade
}

issue_cert() {
    mkdir -p "$CERT_DIR"
    log "Stopping Nginx temporarily to issue a certificate (standalone mode)..."
    systemctl stop nginx || true
    if ! "$ACME_HOME/acme.sh" --issue --standalone -d "$DOMAIN"; then
        warn "Standalone issuance failed. Trying webroot mode via Nginx."
        systemctl start nginx
        "$ACME_HOME/acme.sh" --issue -d "$DOMAIN" -w "$WWW_ROOT" || die "Certificate issuance failed."
    fi
    "$ACME_HOME/acme.sh" --install-cert -d "$DOMAIN" \
        --fullchain-file "$CERT_DIR/fullchain.pem" \
        --key-file "$CERT_DIR/privkey.pem" \
        --reloadcmd "systemctl reload nginx || true; systemctl reload xray || true"
    chmod 600 "$CERT_DIR/privkey.pem"
    log "TLS certificate installed at $CERT_DIR."
}

# ------------------------ Xray-core ------------------------
install_xray() {
    log "Installing Xray-core..."
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
    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    root $WWW_ROOT;
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
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_stapling on;
    ssl_stapling_verify on;
    root $WWW_ROOT;
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
    rm -f "$NGINX_DIR/sites-enabled/default"
    ln -sf "$NGINX_DIR/sites-available/xray.conf" "$NGINX_DIR/sites-enabled/"
    mkdir -p "$WWW_ROOT"
    echo "OK" > "$WWW_ROOT/index.html"
    nginx -t
    systemctl restart nginx
}

# ------------------------ UFW Firewall ------------------------
setup_firewall() {
    log "Configuring UFW..."
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw allow 443/tcp
    echo "y" | ufw enable
    ufw status verbose
}

# ------------------------ SSH Security ------------------------
setup_ssh() {
    log "Securing SSH..."
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# ------------------------ Fail2Ban ------------------------
setup_fail2ban() {
    log "Setting up Fail2Ban..."
    systemctl enable --now fail2ban
}

# ------------------------ Menu Utilities ------------------------
install_menu() {
    log "Installing management menu..."
    cat > /usr/local/bin/vps-menu <<'EOM'
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
    if id -u "$u" >/dev/null 2>&1; then
        echo "User exists."
        return
    fi
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
    if userdel -r "$u" 2>/dev/null; then
        echo "Deleted $u"
    else
        echo "Error deleting user $u"
    fi
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
    jq --argjson item "$newitem" --arg proto "$proto" \
        '(.inbounds[] | select(.protocol == $proto) | .settings.clients) += [$item]' \
        "$XRAY_DIR/config.json" > "$tmp" && mv "$tmp" "$XRAY_DIR/config.json"
    systemctl reload xray
    echo
    line
    echo "Client created for $proto:"
    if [[ "$proto" == "trojan" ]]; then
        echo "trojan://$pw@$DOMAIN:443?security=tls&type=ws&path=$path#$email"
    elif [[ "$proto" == "vmess" ]]; then
        vmess_json=$(jq -n --arg v "$uuid" --arg h "$DOMAIN" --arg p "$path" \
            '{v: "2", ps: $email, add: $h, port: "443", id: $v, aid: "0", net: "ws", type: "", host: $h, path: $p, tls: "tls"}')
        echo "vmess://$(echo "$vmess_json" | base64 -w0)"
    else
        echo "vless://$uuid@$DOMAIN:443?encryption=none&security=tls&type=ws&path=$path&host=$DOMAIN#$email"
    fi
    line
}
show_base_links() {
    echo "VLESS base: vless://$(cat /etc/xray/.vless_id)@$DOMAIN:443?encryption=none&security=tls&type=ws&path=/vless&host=$DOMAIN#base"
    vmjson=$(jq -n --arg v "$(cat /etc/xray/.vmess_id)" --arg h "$DOMAIN" \
        '{v:"2",ps:"base",add:$h,port:"443",id:$v,aid:"0",net:"ws",type:"",host:$h,path:"/vmess",tls:"tls"}')
    echo "VMESS base: vmess://$(echo "$vmjson" | base64 -w0)"
    echo "TROJAN base: trojan://$(cat /etc/xray/.trojan_pw)@$DOMAIN:443?security=tls&type=ws&path=/trojan#base"
}
show_service_status() {
    systemctl status xray --no-pager
    systemctl status nginx --no-pager
}
restart_xray() {
    systemctl restart xray
    echo "Xray service restarted"
}
backup_configs() {
    log "Backing up configurations..."
    tar -czf "/root/vps-backup-$(date +%F).tar.gz" "$XRAY_DIR" "$NGINX_DIR/sites-available/xray.conf"
    echo "Backup created: /root/vps-backup-$(date +%F).tar.gz"
}
restore_configs() {
    read -rp "Enter backup file path: " backup_file
    if [[ -f "$backup_file" ]]; then
        tar -xzf "$backup_file" -C /
        systemctl restart xray nginx
        echo "Configurations restored from $backup_file"
    else
        err "Backup file not found: $backup_file"
    fi
}
update_system() {
    log "Updating system..."
    apt-get update -y && apt-get upgrade -y
    echo "System updated"
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
    echo "[10] Backup configurations"
    echo "[11] Restore configurations"
    echo "[12] Update system"
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
        7|07) show_base_links; pause;;
        8|08) show_service_status; pause;;
        9|09) restart_xray; pause;;
        10) backup_configs; pause;;
        11) restore_configs; pause;;
        12) update_system; pause;;
        0|00) exit 0;;
        *) echo "Invalid option"; pause;;
    esac
    menu
}
menu
EOM
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
    vmjson=$(jq -n --arg v "$(cat /etc/xray/.vmess_id)" --arg h "$DOMAIN" \
        '{v:"2",ps:"base",add:$h,port:"443",id:$v,aid:"0",net:"ws",type:"",host:$h,path:"/vmess",tls:"tls"}')
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
    setup_ssh
    setup_fail2ban
    start_services
    install_menu
    print_summary
    log "All done. Use 'vps-menu' to manage users."
}

main "$@"
