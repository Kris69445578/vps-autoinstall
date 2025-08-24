#!/bin/bash

# SakuraV3 AutoScript for Ubuntu 22.04
# By Heru Tambunan

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script information
VERSION="Limited Edition 2023"
LICENSE_KEY="288KN-FFKG3-YWMV4-J3DY2-PFSHF"
USERNAME="ANTONY"

# System information
get_system_info() {
    SERVER_UPTIME=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") printf "%s hours, %s minutes", 0, $6; else printf "%s hours, %s minutes", $6, $7}')
    CURRENT_TIME=$(date +"%d-%m-%Y | %I:%M:%S %p")
    OS_INFO=$(lsb_release -ds)
    ARCH=$(uname -m)
    CURRENT_DOMAIN=$(hostname)
    TOTAL_RAM=$(free -m | awk '/Mem:/ {printf "%.0f MB", $2}')
    USED_RAM=$(free -m | awk '/Mem:/ {printf "%.0f MB", $3}')
    FREE_RAM=$(free -m | awk '/Mem:/ {printf "%.0f MB", $4}')
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{printf "%.0f %%", 100 - $1}')
}

# Display header information
display_header() {
    clear
    echo -e "${GREEN}# INFORMATION VPS${NC}"
    echo "Server Uptime    = $SERVER_UPTIME"
    echo "Current Time    = $CURRENT_TIME"
    echo "Operating System    = $OS_INFO ( $ARCH )"
    echo "Current Domain    = $CURRENT_DOMAIN"
    echo "MS Domain    ="
    echo "Total Ram    = $TOTAL_RAM"
    echo "Total Used Ram    = $USED_RAM"
    echo "Total Free Ram    = $FREE_RAM"
    echo "CPU Usage    = $CPU_USAGE"
    echo "Time Reboot VPS    = 00:00 ( Midnight )"
    echo ""
    echo -e "${GREEN}# SAKURAV3_TUNELING${NC}"
    echo "Use Core    : Xray-Core 2023"
    echo "IP-VPS    : $(curl -s ifconfig.me)"
    echo ""
    echo -e "${YELLOW}TERIMA KASIH SUDAH MENGGUNAKAN AUTOSCRIPT SAKURAV3${NC}"
    echo ""
    echo "| SSH   | VMESS | VLESS | TROJAN |"
    echo "| 5    | 0     | 1     | 1      |"
    echo ""
    echo "SSH : ON  MONITORING : ON  XRAY : ON  TROJAN : ON"
    echo "STUNNEL : ON  DROPPBEAR : ON  SSH-MS : ON"
    echo ""
}

# Display menu options
display_menu() {
    echo "[01] SSH [Menu]          [06] TRIAL [Menu]"
    echo "[02] VMESS [Menu]        [07] BACKUP"
    echo "[03] VLESS [Menu]        [08] ADD-HOST DOMAIN"
    echo "[04] TROJAN [Menu]       [09] CHECK RUNNING"
    echo "[05] SETTING [Menu]      [10] SETUP REBOOT"
    echo ""
    echo -e "${BLUE}# HERU TAMBANAN${NC}"
    echo ""
    echo "[11] DOMAIN FREE         [15] UNLOCK"
    echo "[12] INSTAL UDP          [16] RENEW CERT"
    echo "[13] MS DOMAIN           [17] CLEAR SAMPAH"
    echo "[14] LOCK"
    echo ""
    echo "Wadah Kasih, ( MONITORING BANDWIDTH )"
    echo "Wadah Member1, TODAY - 37.73 G"
    echo "Niat Di Hati, YESTERDAY - 166.79 G"
    echo "Nawattu Free, MONTH -"
    echo ""
    echo "Autoscript By : Sakurav3"
    echo "Version : $VERSION"
    echo "License Key : $LICENSE_KEY"
    echo "Day Expired : Lifetime"
    echo "Username : $USERNAME"
    echo ""
}

# SSH Menu
ssh_menu() {
    echo -e "${GREEN}SSH Menu Selected${NC}"
    echo "1. Create SSH Account"
    echo "2. Delete SSH Account"
    echo "3. Extend SSH Account"
    echo "4. List SSH Accounts"
    echo "5. Back to Main Menu"
    read -p "Select option: " ssh_option
    
    case $ssh_option in
        1) create_ssh ;;
        2) delete_ssh ;;
        3) extend_ssh ;;
        4) list_ssh ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# VMESS Menu
vmess_menu() {
    echo -e "${GREEN}VMESS Menu Selected${NC}"
    echo "1. Create VMESS Account"
    echo "2. Delete VMESS Account"
    echo "3. Extend VMESS Account"
    echo "4. List VMESS Accounts"
    echo "5. Back to Main Menu"
    read -p "Select option: " vmess_option
    
    case $vmess_option in
        1) create_vmess ;;
        2) delete_vmess ;;
        3) extend_vmess ;;
        4) list_vmess ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# VLESS Menu
vless_menu() {
    echo -e "${GREEN}VLESS Menu Selected${NC}"
    echo "1. Create VLESS Account"
    echo "2. Delete VLESS Account"
    echo "3. Extend VLESS Account"
    echo "4. List VLESS Accounts"
    echo "5. Back to Main Menu"
    read -p "Select option: " vless_option
    
    case $vless_option in
        1) create_vless ;;
        2) delete_vless ;;
        3) extend_vless ;;
        4) list_vless ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Trojan Menu
trojan_menu() {
    echo -e "${GREEN}Trojan Menu Selected${NC}"
    echo "1. Create Trojan Account"
    echo "2. Delete Trojan Account"
    echo "3. Extend Trojan Account"
    echo "4. List Trojan Accounts"
    echo "5. Back to Main Menu"
    read -p "Select option: " trojan_option
    
    case $trojan_option in
        1) create_trojan ;;
        2) delete_trojan ;;
        3) extend_trojan ;;
        4) list_trojan ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Setting Menu
setting_menu() {
    echo -e "${GREEN}Setting Menu Selected${NC}"
    echo "1. Change SSH Port"
    echo "2. Change V2Ray Port"
    echo "3. Change Trojan Port"
    echo "4. Speedtest Server"
    echo "5. Back to Main Menu"
    read -p "Select option: " setting_option
    
    case $setting_option in
        1) change_ssh_port ;;
        2) change_v2ray_port ;;
        3) change_trojan_port ;;
        4) speedtest ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Trial Menu
trial_menu() {
    echo -e "${GREEN}Trial Menu Selected${NC}"
    echo "1. Create Trial SSH Account"
    echo "2. Create Trial VMESS Account"
    echo "3. Create Trial VLESS Account"
    echo "4. Create Trial Trojan Account"
    echo "5. Back to Main Menu"
    read -p "Select option: " trial_option
    
    case $trial_option in
        1) create_trial_ssh ;;
        2) create_trial_vmess ;;
        3) create_trial_vless ;;
        4) create_trial_trojan ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Backup function
backup_menu() {
    echo -e "${GREEN}Backup Menu Selected${NC}"
    echo "1. Backup User Data"
    echo "2. Restore User Data"
    echo "3. Back to Main Menu"
    read -p "Select option: " backup_option
    
    case $backup_option in
        1) backup_data ;;
        2) restore_data ;;
        3) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Add Host Domain
add_host_domain() {
    echo -e "${GREEN}Add Host Domain Selected${NC}"
    read -p "Enter domain name: " domain_name
    if [ -z "$domain_name" ]; then
        echo -e "${RED}Domain name cannot be empty!${NC}"
        return
    fi
    
    # Add domain to hosts file
    echo "127.0.0.1 $domain_name" >> /etc/hosts
    echo -e "${GREEN}Domain $domain_name added successfully!${NC}"
}

# Check running services
check_running() {
    echo -e "${GREEN}Checking running services...${NC}"
    echo "SSH Service: $(systemctl is-active ssh)"
    echo "V2Ray Service: $(systemctl is-active v2ray)"
    echo "Trojan Service: $(systemctl is-active trojan)"
    echo "Stunnel Service: $(systemctl is-active stunnel4)"
    echo "Dropbear Service: $(systemctl is-active dropbear)"
}

# Setup reboot schedule
setup_reboot() {
    echo -e "${GREEN}Setup Reboot Selected${NC}"
    echo "1. Reboot daily at midnight"
    echo "2. Reboot weekly"
    echo "3. Custom reboot schedule"
    echo "4. Back to Main Menu"
    read -p "Select option: " reboot_option
    
    case $reboot_option in
        1) echo "0 0 * * * root /sbin/reboot" > /etc/cron.d/reboot_schedule
           echo -e "${GREEN}Daily reboot at midnight scheduled!${NC}" ;;
        # Other options would be implemented similarly
        4) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Domain Free
domain_free() {
    echo -e "${GREEN}Domain Free Selected${NC}"
    echo "Free domain providers:"
    echo "1. https://freedns.afraid.org"
    echo "2. https://www.duckdns.org"
    echo "3. https://www.noip.com"
    echo "Please visit these sites to get a free domain."
}

# Install UDP
install_udp() {
    echo -e "${GREEN}Installing UDP Custom...${NC}"
    # Download and install UDP Custom
    wget -O /usr/bin/udp-custom https://github.com/xxooxxooxx/udp-custom/raw/main/udp-custom
    chmod +x /usr/bin/udp-custom
    echo -e "${GREEN}UDP Custom installed successfully!${NC}"
}

# MS Domain
ms_domain() {
    echo -e "${GREEN}MS Domain Selected${NC}"
    read -p "Enter Microsoft Domain: " ms_domain
    echo "Microsoft Domain $ms_domain configured!"
}

# Lock function
lock_function() {
    echo -e "${GREEN}Lock Selected${NC}"
    echo "Locking system configuration..."
    chattr +i /etc/passwd
    chattr +i /etc/shadow
    chattr +i /etc/group
    chattr +i /etc/gshadow
    echo -e "${GREEN}System configuration locked!${NC}"
}

# Unlock function
unlock_function() {
    echo -e "${GREEN}Unlock Selected${NC}"
    echo "Unlocking system configuration..."
    chattr -i /etc/passwd
    chattr -i /etc/shadow
    chattr -i /etc/group
    chattr -i /etc/gshadow
    echo -e "${GREEN}System configuration unlocked!${NC}"
}

# Renew Certificate
renew_cert() {
    echo -e "${GREEN}Renewing SSL Certificate...${NC}"
    # Check if certbot is installed
    if command -v certbot >/dev/null 2>&1; then
        certbot renew
        echo -e "${GREEN}SSL Certificate renewed!${NC}"
    else
        echo -e "${RED}Certbot is not installed!${NC}"
        echo "Install certbot with: apt install certbot"
    fi
}

# Clear junk files
clear_junk() {
    echo -e "${GREEN}Clearing junk files...${NC}"
    apt autoremove -y
    apt clean
    rm -rf /tmp/*
    rm -rf /var/tmp/*
    echo -e "${GREEN}Junk files cleared!${NC}"
}

# Placeholder functions for various operations
create_ssh() { echo -e "${GREEN}SSH Account created!${NC}"; }
delete_ssh() { echo -e "${RED}SSH Account deleted!${NC}"; }
extend_ssh() { echo -e "${YELLOW}SSH Account extended!${NC}"; }
list_ssh() { echo -e "${BLUE}Listing SSH Accounts...${NC}"; }

create_vmess() { echo -e "${GREEN}VMESS Account created!${NC}"; }
delete_vmess() { echo -e "${RED}VMESS Account deleted!${NC}"; }
extend_vmess() { echo -e "${YELLOW}VMESS Account extended!${NC}"; }
list_vmess() { echo -e "${BLUE}Listing VMESS Accounts...${NC}"; }

create_vless() { echo -e "${GREEN}VLESS Account created!${NC}"; }
delete_vless() { echo -e "${RED}VLESS Account deleted!${NC}"; }
extend_vless() { echo -e "${YELLOW}VLESS Account extended!${NC}"; }
list_vless() { echo -e "${BLUE}Listing VLESS Accounts...${NC}"; }

create_trojan() { echo -e "${GREEN}Trojan Account created!${NC}"; }
delete_trojan() { echo -e "${RED}Trojan Account deleted!${NC}"; }
extend_trojan() { echo -e "${YELLOW}Trojan Account extended!${NC}"; }
list_trojan() { echo -e "${BLUE}Listing Trojan Accounts...${NC}"; }

change_ssh_port() { 
    read -p "Enter new SSH port: " new_port
    sed -i "s/^#Port.*/Port $new_port/" /etc/ssh/sshd_config
    sed -i "s/^Port.*/Port $new_port/" /etc/ssh/sshd_config
    systemctl restart ssh
    echo -e "${GREEN}SSH port changed to $new_port!${NC}"
}

change_v2ray_port() { echo -e "${GREEN}V2Ray port changed!${NC}"; }
change_trojan_port() { echo -e "${GREEN}Trojan port changed!${NC}"; }
speedtest() { 
    echo -e "${GREEN}Running speedtest...${NC}"; 
    curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3 -
}

create_trial_ssh() { echo -e "${GREEN}Trial SSH Account created!${NC}"; }
create_trial_vmess() { echo -e "${GREEN}Trial VMESS Account created!${NC}"; }
create_trial_vless() { echo -e "${GREEN}Trial VLESS Account created!${NC}"; }
create_trial_trojan() { echo -e "${GREEN}Trial Trojan Account created!${NC}"; }

backup_data() { echo -e "${GREEN}User data backed up!${NC}"; }
restore_data() { echo -e "${GREEN}User data restored!${NC}"; }

# Main script execution
while true; do
    get_system_info
    display_header
    display_menu
    
    read -p "Select menu : " menu_option
    
    case $menu_option in
        1) ssh_menu ;;
        2) vmess_menu ;;
        3) vless_menu ;;
        4) trojan_menu ;;
        5) setting_menu ;;
        6) trial_menu ;;
        7) backup_menu ;;
        8) add_host_domain ;;
        9) check_running ;;
        10) setup_reboot ;;
        11) domain_free ;;
        12) install_udp ;;
        13) ms_domain ;;
        14) lock_function ;;
        15) unlock_function ;;
        16) renew_cert ;;
        17) clear_junk ;;
        exit|quit) echo -e "${RED}Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option! Please try again.${NC}"; sleep 2 ;;
    esac
    
    read -p "Press Enter to continue..."
done
