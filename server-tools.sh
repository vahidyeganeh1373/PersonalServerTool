#!/bin/bash
VERSION="0.3.9"
SERVER_IP=$(hostname -I | awk '{print $1}')

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

# --- 9. Pasarguard Node Function ---
function pasarguard_node_menu() {
  while true; do
    clear
    echo "==============================="
    echo -e "${CYAN}      Pasarguard Node Menu     ${NC}"
    echo "==============================="
    echo "1. Install"
    echo "2. Change core version"
    echo "3. Renew Cert"
    echo "4. Edit Docker Config"
    echo "5. Back to MainMenu"
    echo "-------------------------------"
    read -p "Select an option [1-5]: " pg_choice

    case $pg_choice in
      1)
        echo -e "${YELLOW}[*] Preparing Assets... ${NC}"
        command -v wget >/dev/null 2>&1 || apt-get install -y wget
        mkdir -p /var/lib/pg-node/assets/
        wget -O /var/lib/pg-node/assets/iran.dat https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat
        wget -O /var/lib/pg-node/assets/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
        wget -O /var/lib/pg-node/assets/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
        
        echo -e "${YELLOW}[*] Installing Pasarguard... ${NC}"
        sudo bash -c "$(curl -sL https://github.com/PasarGuard/scripts/raw/main/pg-node.sh)" @ install
        
        echo -e "${YELLOW}[*] Modifying Docker-Compose.yml... ${NC}"
        if [ -f /opt/pg-node/docker-compose.yml ]; then
            if ! grep -q "/var/lib/pg-node/assets" /opt/pg-node/docker-compose.yml; then
                sudo sed -i '/volumes:/a \      - /var/lib/pg-node/assets:/usr/local/share/xray' /opt/pg-node/docker-compose.yml
                echo -e "${GREEN}[✓] Assets volume added to yaml.${NC}"
            fi
        fi
        
        echo -e "${YELLOW}[*] Restarting Pg-Node... ${NC}"
        pg-node restart || true
        read -n 1 -s -r -p $'\nPress any key to return...'
        ;;

      2)
        echo -e "${YELLOW}[*] Updating Core... ${NC}"
        pg-node core-update || echo "Error: Pg-Node Not Found "
        read -n 1 -s -r -p $'\nPress any key to return...'
        ;;

      3)
        echo -e "${YELLOW}[*] Renewing Certificate...${NC}"
        pg-node renew-cert
        
        echo -e "${YELLOW}[*] Checking Configuration...${NC}"
        if [ -f /opt/pg-node/docker-compose.yml ]; then
            if ! grep -q "/var/lib/pg-node/assets" /opt/pg-node/docker-compose.yml; then
                echo "      - /var/lib/pg-node/assets:/usr/local/share/xray" >> /opt/pg-node/docker-compose.yml
                echo -e "${GREEN}[✓] Assets Added To Docker-Compose.yml ${NC}"
            else
                echo -e "${CYAN}[!] Assets Already Exists In Docker-Compose.yml ${NC}"
            fi
            
            echo -e "${YELLOW}[!] Opening Nano For Final Check... (Save and Exit) ${NC}"
            sleep 2
            nano /opt/pg-node/docker-compose.yml
            
            echo -e "${YELLOW}[*] Restarting pg-node...${NC}"
            pg-node restart
            echo -e "${GREEN}[✓] Certificate Renewed And Service Restarted.${NC}"
        else
            echo -e "${RED}[!] Error: /opt/pg-node/docker-compose.yml Not Found! ${NC}"
        fi
        read -n 1 -s -r -p $'\nPress any key to return...'
        ;;
        
      4)
        if [ -f /opt/pg-node/docker-compose.yml ]; then
            echo -e "${YELLOW}[*] Opening Docker-Compose.yml... ${NC}"
            sleep 1
            nano /opt/pg-node/docker-compose.yml
            
            echo -e "${YELLOW}[*] Restarting Pg-Node To Apply Changes... ${NC}"
            pg-node restart
            echo -e "${GREEN}[✓] Done.${NC}"
        else
            echo -e "${RED}[!] Error: Configuration File Not Found ${NC}"
        fi
        read -n 1 -s -r -p $'\nPress any key to return...'
        ;;
      5) break ;;
      *) echo "Invalid Option"; sleep 1 ;;
    esac
  done
}

# --- 8. SSH Tunnel Function ---
function ssh_tunnel_menu() {
  while true; do
    clear
    echo -e "${YELLOW}===============================${NC}"
    echo -e "${YELLOW}         SSH Tunnel Menu           ${NC}"
    echo -e "${YELLOW}===============================${NC}"
    echo ""
    echo "1. Install / ReConfig"
    echo "2. Restart"
    echo "3. Disable"
    echo "4. Edit"
    echo "5. Uninstall"
    echo "6. Reset Timer"
    echo "7. Status"
    echo ""
    echo "8. Return"
    echo ""
    echo -e "${YELLOW}===============================${NC}"
    echo ""
    read -p "$(echo -e "${YELLOW}Choice: ${NC}")" ash_choice
case $ash_choice in

      1)
        echo -e "\n${YELLOW}[*] Setting up SSH Tunnel... ${NC}"
        echo ""
        read -p "$(echo -e "${YELLOW}Foreign IP: ${NC}")" FOREIGN_IP
        echo ""
        echo -e "${GREEN} ┇${NC}"
        echo -e "${GREEN} ▼${NC}"
        echo ""
        read -p "$(echo -e "${YELLOW}Foreign SSH Port (e.g., 22): ${NC}")" REMOTE_SSH_PORT
        echo ""
        echo -e "${GREEN} ┇${NC}"
        echo -e "${GREEN} ▼${NC}"
        echo ""
        read -p "$(echo -e "${YELLOW}Config Port (e.g., 2083): ${NC}")" CONFIG_PORT
        echo ""
        echo -e "${GREEN} ┇${NC}"
        echo -e "${GREEN} ▼${NC}"
        echo ""
        echo -e "${YELLOW}Select Encryption Cipher:${NC}"
        echo ""
        echo -e "${YELLOW}1. AES128-CTR (Stability/DPI Bypass)${NC}"
        echo -e "${YELLOW}2. Chacha20-Poly1305 (Fast/Secure)${NC}"
        echo ""
        read -p "$(echo -e "${YELLOW}Choice [1-2]: ${NC}")" cipher_choice
        echo ""
        if [[ -z "$FOREIGN_IP" || ! "$REMOTE_SSH_PORT" =~ ^[0-9]+$ || ! "$CONFIG_PORT" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}❌ Invalid input (Foreign IP / ports must be filled, ports numeric)${NC}"
            sleep 2
            continue
        fi
        if [[ "$cipher_choice" == "2" ]]; then
            SELECTED_CIPHER="chacha20-poly1305@openssh.com"
        else
            SELECTED_CIPHER="aes128-ctr"
        fi

        systemctl stop ssh-tunnel 2>/dev/null || true
        systemctl disable ssh-tunnel.service 2>/dev/null || true
        rm -f /etc/systemd/system/ssh-tunnel.service || true

cat <<EOF | sudo tee /etc/systemd/system/ssh-tunnel.service > /dev/null
[Unit]
Description=SSH-Tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/ssh -N \\
    -o "StrictHostKeyChecking=no" \\
    -o "UserKnownHostsFile=/dev/null" \\
    -o "FingerprintHash=sha256" \\
    -o "Cipher=${SELECTED_CIPHER}" \\
    -o "Compression=no" \\
    -o "KbdInteractiveAuthentication=no" \\
    -o "PreferredAuthentications=publickey" \\
    -o "ServerAliveInterval 9" \\
    -o "ServerAliveCountMax 3" \\
    -o "RekeyLimit=2G 1h" \\
    -o "TCPKeepAlive=yes" \\
    -o "ExitOnForwardFailure=yes" \\
    -o "IPQoS=throughput" \\
    -p ${REMOTE_SSH_PORT} -L 0.0.0.0:${CONFIG_PORT}:127.0.0.1:${CONFIG_PORT} root@${FOREIGN_IP}
RuntimeMaxSec=3600    
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        
        if [ ! -f ~/.ssh/id_rsa ]; then
            ssh-keygen -t rsa -b 2048 -N "" -f ~/.ssh/id_rsa
        fi
        
        echo -e "${YELLOW}[*] Attempting To Copy SSH Key... (Enter Password If Asked)${NC}"
        echo ""
        ssh-copy-id -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -p ${REMOTE_SSH_PORT} root@${FOREIGN_IP} || echo -e "${RED}Warning: Could not copy SSH key!${NC}"
        
        systemctl daemon-reload
        systemctl enable ssh-tunnel
        systemctl start ssh-tunnel
        systemctl restart ssh-tunnel || echo -e "${RED}Failed To Start Service!${NC}"
        
        echo -e "${BLUE}✅ Done! SSH-Tunnel Is Running${NC}"
        read -p "Press any key to continue..." -n1
        ;;

      2)
         echo -e "\n${YELLOW}[*] Restarting... ${NC}"
         echo ""
         systemctl daemon-reload && systemctl restart ssh-tunnel
         echo -e "${BLUE}✅ Service Restarted${NC}"
         read -p "Press any key to continue..." -n1
         ;;
         
      3)
         echo -e "\n${YELLOW}[*] Disabling... ${NC}"
         echo ""
         systemctl stop ssh-tunnel && systemctl disable ssh-tunnel
         echo -e "${RED}🛑 Tunnel Stopped${NC}";
         read -p "Press any key to continue..." -n1
         ;;
         
      4)
        echo -e "\n${YELLOW}[*] Editing... ${NC}"
        echo ""
        if [ -f /etc/systemd/system/ssh-tunnel.service ]; then
            nano /etc/systemd/system/ssh-tunnel.service
            systemctl daemon-reload && systemctl restart ssh-tunnel
            echo -e "${BLUE}✅ Service Edited & Restarted ${NC}"
            read -p "Press any key to continue..." -n1
        else
            echo -e "${RED}❌ Service Not Found ${NC}"; 
            read -p "Press any key to continue..." -n1
        fi ;;
        
      5)
        echo -e "\n${YELLOW}[*] Uninstalling... ${NC}"
        echo ""
        systemctl stop ssh-tunnel.service 2>/dev/null || true
        systemctl disable ssh-tunnel.service 2>/dev/null || true
        rm -f /etc/systemd/system/ssh-tunnel.service || true
        crontab -l 2>/dev/null | grep -v "systemctl restart ssh-tunnel" | crontab -
        systemctl daemon-reload || true
        echo -e "${RED}❌ SSH-Tunnel Uninstalled Successfully${NC}"
        read -p "Press any key to continue..." -n1
        ;;
     6)
      echo -e "\n${YELLOW}[*] Configure Auto Restart Timer${NC}"
      echo -e "\n${YELLOW}Enter Interval In Hours (e.g. 2h)${NC}"
      echo -e "\n${YELLOW}Enter '0' to Disable The Timer${NC}"
      echo ""
      read -p "$(echo -e "${YELLOW}Interval: ${NC}")" timer_input
      hours=$(echo "$timer_input" | tr -dc '0-9')

      if [[ -z "$hours" ]]; then
          echo -e "${RED}Invalid Input! Please Enter A Number${NC}"
          sleep 2
      elif [[ "$hours" -gt 23 ]]; then
          echo -e "${RED}Invalid Input! Interval must be between 1 and 23 hours (or 0 to disable)${NC}"
          sleep 2
      elif [[ "$hours" -eq 0 ]]; then
          (crontab -l 2>/dev/null | grep -v "systemctl restart ssh-tunnel") | crontab -
          echo -e "${RED}🛑 Auto Restart Timer Disabled${NC}"
          read -p "Press any key to continue..." -n1
      else
          (crontab -l 2>/dev/null | grep -v "systemctl restart ssh-tunnel"; echo "0 */$hours * * * systemctl restart ssh-tunnel") | crontab -
          echo -e "${BLUE}✅ Timer Set! Service Will Restart Every $hours Hour(s)${NC}"
          read -p "Press any key to continue..." -n1
      fi
      ;;
      7)
        trap ':' INT
        journalctl -u ssh-tunnel.service -f
        trap - INT
        read -n 1 -s -r -p $'\nPress any key to return...' ;;
      8) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
    done
} 
# --- 1. Setup Firewall ---
function setup_firewall() {
  echo -e "\n\033[1;33m[*] Setting up Firewall...\033[0m"
  apt-get install -y ufw
  PORTS=(ssh http https 53/tcp 53/udp 80/tcp 80/udp 2020/tcp 2020/udp 443/tcp 443/udp 8000/tcp 8000/udp 57160/tcp 57160/udp 5629/tcp 5629/udp 1080/tcp 1080/udp 3478/tcp 3478/udp 2096/tcp 2096/udp 3832/tcp 3832/udp 8081/tcp 8081/udp 8082/tcp 8082/udp 2095/tcp 2095/udp 25349/tcp 25349/udp 10000/tcp 10000/udp 11000/tcp 11000/udp 11100/tcp 11100/udp 11200/tcp 11200/udp 11300/tcp 11300/udp 11400/tcp 11400/udp 11500/tcp 11500/udp 11600/tcp 11600/udp 21653/tcp 21653/udp 21652/tcp 21652/udp 14848/tcp 14848/udp 55150/tcp 55150/udp 55151/tcp 55151/udp 55250/tcp 55250/udp 55251/tcp 55251/udp 55350/tcp 55350/udp 55351/tcp 55351/udp 55450/tcp 55450/udp 55451/tcp 55451/udp 55550/tcp 55550/udp 55551/tcp 55551/udp 55650/tcp 55650/udp 55651/tcp 55651/udp 55750/tcp 55750/udp 55751/tcp 55751/udp 55850/tcp 55850/udp 55851/tcp 55851/udp 55950/tcp 55950/udp 55951/tcp 55951/udp 56050/tcp 56050/udp 56051/tcp 56051/udp 5666/tcp 5666/udp 2083/tcp 2083/udp 5201/tcp 5201/udp 8880/tcp 8880/udp 2087/tcp 2087/udp)
  for port in "${PORTS[@]}"; do ufw allow "$port"; done
  # always keep the real SSH port(s) open (the port may have been changed with option 3)
  SSH_PORTS=$( { sshd -T 2>/dev/null | awk '/^port /{print $2}'; ss -tlnp 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]}'; } | sort -u )
  for p in $SSH_PORTS; do ufw allow "$p"/tcp; done
  BLOCKED_SUBNETS=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 240.0.0.0/4 25.10.40.0/24 25.11.10.0/24 103.58.50.0/24 195.137.167.0/24 45.14.174.0/24 206.191.152.0/24 216.218.185.0/24 114.208.187.0/24 185.235.87.0/24 185.235.86.0/24 233.252.0.0/24 224.0.0.0/4 240.0.0.0/24 203.0.113.0/24 198.51.100.0/24 198.18.0.0/15 192.88.99.0/24 192.0.2.0/24 192.0.0.0/24 102.224.45.0/24)
  for subnet in "${BLOCKED_SUBNETS[@]}"; do ufw deny out from any to "$subnet"; done
  echo "y" | sudo ufw enable
  read -n 1 -s -r -p $'\033[1;35m\n[✓] Done. Press any key to return\033[0m'
}

function optimize_network() {
  local CONF="${SYSCTL_CONF:-/etc/sysctl.conf}"
  echo -e "\n${YELLOW}[*] Optimizing Network...${NC}"
  # key=value  (values are chosen for a tunnel/proxy server with ~100 users, see notes in the changelog)
  local settings=(
    "net.ipv4.tcp_syncookies=1"
    "net.core.default_qdisc=fq"
    "net.ipv4.tcp_congestion_control=bbr"
    "net.ipv4.tcp_max_syn_backlog=8192"
    "net.core.somaxconn=16384"
    "net.core.netdev_max_backlog=16384"
    "net.ipv4.tcp_fastopen=3"
    "net.ipv4.tcp_tw_reuse=1"
    "net.ipv4.tcp_mtu_probing=1"
    "net.ipv4.tcp_slow_start_after_idle=0"
    "net.ipv4.tcp_keepalive_time=30"
    "net.ipv4.tcp_keepalive_intvl=5"
    "net.ipv4.tcp_keepalive_probes=3"
    "net.ipv4.tcp_notsent_lowat=131072"
    "net.ipv4.tcp_fin_timeout=15"
    "net.core.rmem_max=67108864"
    "net.core.wmem_max=67108864"
    "net.ipv4.tcp_rmem=4096 87380 67108864"
    "net.ipv4.tcp_wmem=4096 65536 67108864"
  )
  local item key val
  touch "$CONF"
  # remove any previous entry of these keys (old script, manual edits), then add the fresh block
  sed -i '/^# --- Server Tools: network optimize ---$/d' "$CONF"
  for item in "${settings[@]}"; do
    key="${item%%=*}"
    sed -i "/^[[:space:]]*${key//./\\.}[[:space:]]*=/d" "$CONF"
  done
  {
    echo ""
    echo "# --- Server Tools: network optimize ---"
    for item in "${settings[@]}"; do echo "${item%%=*} = ${item#*=}"; done
  } >> "$CONF"
  modprobe tcp_bbr 2>/dev/null || true
  sysctl -p "$CONF" >/dev/null 2>&1 || echo -e "${RED}[!] sysctl reported an error for some key (checking below)${NC}"
  # verify what the kernel really accepted (OpenVZ/LXC VPS may refuse some keys)
  local bad=0 cur want
  for item in "${settings[@]}"; do
    key="${item%%=*}"; want=$(echo "${item#*=}" | tr -s "[:space:]" " " | sed "s/ *$//")
    cur=$(sysctl -n "$key" 2>/dev/null | tr -s "[:space:]" " " | sed "s/ *$//")
    if [ "$cur" != "$want" ]; then
      echo -e "${RED}[!] $key = ${cur:-n/a}  (wanted $want)${NC}"; bad=$((bad+1))
    fi
  done
  if [ "$bad" -eq 0 ]; then
    echo -e "${GREEN}[✓] Network Optimized (${#settings[@]} settings applied and verified)${NC}"
  else
    echo -e "${YELLOW}[!] $bad setting(s) not applied (kernel/VPS refused them); the rest are active${NC}"
  fi
  sleep 1
}

function change_ssh_port() {
    echo -e "\n${YELLOW}[*] Changing SSH Port... ${NC}"
    read -p "Enter New SSH Port: " NEW_PORT

    if [[ "$NEW_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -gt 0 ] && [ "$NEW_PORT" -le 65535 ]; then

        if command -v ufw >/dev/null; then
            echo -e "${YELLOW}[*] Updating UFW...${NC}"
            ufw allow $NEW_PORT/tcp >/dev/null
            ufw allow $NEW_PORT/udp >/dev/null
            ufw reload >/dev/null
            echo -e "${GREEN}[✓] UFW Updated (Port $NEW_PORT Allowed) ${NC}"
        fi

        sed -i '/^Port /d' /etc/ssh/sshd_config
        sed -i '/^#Port /d' /etc/ssh/sshd_config
        echo "Port $NEW_PORT" >> /etc/ssh/sshd_config

        echo -e "${YELLOW}[*] Disabling ssh.socket (if present)...${NC}"
        if systemctl list-unit-files | grep -q "^ssh.socket"; then
            systemctl stop ssh.socket 2>/dev/null || true
            systemctl disable ssh.socket 2>/dev/null || true
            echo -e "${GREEN}[✓] ssh.socket Disabled${NC}"
        fi

        echo -e "${YELLOW}[*] Restarting SSH service...${NC}"
        systemctl daemon-reload
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
            echo -e "${GREEN}[✓] SSH Port Successfully Changed To $NEW_PORT ${NC}"
            echo -e "${CYAN}[i] Verifying listening port...${NC}"
            ss -tlnp | grep ssh || true
        else
            echo -e "${RED}[!] Failed To Restart SSH. Please Check /etc/ssh/sshd_config Manually ${NC}"
        fi
    else
        echo -e "${RED}[!] Invalid Input. Please Enter a Valid Port Number ${NC}"
    fi
    
    read -n 1 -s -r -p $'\nPress any key to return...'
}

function enable_root_login() {
    echo -e "\n${YELLOW}[*] Enabling Direct Root Login... ${NC}"
    
    read -r -p "Set a Password for Root user: " ROOT_PASS

    if [ -n "$ROOT_PASS" ]; then
        echo "root:$ROOT_PASS" | chpasswd
        
        sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        grep -q '^PermitRootLogin yes' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
        
        sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
        # cloud images ship drop-in files (e.g. 50-cloud-init.conf) that override the main file
        sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/; s/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
        
        sudo systemctl restart sshd || sudo service ssh restart

        echo -e "\n${GREEN}[✓] Root Login Is Now Enabled ${NC}"
        echo -e "${YELLOW}[!] You Can Now Login Directly Using: ssh root@Your_IP ${NC}"
    else
        echo -e "\n${RED}[!] Password Cannot Be Empty! ${NC}"
    fi

    read -n 1 -s -r -p $'\nPress any key to return...'
}

function change_root_password() {
    echo -e "\n${YELLOW}[*] Changing Root Password...${NC}"
    
    read -r -p "Enter New Root Password: " USER_PASS
    echo -e "\n"

    if [ -n "$USER_PASS" ]; then
        if echo "root:$USER_PASS" | chpasswd; then
            echo -e "${GREEN}[✓] Password Successfully Changed ${NC}"
        else
            echo -e "${RED}[!] Error: Could Not Change Password ${NC}"
        fi
    else
        echo -e "${RED}[!] Password Cannot Be Empty! ${NC}"
    fi

    read -n 1 -s -r -p $'\nPress any key to return...'
}

function change_dns() {
    echo -e "\n${YELLOW}[*] Changing DNS Configuration...${NC}"
    
    # Remove immutable flag if it was set before, so we can modify/replace the file
    sudo chattr -i /etc/resolv.conf 2>/dev/null || true
    
    echo -e "${YELLOW}[*] Disabling systemd-resolved...${NC}"
    sudo systemctl disable --now systemd-resolved 2>/dev/null || echo -e "${RED}[!] systemd-resolved was not running or already disabled${NC}"
    
    echo -e "${YELLOW}[*] Writing new resolv.conf...${NC}"
    sudo rm -f /etc/resolv.conf
    sudo bash -c 'cat > /etc/resolv.conf << EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF'
    
    echo -e "${YELLOW}[*] Locking resolv.conf (immutable)...${NC}"
    sudo chattr +i /etc/resolv.conf 2>/dev/null || echo -e "${RED}[!] Could not lock resolv.conf (chattr not supported here)${NC}"
    
    echo -e "${GREEN}[✓] DNS Changed Successfully To 1.1.1.1 / 8.8.8.8${NC}"
    echo -e "${CYAN}[i] Current /etc/resolv.conf:${NC}"
    cat /etc/resolv.conf
    
    read -n 1 -s -r -p $'\nPress any key to return...'
}

# --- 5. Backhaul ---
function Backhual() {
  while true; do
    clear
    echo "==============================="
    echo "         Backhaul Menu         "
    echo "==============================="
    echo "1. Install Backhaul Core⬇️"
    echo "2. Run 🔄"
    echo "3. Restart ♻️"
    echo "4. Return 🔙"
    read -p "Choice: " bh_choice
    case $bh_choice in
      1) command -v git >/dev/null 2>&1 || apt-get install -y git
         rm -rf /tmp/my-uploads && git clone https://github.com/Alighaemi9731/backhaul.git /tmp/my-uploads
         mkdir -p /opt/utunnel && mv /tmp/my-uploads/utunnel /opt/utunnel/utunnel
         mv /tmp/my-uploads/utunnel_manager /root/utunnel_manager && chmod +x /root/utunnel_manager; read -p "Done..." -n1 ;;
      2) if [ -x /root/utunnel_manager ]; then /root/utunnel_manager; else echo -e "${RED}❌ Not installed. Use option 1 first${NC}"; read -p "Press any key..." -n1; fi ;;
      3) sudo systemctl restart utunnel_king; read -p "Restarted..." -n1 ;;
      4) break ;;
    esac
  done
}

# --- 6. Gost ---
function GostMenu() {
  while true; do
    clear
    echo -e "${YELLOW}===============================${NC}"
    echo -e "${YELLOW}           GOST Menu           ${NC}"
    echo -e "${YELLOW}===============================${NC}"
    echo ""
    echo "1. Install"
    echo "2. Restart"
    echo "3. Disable"
    echo "4. Edit Config"
    echo "5. Status"
    echo "6. Uninstall"
    echo "7. Show Logs"
    echo ""
    echo "8. Return"
    echo ""
    
    read -p "$(echo -e "${YELLOW}Choice: ${NC}")" gost_choice
    echo ""
    case $gost_choice in
    
      1) if systemctl list-unit-files | grep -q gost.service; then sudo systemctl stop gost || true; fi
         command -v wget >/dev/null 2>&1 || apt-get install -y wget
         if ! wget -O /tmp/gost.tar.gz https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_amd64.tar.gz; then
            echo -e "${RED}❌ Download failed${NC}"; read -p "Press any key to continue..." -n1; continue
         fi
         rm -rf /usr/local/bin/gost && mkdir -p /usr/local/bin/gost && tar -xzf /tmp/gost.tar.gz -C /usr/local/bin/gost/
         rm -f /tmp/gost.tar.gz
         
         echo -e "${YELLOW}===============================${NC}"
         echo ""
         echo -e "${YELLOW}Please Choice Server Side${NC}"
         read -p "$(echo -e "${YELLOW}Iran = 1 , Foreign = 2 | (e.g. 2): ${NC}")" region_choice
         echo ""
         read -p "$(echo -e "${YELLOW}Tunnel Port (e.g. 443): ${NC}")" T_PORT
         echo ""
         read -p "$(echo -e "${YELLOW}Config Port (e.g. 2083): ${NC}")" C_PORT
         echo ""
         read -p "$(echo -e "${YELLOW}GOST Username: ${NC}")" G_USER
         echo ""
         read -p "$(echo -e "${YELLOW}GOST Password: ${NC}")" G_PASS
         echo ""
         read -p "$(echo -e "${YELLOW}Foreign Domain (e.g. speed.domain.com): ${NC}")" G_DOMAIN
         if command -v ufw >/dev/null 2>&1; then
            sudo ufw allow "$T_PORT"/tcp >/dev/null 2>&1
            sudo ufw allow "$C_PORT"/tcp >/dev/null 2>&1
            sudo ufw allow "$T_PORT"/udp >/dev/null 2>&1
            sudo ufw allow "$C_PORT"/udp >/dev/null 2>&1
         fi
         
         if [ "$region_choice" = "1" ]; then
            cat <<EOF | sudo tee /usr/lib/systemd/system/gost.service > /dev/null
[Unit]
Description=GO Simple Tunnel
After=network.target
Wants=network.target

[Service]
ExecStart=/usr/local/bin/gost/gost -L "tcp://:${C_PORT}/127.0.0.1:${C_PORT}" -F "relay+wss://${G_USER}:${G_PASS}@${G_DOMAIN}:${T_PORT}?serverName=${G_DOMAIN}&path=/lib-stream&ping=10&retry=5&keepalive=true&ttl=60s&mux=true&conns=1"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
         else

            command -v ufw >/dev/null 2>&1 && sudo ufw allow 80/tcp >/dev/null 2>&1
            
            CERT_PATH="/var/lib/mygost/certs/${G_DOMAIN}.cer"
            KEY_PATH="/var/lib/mygost/certs/${G_DOMAIN}.cer.key"

            if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
                echo -e "${CYAN}✅ Existing Certificate Found For $G_DOMAIN. Skipping SSL issuance.${NC}"
            else
                echo ""
                echo -e "${CYAN}--- Installing SSL Certificate for $G_DOMAIN ---${NC}"
                command -v socat >/dev/null 2>&1 || { apt update -y >/dev/null 2>&1 && apt install curl socat -y >/dev/null 2>&1; }
                RANDOM_EMAIL="gost_$(date +%s | cut -b6-10)@gmail.com"
                curl -s https://get.acme.sh | sh -s email=$RANDOM_EMAIL --force >/dev/null 2>&1
                ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                
                mkdir -p /var/lib/mygost/certs
                ~/.acme.sh/acme.sh \
                  --issue --force --standalone -d "$G_DOMAIN" \
                  --fullchain-file "/var/lib/mygost/certs/$G_DOMAIN.cer" \
                  --key-file "/var/lib/mygost/certs/$G_DOMAIN.cer.key"
            fi
            
            cat <<EOF | sudo tee /usr/lib/systemd/system/gost.service > /dev/null
[Unit]
Description=GO Simple Tunnel
After=network.target
Wants=network.target

[Service]
ExecStart=/usr/local/bin/gost/gost -L "relay+wss://${G_USER}:${G_PASS}@:${T_PORT}/127.0.0.1:${C_PORT}?cert=${CERT_PATH}&key=${KEY_PATH}&path=/lib-stream"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
         fi
         
         sudo systemctl daemon-reload && sudo systemctl enable gost && sudo systemctl restart gost
         echo ""
         echo -e "${YELLOW}===============================${NC}"
         echo ""
         echo -e "${BLUE}✅ Done! Gost Is Running${NC}"
         echo ""
         read -p "Press any key to continue..." -n1 ;;
         
      2) sudo systemctl daemon-reload && sudo systemctl enable gost && sudo systemctl restart gost; read -p "Gost Restarted" -n1 ;;

      3) sudo systemctl stop gost && sudo systemctl disable gost
         echo -e "${RED}🛑 Gost Disabled Successfully${NC}"
         read -p "Press any key to continue..." -n1 ;;

      4)
         if [ -f "/usr/lib/systemd/system/gost.service" ]; then
            nano /usr/lib/systemd/system/gost.service
            echo -e "${YELLOW}Applying changes...${NC}"
            sudo systemctl daemon-reload && sudo systemctl restart gost
            echo -e "${BLUE}✅ Changes Applied And Service Restarted!${NC}"
         else
            echo -e "${RED}❌ Service File Not Found! Install First${NC}"
         fi
         read -p "Press any key to continue..." -n1 ;;

      5) clear
         echo -e "${YELLOW}Gost Service Status${NC}"
         sudo systemctl status gost --no-pager
         echo "---------------------------"
         read -p "Press any key to continue..." -n1 ;;

      6) sudo systemctl stop gost && sudo systemctl disable gost
         sudo rm /usr/lib/systemd/system/gost.service
         sudo rm -rf /usr/local/bin/gost
         sudo systemctl daemon-reload
         echo -e "${RED}❌ Gost Uninstalled Successfully${NC}"
         read -p "Press any key to continue..." -n1 ;;
      7) clear
         echo "Press Ctrl+C to exit logs..."
         trap ':' INT
         journalctl -u gost -f
         trap - INT ;;
         
      8) break ;;
    esac
  done
}

# --- 7. Lena ---
function lena_tunnel() {
  bash <(curl -Ls https://raw.githubusercontent.com/MrAminiDev/LenaTunnel/main/install.sh)
  read -n 1 -s -r -p $'\nDone. Press any key...'
}

# --- 12. Waterwall Tunnel ---
WW_VERSION="${WW_VERSION:-v1.5.2}"
WW_DIR="${WW_DIR:-/opt/waterwall}"
WW_SERVICE="${WW_SERVICE:-/etc/systemd/system/waterwall.service}"
WW_URL="https://github.com/radkesvat/WaterWall/releases/download/${WW_VERSION}/Waterwall-linux-clang-x64.zip"

function ww_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
function ww_valid_ip() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local o; local IFS=.
  for o in $1; do [ "$((10#$o))" -le 255 ] || return 1; done
  return 0
}
# secrets are substituted into JSON: only safe characters allowed
function ww_valid_secret() { [[ "$1" =~ ^[A-Za-z0-9._@#%+=:,-]+$ ]]; }
function ww_valid_domain() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; }

function ww_ask_port() { # $1=prompt $2=default $3=varname
  local v
  while true; do
    read -p "$(echo -e "${YELLOW}$1 [$2]: ${NC}")" v
    v=${v:-$2}
    if ww_valid_port "$v"; then printf -v "$3" '%s' "$v"; return; fi
    echo -e "${RED}Invalid port${NC}"
  done
}
function ww_ask_ip() { # $1=prompt $2=varname
  local v
  while true; do
    read -p "$(echo -e "${YELLOW}$1: ${NC}")" v
    if ww_valid_ip "$v"; then printf -v "$2" '%s' "$v"; return; fi
    echo -e "${RED}Invalid IP${NC}"
  done
}
function ww_ask_secret() { # $1=prompt $2=varname
  local v
  while true; do
    read -p "$(echo -e "${YELLOW}$1: ${NC}")" v
    if ww_valid_secret "$v"; then printf -v "$2" '%s' "$v"; return; fi
    echo -e "${RED}Allowed characters: A-Z a-z 0-9 . _ @ # % + = : , -  (no spaces)${NC}"
  done
}

function ww_install_core() {
  echo -e "${YELLOW}[*] Installing Waterwall core ${WW_VERSION}...${NC}"
  apt-get update -y && apt-get install -y unzip curl libatomic1 || { echo -e "${RED}❌ apt install failed${NC}"; return 1; }
  mkdir -p "$WW_DIR/configs" "$WW_DIR/logs"
  (
    cd "$WW_DIR" || exit 1
    curl -L -f -o ww.zip "$WW_URL" || exit 1
    unzip -o ww.zip || exit 1
    chmod +x Waterwall
    rm -f ww.zip
  ) || { echo -e "${RED}❌ Waterwall core install failed${NC}"; return 1; }
}

# --- Waterwall templates (exact tested configs; only ports/IPs/secrets are tokens) ---
function ww_tpl_config() { # $1 = raw|reality|hd  $2 = iran|foreign
  case "$1-$2" in
  raw-iran) cat <<'WWTPL'
{
  "name": "iran-reverse-raw",
  "author": "waterwall-user",
  "config-version": 1,
  "core-minimum-version": 0,
  "nodes": [
    {
      "name": "users_inbound",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": __CONFIG_PORT__,
        "nodelay": true
      },
      "next": "bridge_users"
    },
    {
      "name": "bridge_users",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_reverse"
      }
    },
    {
      "name": "bridge_reverse",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_users"
      }
    },
    {
      "name": "reverse_server",
      "type": "ReverseServer",
      "settings": {
        "reverse-secret-length": 640,
        "reverse-secret": "__SECRET__"
      },
      "next": "bridge_reverse"
    },
    {
      "name": "peers_inbound",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": __TUNNEL_PORT__,
        "nodelay": true,
        "whitelist": [
          "__FOREIGN_IP__/32"
        ]
      },
      "next": "reverse_server"
    }
  ]
}
WWTPL
  ;;
  raw-foreign) cat <<'WWTPL'
{
  "name": "foreign-reverse-raw",
  "author": "waterwall-user",
  "config-version": 1,
  "core-minimum-version": 0,
  "nodes": [
    {
      "name": "local_service",
      "type": "TcpConnector",
      "settings": {
        "address": "127.0.0.1",
        "port": __CONFIG_PORT__,
        "nodelay": true
      }
    },
    {
      "name": "bridge_local",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_reverse"
      },
      "next": "local_service"
    },
    {
      "name": "bridge_reverse",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_local"
      },
      "next": "reverse_client"
    },
    {
      "name": "reverse_client",
      "type": "ReverseClient",
      "settings": {
        "minimum-unused": 32,
        "reverse-secret-length": 640,
        "reverse-secret": "__SECRET__"
      },
      "next": "to_iran"
    },
    {
      "name": "to_iran",
      "type": "TcpConnector",
      "settings": {
        "address": "__IRAN_IP__",
        "port": __TUNNEL_PORT__,
        "nodelay": true
      }
    }
  ]
}
WWTPL
  ;;
  reality-iran) cat <<'WWTPL'
{
  "name": "iran-reverse-reality",
  "author": "waterwall-user",
  "config-version": 1,
  "core-minimum-version": 0,
  "nodes": [
    {
      "name": "users_inbound",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": __CONFIG_PORT__,
        "nodelay": true
      },
      "next": "bridge_users"
    },
    {
      "name": "bridge_users",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_reverse"
      }
    },
    {
      "name": "bridge_reverse",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_users"
      }
    },
    {
      "name": "reverse_server",
      "type": "ReverseServer",
      "settings": {
        "reverse-secret-length": 640,
        "reverse-secret": "__SECRET__"
      },
      "next": "bridge_reverse"
    },
    {
      "name": "reality_server",
      "type": "RealityServer",
      "settings": {
        "destination": "visitor_site",
        "password": "__REALITY_PASS__",
        "algorithm": "chacha20-poly1305",
        "sniffing-attempts": 8
      },
      "next": "reverse_server"
    },
    {
      "name": "visitor_site",
      "type": "TcpConnector",
      "settings": {
        "address": "__SNI__",
        "port": 443,
        "nodelay": true
      }
    },
    {
      "name": "peers_inbound",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": __TUNNEL_PORT__,
        "nodelay": true,
        "whitelist": [
          "__FOREIGN_IP__/32"
        ]
      },
      "next": "reality_server"
    }
  ]
}
WWTPL
  ;;
  reality-foreign) cat <<'WWTPL'
{
  "name": "foreign-reverse-reality",
  "author": "waterwall-user",
  "config-version": 1,
  "core-minimum-version": 0,
  "nodes": [
    {
      "name": "local_service",
      "type": "TcpConnector",
      "settings": {
        "address": "127.0.0.1",
        "port": __CONFIG_PORT__,
        "nodelay": true
      }
    },
    {
      "name": "bridge_local",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_reverse"
      },
      "next": "local_service"
    },
    {
      "name": "bridge_reverse",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_local"
      },
      "next": "reverse_client"
    },
    {
      "name": "reverse_client",
      "type": "ReverseClient",
      "settings": {
        "minimum-unused": 64,
        "reverse-secret-length": 640,
        "reverse-secret": "__SECRET__"
      },
      "next": "reality_client"
    },
    {
      "name": "reality_client",
      "type": "RealityClient",
      "settings": {
        "sni": "__SNI__",
        "verify": true,
        "password": "__REALITY_PASS__",
        "algorithm": "chacha20-poly1305"
      },
      "next": "to_iran"
    },
    {
      "name": "to_iran",
      "type": "TcpConnector",
      "settings": {
        "address": "__IRAN_IP__",
        "port": __TUNNEL_PORT__,
        "nodelay": true
      }
    }
  ]
}
WWTPL
  ;;
  hd-iran) cat <<'WWTPL'
{
  "name": "iran-reverse-halfduplex",
  "author": "waterwall-user",
  "config-version": 1,
  "core-minimum-version": 0,
  "nodes": [
    {
      "name": "users_inbound",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": __CONFIG_PORT__,
        "nodelay": true
      },
      "next": "bridge_users"
    },
    {
      "name": "bridge_users",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_reverse"
      }
    },
    {
      "name": "bridge_reverse",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_users"
      }
    },
    {
      "name": "reverse_server",
      "type": "ReverseServer",
      "settings": {
        "reverse-secret-length": 640,
        "reverse-secret": "__SECRET__"
      },
      "next": "bridge_reverse"
    },
    {
      "name": "halfduplex_server",
      "type": "HalfDuplexServer",
      "settings": {},
      "next": "reverse_server"
    },
    {
      "name": "peers_inbound",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": __TUNNEL_PORT__,
        "nodelay": true,
        "whitelist": [
          "__FOREIGN_IP__/32"
        ]
      },
      "next": "halfduplex_server"
    }
  ]
}
WWTPL
  ;;
  hd-foreign) cat <<'WWTPL'
{
  "name": "foreign-reverse-halfduplex",
  "author": "waterwall-user",
  "config-version": 1,
  "core-minimum-version": 0,
  "nodes": [
    {
      "name": "local_service",
      "type": "TcpConnector",
      "settings": {
        "address": "127.0.0.1",
        "port": __CONFIG_PORT__,
        "nodelay": true
      }
    },
    {
      "name": "bridge_local",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_reverse"
      },
      "next": "local_service"
    },
    {
      "name": "bridge_reverse",
      "type": "Bridge",
      "settings": {
        "pair": "bridge_local"
      },
      "next": "reverse_client"
    },
    {
      "name": "reverse_client",
      "type": "ReverseClient",
      "settings": {
        "minimum-unused": 128,
        "reverse-secret-length": 640,
        "reverse-secret": "__SECRET__"
      },
      "next": "halfduplex_client"
    },
    {
      "name": "halfduplex_client",
      "type": "HalfDuplexClient",
      "settings": {},
      "next": "to_iran"
    },
    {
      "name": "to_iran",
      "type": "TcpConnector",
      "settings": {
        "address": "__IRAN_IP__",
        "port": __TUNNEL_PORT__,
        "nodelay": true
      }
    }
  ]
}
WWTPL
  ;;
  esac
}

function ww_tpl_core() { # $1 = iran|foreign
  case "$1" in
  iran) cat <<'WWTPL'
{
  "log": {
    "path": "logs/",
    "core": { "loglevel": "INFO", "file": "core.log", "console": true },
    "network": { "loglevel": "WARN", "file": "network.log", "console": true },
    "dns": { "loglevel": "WARN", "file": "dns.log", "console": false },
    "internal": { "loglevel": "WARN", "file": "internal.log", "console": false }
  },
  "misc": {
    "workers": 2,
    "ram-profile": "server",
    "mtu": 1500,
    "try-enabling-bbr": true,
    "libs-path": "libs/"
  },
  "dns": {
    "domain-strategy": "prefer-ipv4"
  },
  "configs": [
    "configs/reverse-server.json"
  ]
}
WWTPL
  ;;
  foreign) cat <<'WWTPL'
{
  "log": {
    "path": "logs/",
    "core": { "loglevel": "INFO", "file": "core.log", "console": true },
    "network": { "loglevel": "WARN", "file": "network.log", "console": true },
    "dns": { "loglevel": "WARN", "file": "dns.log", "console": false },
    "internal": { "loglevel": "WARN", "file": "internal.log", "console": false }
  },
  "misc": {
    "workers": 2,
    "ram-profile": "client-larger",
    "mtu": 1500,
    "try-enabling-bbr": true,
    "libs-path": "libs/"
  },
  "dns": {
    "domain-strategy": "prefer-ipv4"
  },
  "configs": [
    "configs/reverse-client.json"
  ]
}
WWTPL
  ;;
  esac
}

function ww_tpl_service() { # $1 = iran|foreign
  case "$1" in
  iran) cat <<'WWTPL'
[Unit]
Description=WaterWall tunnel (Iran side)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/waterwall
ExecStart=/opt/waterwall/Waterwall
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
WWTPL
  ;;
  foreign) cat <<'WWTPL'
[Unit]
Description=WaterWall tunnel (foreign side)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/waterwall
ExecStart=/opt/waterwall/Waterwall
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
WWTPL
  ;;
  esac
}


# fills a template: $1=text, then tokens from globals
function ww_fill() {
  local t="$1"
  t="${t//__CONFIG_PORT__/$W_CP}"
  t="${t//__TUNNEL_PORT__/$W_TP}"
  t="${t//__FOREIGN_IP__/$W_FOREIGN_IP}"
  t="${t//__IRAN_IP__/$W_IRAN_IP}"
  t="${t//__SECRET__/$W_SECRET}"
  t="${t//__REALITY_PASS__/$W_REALITY_PASS}"
  t="${t//__SNI__/$W_SNI}"
  printf '%s\n' "$t"
}

function ww_install() {
  echo -e "\n${YELLOW}[*] Setting up Waterwall Tunnel... ${NC}"
  echo ""
  echo -e "${YELLOW}Select Tunnel Type:${NC}"
  echo ""
  echo -e "${YELLOW}1. Reverse TCP${NC}"
  echo -e "${YELLOW}2. Reverse TCP Reality${NC}"
  echo -e "${YELLOW}3. Reverse TCP HalfDuplex${NC}"
  echo ""
  local T KIND
  while true; do
    read -p "$(echo -e "${YELLOW}Choice [1-3]: ${NC}")" T
    [[ "$T" =~ ^[123]$ ]] && break
    echo -e "${RED}Invalid option${NC}"
  done
  case $T in 1) KIND=raw ;; 2) KIND=reality ;; 3) KIND=hd ;; esac
  echo ""
  echo -e "${GREEN} ┇${NC}"; echo -e "${GREEN} ▼${NC}"; echo ""
  local SIDE_N SIDE
  while true; do
    read -p "$(echo -e "${YELLOW}Server Side - Iran = 1 , Foreign = 2 | (e.g. 1): ${NC}")" SIDE_N
    [[ "$SIDE_N" =~ ^[12]$ ]] && break
    echo -e "${RED}Invalid option${NC}"
  done
  if [ "$SIDE_N" = "1" ]; then SIDE=iran; else SIDE=foreign; fi
  echo ""
  echo -e "${GREEN} ┇${NC}"; echo -e "${GREEN} ▼${NC}"; echo ""

  W_TP=""; W_CP=""; W_FOREIGN_IP=""; W_IRAN_IP=""; W_SECRET=""; W_REALITY_PASS=""; W_SNI=""
  ww_ask_port "Tunnel Port (e.g. 8443)" 8443 W_TP
  echo ""
  ww_ask_port "Config Port (e.g. 443)" 443 W_CP
  echo ""
  if [ "$SIDE" = "iran" ]; then
    ww_ask_ip "Foreign Server IP" W_FOREIGN_IP
  else
    ww_ask_ip "Iran Server IP" W_IRAN_IP
  fi
  echo ""
  ww_ask_secret "Tunnel Secret (same on both sides)" W_SECRET
  echo ""
  if [ "$KIND" = "reality" ]; then
    ww_ask_secret "Reality Password (same on both sides)" W_REALITY_PASS
    echo ""
    while true; do
      read -p "$(echo -e "${YELLOW}SNI / Visitor Domain (same on both sides, e.g. www.example.com): ${NC}")" W_SNI
      ww_valid_domain "$W_SNI" && break
      echo -e "${RED}Invalid domain${NC}"
    done
    echo ""
    if [ "$SIDE" = "iran" ]; then
      command -v curl >/dev/null 2>&1 || apt-get install -y curl
      echo -e "${YELLOW}[*] Checking $W_SNI:443 from this server...${NC}"
      if curl -sI --max-time 10 "https://$W_SNI" >/dev/null 2>&1; then
        echo -e "${GREEN}[✓] $W_SNI is reachable${NC}"
      else
        echo -e "${RED}[!] $W_SNI is NOT reachable from this server (Reality handshake will fail)${NC}"
        read -p "$(echo -e "${YELLOW}Continue anyway? [y/N]: ${NC}")" go_on
        [[ "$go_on" =~ ^[Yy]$ ]] || { echo -e "${RED}Aborted${NC}"; return 0; }
      fi
    fi
  fi

  systemctl stop waterwall 2>/dev/null || true
  if [ ! -x "$WW_DIR/Waterwall" ]; then
    if ! ww_install_core; then read -p "Press any key to continue..." -n1; return 1; fi
  else
    mkdir -p "$WW_DIR/configs" "$WW_DIR/logs"
    echo -e "${CYAN}[i] Waterwall core already installed (use 'Update Core' to replace)${NC}"
  fi

  local CFG
  if [ "$SIDE" = "iran" ]; then CFG="reverse-server.json"; rm -f "$WW_DIR/configs/reverse-client.json"
  else CFG="reverse-client.json"; rm -f "$WW_DIR/configs/reverse-server.json"; fi

  ww_fill "$(ww_tpl_core "$SIDE")"            > "$WW_DIR/core.json"
  ww_fill "$(ww_tpl_config "$KIND" "$SIDE")"  > "$WW_DIR/configs/$CFG"
  ww_fill "$(ww_tpl_service "$SIDE")"         > "$WW_SERVICE"
  sed -i "s|^WorkingDirectory=.*|WorkingDirectory=${WW_DIR}|; s|^ExecStart=.*|ExecStart=${WW_DIR}/Waterwall|" "$WW_SERVICE"

  if [ "$SIDE" = "iran" ] && command -v ufw >/dev/null 2>&1; then
    ufw allow from "$W_FOREIGN_IP" to any port "$W_TP" proto tcp >/dev/null 2>&1 || true
    ufw allow "$W_CP"/tcp >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  systemctl enable waterwall
  systemctl start waterwall
  systemctl restart waterwall || echo -e "${RED}Failed To Start Service!${NC}"

  sleep 2
  echo ""
  if systemctl is-active --quiet waterwall; then
    echo -e "${BLUE}✅ Done! Waterwall Tunnel Is Running${NC}"
  else
    echo -e "${RED}❌ Service is not running. Check: journalctl -u waterwall -n 50${NC}"
  fi
  if [ "$SIDE" = "iran" ]; then
    echo -e "${CYAN}[i] Now set up the Foreign side. Then check: ss -tn | grep :$W_TP | wc -l${NC}"
  fi
  read -p "Press any key to continue..." -n1
}

function waterwall_menu() {
  while true; do
    clear
    echo -e "${YELLOW}===============================${NC}"
    echo -e "${YELLOW}       Waterwall Tunnel        ${NC}"
    echo -e "${YELLOW}===============================${NC}"
    echo ""
    echo "1. Install / ReConfig"
    echo "2. Restart"
    echo "3. Stop"
    echo "4. Status"
    echo "5. Logs"
    echo "6. Edit Configs"
    echo "7. Update Core"
    echo "8. Uninstall"
    echo ""
    echo "9. Return"
    echo ""
    read -p "$(echo -e "${YELLOW}Choice: ${NC}")" ww_choice
    case $ww_choice in
      1) ww_install ;;
      2) systemctl daemon-reload && systemctl restart waterwall && echo -e "${BLUE}✅ Service Restarted${NC}" || echo -e "${RED}❌ Failed${NC}"
         read -p "Press any key to continue..." -n1 ;;
      3) systemctl stop waterwall && systemctl disable waterwall
         echo -e "${RED}🛑 Tunnel Stopped${NC}"
         read -p "Press any key to continue..." -n1 ;;
      4) clear; systemctl status waterwall --no-pager
         echo ""
         journalctl -u waterwall -n 10 --no-pager
         read -p "Press any key to continue..." -n1 ;;
      5) echo "Press Ctrl+C to exit logs..."
         trap ':' INT
         journalctl -u waterwall -f
         trap - INT ;;
      6) if ls "$WW_DIR"/configs/*.json >/dev/null 2>&1; then
           for f in "$WW_DIR"/configs/*.json; do nano "$f"; done
           systemctl restart waterwall && echo -e "${BLUE}✅ Edited & Restarted${NC}"
         else
           echo -e "${RED}❌ Config Not Found. Install First${NC}"
         fi
         read -p "Press any key to continue..." -n1 ;;
      7) systemctl stop waterwall 2>/dev/null || true
         ww_install_core && systemctl start waterwall && echo -e "${BLUE}✅ Core Updated ($WW_VERSION)${NC}"
         read -p "Press any key to continue..." -n1 ;;
      8) systemctl stop waterwall 2>/dev/null || true
         systemctl disable waterwall 2>/dev/null || true
         rm -f "$WW_SERVICE"
         cd / && rm -rf "$WW_DIR"
         systemctl daemon-reload || true
         echo -e "${RED}❌ Waterwall Tunnel Uninstalled${NC}"
         read -p "Press any key to continue..." -n1 ;;
      9) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

# ======================= MTU Test + MSS Clamp =======================
# NOTE: mtu_search / mss_helper_text / mss_install_local / mss_remove_local are self-contained
# (no script variables) because they are also sent to the other server over ssh.

# Largest packet size (MTU) that passes with DF set. Every ping is shown live (stderr),
# the final number (or FAIL if ICMP does not work at all) is printed on stdout.
# About 50-60 probes: binary search (5 packets per step) + 10 packets to measure loss at the final size.
function mtu_search() {
  local target="$1" lo=548 hi=1472 mid best=0 n=5
  # mtu_try SIZE COUNT : live output; returns 0 if at least one reply came back
  mtu_try() {
    local sz="$1" cnt="$2" got=0 line
    echo "  -- packet size $((sz+28)) (payload $sz), $cnt pings:" >&2
    while IFS= read -r line; do
      case "$line" in
        *"bytes from"*) got=$((got+1)); echo "       reply  time=${line##*time=}" >&2 ;;
        *"transmitted"*|"") ;;
        PING*|---*|rtt*|round-trip*) ;;
        *) echo "       $line" >&2 ;;
      esac
    done < <(ping -n -M do -c "$cnt" -i 0.2 -W 2 -s "$sz" "$target" </dev/null 2>&1)
    echo "       => $got/$cnt replies" >&2
    MTU_LAST_GOT=$got
    [ "$got" -ge 1 ]
  }
  echo "  target: $target   (smallest size first, then binary search)" >&2
  if ! mtu_try "$lo" "$n"; then echo "FAIL"; return 1; fi
  best=$lo; lo=$((lo+1))
  while [ "$lo" -le "$hi" ]; do
    mid=$(( (lo+hi)/2 ))
    if mtu_try "$mid" "$n"; then best=$mid; lo=$((mid+1)); else hi=$((mid-1)); fi
  done
  echo "  -- verification at the final size ($((best+28))):" >&2
  mtu_try "$best" 10 || true
  [ "${MTU_LAST_GOT:-0}" -lt 8 ] && echo "  [!] packet loss at the final size: $((10-MTU_LAST_GOT))/10 lost" >&2
  local ifc ifm
  ifc=$(ip route get "$target" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  ifm=$(cat "/sys/class/net/$ifc/mtu" 2>/dev/null)
  if [ -n "$ifm" ] && [ $((best+28)) -ge "$ifm" ]; then
    echo "  [i] the result equals this server's interface MTU ($ifm): ping cannot send bigger packets than that, so the real path may allow more." >&2
  fi
  echo $((best+28))
}

# Rendezvous without ssh: one side waits (listen), the other connects. Prints the peer's message.
# mtu_exchange listen|connect PEER_IP PORT MESSAGE
function mtu_exchange() {
  python3 - "$@" <<'PYEOF'
import socket, sys, time, re
role, peer, port, msg = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
deadline = time.time() + 600
if role == "listen":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(5)
    while time.time() < deadline:
        s.settimeout(max(1, deadline - time.time()))
        try:
            c, a = s.accept()
        except socket.timeout:
            break
        if a[0] != peer:
            sys.stderr.write("  (ignored a connection from %s - not the IP you entered)\n" % a[0]); c.close(); continue
        try:
            c.settimeout(15); d = c.recv(256).decode().strip(); c.sendall((msg + "\n").encode()); c.close()
            if re.fullmatch(r"[A-Za-z0-9]{1,16}", d): print(d); sys.exit(0)
        except Exception:
            continue
    sys.exit(1)
else:
    while time.time() < deadline:
        try:
            c = socket.create_connection((peer, port), timeout=5); c.settimeout(15)
            c.sendall((msg + "\n").encode()); d = c.recv(256).decode().strip(); c.close()
            if re.fullmatch(r"[A-Za-z0-9]{1,16}", d): print(d); sys.exit(0)
        except Exception:
            pass
        time.sleep(2)
    sys.exit(1)
PYEOF
}

function mss_helper_text() {
cat <<'HEOF'
#!/bin/sh
# Server Tools - MSS clamp helper (apply at boot / clear)
CONF=/etc/server-tools-mss.conf
[ -f "$CONF" ] && . "$CONF"
clear_rules() {
  iptables -t mangle -S POSTROUTING 2>/dev/null | grep -- 'server-tools-mss' | sed 's/^-A /-D /' | while read -r r; do iptables -t mangle $r 2>/dev/null; done
}
case "$1" in
  apply)
    [ -n "$MSS" ] || exit 1
    clear_rules
    # only lowers the MSS (never raises a smaller one); falls back to the plain rule if xt_tcpmss is missing
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss "$((MSS+1)):65535" -m comment --comment server-tools-mss -j TCPMSS --set-mss "$MSS" 2>/dev/null \
      || iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -m comment --comment server-tools-mss -j TCPMSS --set-mss "$MSS" || exit 1
    if [ -n "$IFACE" ] && [ -n "$IFMTU" ]; then ip link set dev "$IFACE" mtu "$IFMTU" || exit 1; fi
    ;;
  clear)
    clear_rules
    if [ -n "$IFACE" ] && [ -n "$ORIG_MTU" ]; then ip link set dev "$IFACE" mtu "$ORIG_MTU" 2>/dev/null; fi
    ;;
esac
exit 0
HEOF
}

# MSS = MTU - 52 (20 IP + 20 TCP + 12 timestamp); interface MTU = MSS + 52 = the measured path MTU
# mss_install_local MSS [IFACE|auto] [IFACE_MTU]
function mss_install_local() {
  local mss="$1" iface="${2:-}" ifmtu="${3:-}" orig=""
  local conf=/etc/server-tools-mss.conf helper=/usr/local/sbin/server-tools-mss unit=/etc/systemd/system/server-tools-mss.service
  if ! command -v iptables >/dev/null 2>&1; then apt-get install -y iptables >/dev/null 2>&1 || { echo "iptables is not installed and could not be installed"; return 1; }; fi
  if [ -n "$ifmtu" ]; then
    if [ "$iface" = "auto" ]; then iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'); fi
    [ -n "$iface" ] || { echo "could not detect the network interface"; return 1; }
    # keep the very first original MTU if we already changed this interface before
    if [ -f "$conf" ]; then orig=$(. "$conf"; [ "$IFACE" = "$iface" ] && echo "$ORIG_MTU"); fi
    [ -n "$orig" ] || orig=$(cat "/sys/class/net/$iface/mtu" 2>/dev/null)
  else
    iface=""
  fi
  { echo "MSS=$mss"; echo "IFACE=$iface"; echo "IFMTU=$ifmtu"; echo "ORIG_MTU=$orig"; } > "$conf"
  mss_helper_text > "$helper"; chmod +x "$helper"
  cat > "$unit" <<UEOF
[Unit]
Description=Server Tools MSS clamp
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$helper apply
ExecStop=$helper clear

[Install]
WantedBy=multi-user.target
UEOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable server-tools-mss >/dev/null 2>&1 || true
  "$helper" apply || { echo "applying the iptables rule failed"; return 1; }
  if iptables -t mangle -S POSTROUTING 2>/dev/null | grep -q 'server-tools-mss'; then
    echo "OK: MSS clamp $mss active$( [ -n "$ifmtu" ] && echo ", $iface MTU = $ifmtu" ) (persistent after reboot)"
  else
    echo "rule not found after applying"; return 1
  fi
}

function mss_remove_local() {
  local helper=/usr/local/sbin/server-tools-mss
  [ -x "$helper" ] && "$helper" clear
  systemctl disable server-tools-mss >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/server-tools-mss.service /etc/server-tools-mss.conf "$helper"
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "OK: MSS clamp removed (interface MTU restored if it was changed by this tool)"
}

function mss_status() {
  echo -e "\n${YELLOW}[*] Current state${NC}"
  if [ -f /etc/server-tools-mss.conf ]; then
    echo -e "${CYAN}Saved config:${NC}"; sed 's/^/   /' /etc/server-tools-mss.conf
  else
    echo "   (no clamp configured by this tool)"
  fi
  echo -e "${CYAN}iptables TCPMSS rules (mangle/POSTROUTING):${NC}"
  iptables -t mangle -S POSTROUTING 2>/dev/null | grep TCPMSS | sed 's/^/   /' || true
  local ifc; ifc=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  [ -n "$ifc" ] && echo -e "${CYAN}Interface $ifc MTU:${NC} $(cat /sys/class/net/$ifc/mtu 2>/dev/null)"
}

function mtu_test_and_apply() {
  local R_IP in ROLE role fwd rev mtu mss R_PORT="${MTU_PORT:-5201}"
  echo -e "\n${YELLOW}[*] MTU test between 2 servers${NC}"
  command -v python3 >/dev/null 2>&1 || { echo -e "${RED}python3 is required (apt-get install -y python3)${NC}"; sleep 2; return; }
  while true; do
    read -r -p "$(echo -e "${YELLOW}Other server IP: ${NC}")" R_IP
    ww_valid_ip "$R_IP" && break
    echo -e "${RED}Invalid IP${NC}"
  done
  echo -e "  ${CYAN}1)${NC} Direct"
  echo -e "  ${CYAN}2)${NC} Reverse"
  read -r -p "$(echo -e "${YELLOW}Choice: ${NC}")" ROLE
  case "$ROLE" in
    1) role=listen;  echo -e "${YELLOW}[*] Waiting for the other server ($R_IP) ... run this option there and choose Reverse${NC}" ;;
    2) role=connect; echo -e "${YELLOW}[*] Connecting to the other server ($R_IP) ... run this option there and choose Direct${NC}" ;;
    *) echo "Invalid option"; sleep 1; return ;;
  esac
  if [ "$(mtu_exchange "$role" "$R_IP" "$R_PORT" ready)" != "ready" ]; then
    echo -e "${RED}[!] The other server did not connect (check the IP and that TCP port $R_PORT is open on the Direct server).${NC}"; sleep 2; return
  fi
  echo -e "${GREEN}[✓] Connected. Testing ${SERVER_IP} -> ${R_IP}${NC}"
  fwd=$(mtu_search "$R_IP" | tail -n1)
  echo -e "    result: ${CYAN}${fwd}${NC}"
  echo -e "${YELLOW}[*] Getting the result of the other server ...${NC}"
  rev=$(mtu_exchange "$role" "$R_IP" "$R_PORT" "$fwd")
  [[ "$rev" =~ ^[0-9]+$ ]] || rev="FAIL"

  mtu=""
  if [[ "$fwd" =~ ^[0-9]+$ ]] && [[ "$rev" =~ ^[0-9]+$ ]]; then
    mtu=$(( fwd < rev ? fwd : rev ))
  elif [[ "$fwd" =~ ^[0-9]+$ ]]; then
    mtu="$fwd"; echo -e "${YELLOW}[!] Other server's result unavailable; using this server's result only.${NC}"
  elif [[ "$rev" =~ ^[0-9]+$ ]]; then
    mtu="$rev"; echo -e "${YELLOW}[!] This server's test failed; using the other server's result only.${NC}"
  fi

  if [ -n "$mtu" ]; then
    mss=$((mtu-52))
    echo ""
    echo -e "${CYAN}  ${SERVER_IP} -> ${R_IP} : ${fwd}${NC}"
    echo -e "${CYAN}  ${R_IP} -> ${SERVER_IP} : ${rev}${NC}"
    echo -e "${GREEN}  Suitable MTU = ${mtu}   (MSS = ${mss} = MTU - 52: 40 header + 12 TCP timestamp)${NC}"
  else
    echo -e "${RED}[!] ICMP ping did not work in either direction, so the MTU cannot be measured.${NC}"
    echo -e "${YELLOW}    Safe values: 1360 (common), 1280 (very conservative).${NC}"
    mss=""
  fi

  read -r -p "$(echo -e "${YELLOW}Set MSS ${mss:+[${mss}]}? Enter = ${mss:+yes}, type another number, n = cancel: ${NC}")" in
  case "$in" in
    n|N) echo "Cancelled."; sleep 1; return ;;
    "") [ -n "$mss" ] || { echo "No value."; sleep 1; return; } ;;
    *) mss="$in" ;;
  esac
  if ! [[ "$mss" =~ ^[0-9]+$ ]] || [ "$mss" -lt 500 ] || [ "$mss" -gt 1460 ]; then
    echo -e "${RED}Invalid MSS (allowed 500-1460)${NC}"; sleep 1; return
  fi
  local ifmtu=""
  read -r -p "$(echo -e "${YELLOW}Also set the interface MTU to $((mss+52)) on this server? [y/N]: ${NC}")" in
  [[ "$in" =~ ^[yY]$ ]] && ifmtu=$((mss+52))

  echo -e "${YELLOW}[*] Applying on this server...${NC}"
  if mss_install_local "$mss" auto "$ifmtu"; then echo -e "${GREEN}[✓] Done on this server${NC}"; else echo -e "${RED}[!] Failed on this server${NC}"; fi
  echo -e "${YELLOW}[i] Confirm the same on the other server too (it shows the same numbers).${NC}"
  read -n 1 -s -r -p $'\033[1;35m\n[✓] Press any key to return\033[0m'
}

function mtu_tool_menu() {
  while true; do
    clear
    echo -e "${YELLOW}========== MTU Test + MSS Clamp ==========${NC}"
    echo -e "${CYAN}1)${NC} Test MTU between 2 servers (Direct + Reverse) and apply"
    echo -e "${CYAN}2)${NC} Show current MSS / MTU state"
    echo -e "${CYAN}3)${NC} Set MSS manually (this server only)"
    echo -e "${CYAN}4)${NC} Remove MSS clamp / restore MTU (this server)"
    echo -e "${CYAN}0)${NC} Back"
    echo ""
    read -r -p "$(echo -e "${YELLOW}Choice: ${NC}")" c
    case $c in
      1) mtu_test_and_apply ;;
      2) mss_status; read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m' ;;
      3) local v; read -r -p "MSS (500-1460): " v
         if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 500 ] && [ "$v" -le 1460 ]; then mss_install_local "$v"; else echo -e "${RED}Invalid${NC}"; fi
         read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m' ;;
      4) mss_remove_local; read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m' ;;
      0) return ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

# --- Main Menu ---
function main_menu() {
  while true; do
    clear
    echo -e "${YELLOW}===========================================${NC}"
    echo -e "${YELLOW}             Server Tools Menu       ${NC}"
    echo -e "${YELLOW}              Version : $VERSION       ${NC}"
    echo -e "${YELLOW}===========================================${NC}"
    echo -e "${BLUE}         Server IP : ${BLUE}$SERVER_IP${NC}"
    echo -e "${YELLOW}===========================================${NC}"
    echo ""
    echo -e "${CYAN}1)${NC} Setup Firewall (For Hetzner Abuse)"
    echo -e "${CYAN}2)${NC} Optimize Network"
    echo -e "${CYAN}3)${NC} Change SSH Port"
    echo -e "${CYAN}4)${NC} Change Root Password"
    echo -e "${CYAN}5)${NC} Backhual Tunnel (Premium)"
    echo -e "${CYAN}6)${NC} GOST Tunnel (Relay + WSS + MUX)"
    echo -e "${CYAN}7)${NC} Lena Tunnel"
    echo -e "${CYAN}8)${NC} SSH Tunnel + Encryption (Just Iran Side)"
    echo -e "${CYAN}9)${NC} Pasarguard Node"
    echo -e "${CYAN}10)${NC} Enable Root Login"
    echo -e "${CYAN}11)${NC} Change DNS"
    echo -e "${CYAN}12)${NC} Waterwall Tunnel (New)"
    echo -e "${CYAN}13)${NC} MTU Test + MSS Clamp"
    echo -e "${CYAN}0)${NC} Exit"
    echo ""
    echo -e "${YELLOW}===========================================${NC}"
    echo ""
    read -p "$(echo -e "${YELLOW}Choice: ${NC}")" choice
    echo ""

    case $choice in
      1) setup_firewall ;;
      2) optimize_network ;;
      3) change_ssh_port ;;
      4) change_root_password ;;
      5) Backhual ;;
      6) GostMenu ;;
      7) lena_tunnel ;;
      8) ssh_tunnel_menu ;;
      9) pasarguard_node_menu ;;
      10) enable_root_login ;;
      11) change_dns ;;
      12) waterwall_menu ;;
      13) mtu_tool_menu ;;
      0) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

main_menu
