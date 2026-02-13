#!/bin/bash
VERSION="0.3.3"
SERVER_IP=$(hostname -I | awk '{print $1}')

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'

set -e

# --- 11. Pasarguard Node Function ---
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
    read -p "Select an option [1-4]: " pg_choice

    case $pg_choice in
      1)
        echo -e "${YELLOW}[*] Preparing Assets... ${NC}"
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

# --- 10. SSH Tunnel Function ---
function ssh_tunnel_menu() {
  while true; do
    clear
    echo -e "${YELLOW}===============================${NC}"
    echo -e "${YELLOW}         SSH-Tunnel Menu           ${NC}"
    echo -e "${YELLOW}===============================${NC}"
    echo ""
    echo "1. Install / ReConfig"
    echo "2. Restart"
    echo "3. Disable"
    echo "4. Edit"
    echo "5. Uninstall"
    echo "6. Status"
    echo ""
    echo "7. Return"
    echo ""
    read -p "$(echo -e "${YELLOW}Choice: ${NC}")" ash_choice
    echo ""
case $ash_choice in

      1)
        echo -e "\n${YELLOW}[*] Setting up AutoSSH... ${NC}"
        echo ""
        read -p "$(echo -e "${YELLOW}Foreign IP: ${NC}")" FOREIGN_IP
        echo ""
        read -p "$(echo -e "${YELLOW}Foreign SSH Port (e.g., 22): ${NC}")" REMOTE_SSH_PORT
        echo ""
        read -p "$(echo -e "${YELLOW}Config Port (e.g., 2083): ${NC}")" CONFIG_PORT
        echo ""

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
    -o "Ciphers=chacha20-poly1305@openssh.com" \\
    -o "Compression=yes" \\
    -o "KbdInteractiveAuthentication=no" \\
    -o "PreferredAuthentications=publickey" \\
    -o "ServerAliveInterval 25" \\
    -o "ServerAliveCountMax 3" \\
    -o "TCPKeepAlive=no" \\
    -o "ExitOnForwardFailure=yes" \\
    -p ${REMOTE_SSH_PORT} -L 0.0.0.0:${CONFIG_PORT}:127.0.0.1:${CONFIG_PORT} root@${FOREIGN_IP}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        
        if [ ! -f ~/.ssh/id_rsa ]; then
            ssh-keygen -t rsa -b 2048 -N "" -f ~/.ssh/id_rsa
        fi
        
        echo -e "${YELLOW}[*] Attempting To Copy SSH Key... (Enter Password If Asked)${NC}"
        ssh-copy-id -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -p ${REMOTE_SSH_PORT} root@${FOREIGN_IP} || echo -e "${RED}Warning: Could not copy SSH key!${NC}"
        
        systemctl daemon-reload
        systemctl enable ssh-tunnel
        systemctl start ssh-tunnel
        systemctl restart ssh-tunnel || echo -e "${RED}Failed To Start Service!${NC}"
        
        echo -e "${BLUE}✅ Done! SSH-Tunnel Is Running${NC}"
        read -n 1 -s -r -p $'\nPress any key to return...'
        ;;
        
      2) systemctl daemon-reload && systemctl restart ssh-tunnel; echo -e "${GREEN}[✓] Service Restarted ${NC}"; sleep 1 ;;
      3) systemctl stop ssh-tunnel && systemctl disable ssh-tunnel; echo -e "${GREEN}[✓] Tunnel Stopped ${NC}"; sleep 1 ;;
      4) 
        if [ -f /etc/systemd/system/ssh-tunnel.service ]; then
            nano /etc/systemd/system/ssh-tunnel.service
            systemctl daemon-reload && systemctl restart ssh-tunnel
        else
            echo -e "${RED}[!] Service Not Found ${NC}"; sleep 2
        fi ;;
      5)
        echo -e "\n${RED}[*] Uninstalling... ${NC}"
        systemctl stop ssh-tunnel.service 2>/dev/null || true
        systemctl disable ssh-tunnel.service 2>/dev/null || true
        
        rm -f /etc/systemd/system/ssh-tunnel.service || true
  
        systemctl daemon-reload || true
        echo -e "${GREEN}[✓] Done ${NC}"; sleep 2 
        ;;
      6) 
        systemctl status ssh-tunnel --no-pager
        read -n 1 -s -r -p $'\nPress any key to return...' ;;
      7) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
    done
} 
# --- 01. Setup Firewall ---
function setup_firewall() {
  echo -e "\n\033[1;33m[*] Setting up Firewall...\033[0m"
  apt install ufw -y
  PORTS=(ssh http https 53/tcp 53/udp 80/tcp 80/udp 2020/tcp 2020/udp 443/tcp 443/udp 8000/tcp 8000/udp 57160/tcp 57160/udp 5629/tcp 5629/udp 1080/tcp 1080/udp 3478/tcp 3478/udp 2096/tcp 2096/udp 3832/tcp 3832/udp 8081/tcp 8081/udp 8082/tcp 8082/udp 2095/tcp 2095/udp 25349/tcp 25349/udp 10000/tcp 10000/udp 11000/tcp 11000/udp 11100/tcp 11100/udp 11200/tcp 11200/udp 11300/tcp 11300/udp 11400/tcp 11400/udp 11500/tcp 11500/udp 11600/tcp 11600/udp 21653/tcp 21653/udp 21652/tcp 21652/udp 14848/tcp 14848/udp 55150/tcp 55150/udp 55151/tcp 55151/udp 55250/tcp 55250/udp 55251/tcp 55251/udp 55350/tcp 55350/udp 55351/tcp 55351/udp 55450/tcp 55450/udp 55451/tcp 55451/udp 55550/tcp 55550/udp 55551/tcp 55551/udp 55650/tcp 55650/udp 55651/tcp 55651/udp 55750/tcp 55750/udp 55751/tcp 55751/udp 55850/tcp 55850/udp 55851/tcp 55851/udp 55950/tcp 55950/udp 55951/tcp 55951/udp 56050/tcp 56050/udp 56051/tcp 56051/udp 5666/tcp 5666/udp 2083/tcp 2083/udp 5201/tcp 5201/udp 8880/tcp 8880/udp 2087/tcp 2087/udp)
  for port in "${PORTS[@]}"; do ufw allow "$port"; done
  BLOCKED_SUBNETS=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 173.245.0.0/16 141.101.0.0/16 240.0.0.0/4 25.10.40.0/24 25.11.10.0/24 103.58.50.0/24 195.137.167.0/24 45.14.174.0/24 206.191.152.0/24 216.218.185.0/24 114.208.187.0/24 185.235.87.0/24 185.235.86.0/24 102.0.0.0/8 233.252.0.0/24 224.0.0.0/4 240.0.0.0/24 203.0.113.0/24 198.51.100.0/24 198.18.0.0/15 192.88.99.0/24 192.0.2.0/24 192.0.0.0/24 102.224.45.0/24)
  for subnet in "${BLOCKED_SUBNETS[@]}"; do ufw deny out from any to "$subnet"; done
  echo "y" | sudo ufw enable
  read -n 1 -s -r -p $'\033[1;35m\n[✓] Done. Press any key to return\033[0m'
}

function install_bbr() {
  echo "Optimizing network with BBR..."
  if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  fi
  if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  fi
  sysctl -p
  echo "BBR Optimization Applied Successfully!"
  read -n 1 -s -r -p $'\nPress any key to return'
}

function optimize_network() {
  keys=("net.ipv4.tcp_keepalive_time" "net.ipv4.tcp_keepalive_intvl" "net.ipv4.tcp_keepalive_probes" "net.ipv4.tcp_fastopen" "net.ipv4.tcp_slow_start_after_idle" "net.ipv4.tcp_mtu_probing")
  for key in "${keys[@]}"; do
    case $key in net.ipv4.tcp_keepalive_time) v=30;; net.ipv4.tcp_keepalive_intvl) v=10;; net.ipv4.tcp_keepalive_probes) v=3;; net.ipv4.tcp_fastopen) v=3;; net.ipv4.tcp_slow_start_after_idle) v=0;; net.ipv4.tcp_mtu_probing) v=1;; esac
    grep -q "^$key" /etc/sysctl.conf && sed -i "s|^$key.*|$key = $v|" /etc/sysctl.conf || echo "$key = $v" | sudo tee -a /etc/sysctl.conf
  done
  sudo sysctl -p > /dev/null
  read -n 1 -s -r -p $'\n[✓] Optimization Applied. Press any key'
}

function change_ssh_port() {
    echo -e "\n${YELLOW}[*] Changing SSH Port... ${NC}"
    read -p "Enter New SSH Port: " NEW_PORT

    if [[ "$NEW_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -gt 0 ]; then

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

        echo -e "${YELLOW}[*] Restarting SSH service...${NC}"
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            echo -e "${GREEN}[✓] SSH Port Successfully Changed To $NEW_PORT ${NC}"
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
    
    read -p "Set a Password for Root user: " ROOT_PASS

    if [ -n "$ROOT_PASS" ]; then
        echo -e "$ROOT_PASS\n$ROOT_PASS" | sudo passwd root > /dev/null 2>&1
        
        sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        
        sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        
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
    
    # استفاده از -s برای اینکه پسورد موقع تایپ دیده نشود
    read -p "Enter New Root Password: " USER_PASS
    echo -e "\n"

    if [ -n "$USER_PASS" ]; then
        echo -e "$USER_PASS\n$USER_PASS" | passwd root > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] Password Successfully Changed ${NC}"
        else
            echo -e "${RED}[!] Error: Could Not Change Password ${NC}"
        fi
    else
        echo -e "${RED}[!] Password Cannot Be Empty! ${NC}"
    fi

    read -n 1 -s -r -p $'\nPress any key to return...'
}

# --- 06. Marzban Node ---
function install_marzban_node() {
  while true; do
    clear
    echo "==============================="
    echo "       Marzban-node Menu       "
    echo "==============================="
    echo "1. Install ⬇️"
    echo "2. Restart ♻️"
    echo "3. Update Core"
    echo "4. Return 🔙"
    read -p "Select choice: " marzban_choice
    case $marzban_choice in
      1)
        apt update && apt upgrade -y && apt install socat curl git -y
        mkdir -p /var/lib/marzban-node/assets/
        wget -O /var/lib/marzban-node/assets/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
        wget -O /var/lib/marzban-node/assets/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
        wget -O /var/lib/marzban-node/assets/iran.dat https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat
        git clone https://github.com/Gozargah/Marzban-node && cd Marzban-node
        curl -fsSL https://get.docker.com | sh
        cat > docker-compose.yml <<EOF
services:
  marzban-node:
    image: gozargah/marzban-node:latest
    restart: always
    network_mode: host
    environment:
      SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/ssl_client_cert.pem"
      XRAY_EXECUTABLE_PATH: "/var/lib/marzban/xray-core/xray"
      SERVICE_PROTOCOL: "rest"
      SERVICE_PORT: 40050
      XRAY_API_PORT: 40051
    volumes:
      - /var/lib/marzban:/var/lib/marzban
      - /var/lib/marzban-node:/var/lib/marzban-node
      - /var/lib/marzban-node/assets:/usr/local/share/xray
EOF
        mkdir -p /var/lib/marzban/xray-core && cd /var/lib/marzban/xray-core
        wget https://github.com/XTLS/Xray-core/releases/download/v25.3.6/Xray-linux-64.zip
        apt install unzip -y && unzip Xray-linux-64.zip && rm Xray-linux-64.zip
        cd ~/Marzban-node && docker compose down && docker compose up -d
        read -p "Done. Press any key..." -n1 ;;
      2) cd ~/Marzban-node && docker compose down && docker compose up -d; read -p "Restarted..." -n1 ;;
      3) cd ~/Marzban-node && docker compose down && rm -rf /var/lib/marzban/xray-core
         mkdir -p /var/lib/marzban/xray-core && cd /var/lib/marzban/xray-core
         wget https://github.com/XTLS/xray-core/releases/latest/download/Xray-linux-64.zip
         unzip Xray-linux-64.zip && rm Xray-linux-64.zip
         cd ~/Marzban-node && docker compose up -d; read -p "Updated..." -n1 ;;
      4) break ;;
    esac
  done
}

# --- 07. Backhaul ---
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
      1) rm -rf /tmp/my-uploads && git clone https://github.com/Alighaemi9731/backhaul.git /tmp/my-uploads
         mkdir -p /opt/utunnel && mv /tmp/my-uploads/utunnel /opt/utunnel/utunnel
         mv /tmp/my-uploads/utunnel_manager /root/utunnel_manager && chmod +x /root/utunnel_manager; read -p "Done..." -n1 ;;
      2) /root/utunnel_manager ;;
      3) sudo systemctl restart utunnel_king; read -p "Restarted..." -n1 ;;
      4) break ;;
    esac
  done
}

# --- 08. Gost ---
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
    echo "7. Restart Timer"
    echo "8. Show Logs"
    echo ""
    echo "9. Return"
    echo ""
    
    read -p "$(echo -e "${YELLOW}Choice: ${NC}")" gost_choice
    echo ""
    case $gost_choice in
    
      1) if systemctl list-unit-files | grep -q gost.service; then sudo systemctl stop gost || true; fi
         rm -rf /usr/local/bin/gost && wget https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_amd64.tar.gz
         mkdir -p /usr/local/bin/gost && tar -xvzf gost_3.2.6_linux_amd64.tar.gz -C /usr/local/bin/gost/
         
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
                
                export DOMAIN="$G_DOMAIN"
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
         sudo systemctl status gost
         echo "---------------------------"
         read -p "Press any key to continue..." -n1 ;;

      6) sudo systemctl stop gost && sudo systemctl disable gost
         sudo rm /usr/lib/systemd/system/gost.service
         sudo rm -rf /usr/local/bin/gost
         sudo systemctl daemon-reload
         crontab -l 2>/dev/null | grep -v "systemctl restart ssh-tunnel" | crontab -
         echo -e "${RED}❌ Gost Uninstalled Successfully${NC}"
         read -p "Press any key to continue..." -n1 ;;
      7)
        echo -e "\n${YELLOW}[*] Configure Auto Restart Timer${NC}"
        echo "Enter Interval In Hours (e.g., 1h, 2h, 5h)."
        echo "Enter '0' to disable the timer."
        echo ""
        read -p "$(echo -e "${YELLOW}Interval: ${NC}")" timer_input
        
        hours=$(echo "$timer_input" | tr -dc '0-9')
        
        if [[ -z "$hours" ]]; then
            echo -e "${RED}Invalid Input! Please enter A Number${NC}"
            sleep 2
        elif [[ "$hours" -eq 0 ]]; then
            (crontab -l 2>/dev/null | grep -v "systemctl restart ssh-tunnel") | crontab -
            echo -e "${RED}🛑 Auto Restart Timer Disabled${NC}"
            sleep 2
        else
            (crontab -l 2>/dev/null | grep -v "systemctl restart ssh-tunnel") > /tmp/cron_temp
            
            echo "0 */$hours * * * systemctl restart ssh-tunnel" >> /tmp/cron_temp
            
            crontab /tmp/cron_temp
            rm /tmp/cron_temp
            echo -e "${BLUE}✅ Timer Set! Service Will Restart Every $hours Hour(s)${NC}"
            sleep 2
        fi
        ;;
      8) clear
         echo "Press Ctrl+C to exit logs..."
         journalctl -u gost -f ;;
         
      9) break ;;
    esac
  done
}

# --- 09. Lena ---
function lena_tunnel() {
  bash <(curl -Ls https://raw.githubusercontent.com/MrAminiDev/LenaTunnel/main/install.sh)
  read -n 1 -s -r -p $'\nDone. Press any key...'
}

# --- Main Menu ---
function main_menu() {
  while true; do
    clear
    echo -e "${YELLOW}===========================================${NC}"
    echo -e "${YELLOW}              Server Tools Menu       ${NC}"
    echo -e "${YELLOW}               Version : $VERSION       ${NC}"
    echo -e "${YELLOW}===========================================${NC}"
    echo -e "${PURPLE}         Server IP : ${BLUE}$SERVER_IP${NC}"
    echo -e "${YELLOW}===========================================${NC}"
    echo ""
    echo -e "${CYAN}1)${NC} Setup Firewall"
    echo -e "${CYAN}2)${NC} Install BBR"
    echo -e "${CYAN}3)${NC} Optimize Network"
    echo -e "${CYAN}4)${NC} Change SSH Port"
    echo -e "${CYAN}5)${NC} Change Root Password"
    echo -e "${CYAN}6)${NC} Marzban Node"
    echo -e "${CYAN}7)${NC} Backhual Tunnel (Premium)"
    echo -e "${CYAN}8)${NC} GOST Tunnel (Relay + WSS + MUX)"
    echo -e "${CYAN}9)${NC} Lena Tunnel"
    echo -e "${CYAN}10)${NC} Auto "SSH + AES128-CTR + Mux" Tunnel (Just Iran Side)"
    echo -e "${CYAN}11)${NC} Pasarguard Node"
    echo -e "${CYAN}12)${NC} Enable Root Login"
    echo -e "${CYAN}0)${NC} Exit"
    echo ""
    echo -e "${YELLOW}===========================================${NC}"
    read -p "Enter your choice: " choice

    case $choice in
      1) setup_firewall ;;
      2) install_bbr ;;
      3) optimize_network ;;
      4) change_ssh_port ;;
      5) change_root_password ;;
      6) install_marzban_node ;;
      7) Backhual ;;
      8) GostMenu ;;
      9) lena_tunnel ;;
      10) ssh_tunnel_menu ;;
      11) pasarguard_node_menu ;;
      12) enable_root_login ;;
      0|0) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

main_menu
