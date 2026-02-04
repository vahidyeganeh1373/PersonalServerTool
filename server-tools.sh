#!/bin/bash
VERSION="1.1.0"
SERVER_IP=$(hostname -I | awk '{print $1}')

# Colors used in your script style
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'

set -e

# --- New Function: Auto SSH Tunnel ---
function auto_ssh_tunnel_menu() {
  while true; do
    clear
    echo "==============================="
    echo -e "${PURPLE}       Auto SSH Tunnel        ${NC}"
    echo "==============================="
    echo "1. Install ⬇️"
    echo "2. Enable / Restart ♻️"
    echo "3. Disable ⛔"
    echo "4. Status 📊"
    echo "5. Return 🔙"
    echo "-------------------------------"
    read -p "Select an option [1-5]: " ash_choice

    case $ash_choice in
      1)
        echo -e "\n${YELLOW}[*] Setting up AutoSSH Tunnel...${NC}"
        read -p "Foreign IP: " FOREIGN_IP
        read -p "Config Port: " CONFIG_PORT
        
        apt update && apt install -y autossh

        echo -e "${YELLOW}[*] Creating service file...${NC}"
        cat <<EOF | sudo tee /etc/systemd/system/ssh-tunnel.service > /dev/null
[Unit]
Description=AutoSSH Tunnel
After=network.target

[Service]
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -o "ExitOnForwardFailure=yes" -o "StrictHostKeyChecking=no" -N -L 0.0.0.0:${CONFIG_PORT}:localhost:${CONFIG_PORT} root@${FOREIGN_IP}
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

        echo -e "${YELLOW}[*] Generating SSH Key (Please follow prompts)...${NC}"
        ssh-keygen -t rsa
        
        echo -e "${YELLOW}[*] Copying Key to root@${FOREIGN_IP}...${NC}"
        ssh-copy-id root@${FOREIGN_IP}

        sudo systemctl daemon-reload
        sudo systemctl enable ssh-tunnel
        sudo systemctl restart ssh-tunnel
        sudo systemctl status ssh-tunnel
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      2)
        echo -e "${YELLOW}[*] Restarting Tunnel...${NC}"
        sudo systemctl daemon-reload
        sudo systemctl restart ssh-tunnel
        echo -e "${GREEN}[✓] Success.${NC}"
        sleep 1
        ;;
      3)
        echo -e "${RED}[*] Disabling Tunnel...${NC}"
        sudo systemctl stop ssh-tunnel
        sudo systemctl disable ssh-tunnel
        echo -e "${GREEN}[✓] Tunnel stopped.${NC}"
        sleep 1
        ;;
      4)
        echo -e "${CYAN}[*] Tunnel Status:${NC}"
        sudo systemctl status ssh-tunnel
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      5)
        break
        ;;
      *)
        echo -e "${RED}Invalid option!${NC}"
        sleep 1
        ;;
    esac
  done
}

# --- Existing Functions ---

function setup_firewall() {
  echo ""
  echo -e "\033[1;33m[*] Setting up...\033[0m"
  echo ""
  
  PORTS=(
    ssh http https 53/tcp 53/udp 80/tcp 80/udp 2020/tcp 2020/udp
    443/tcp 443/udp 8000/tcp 8000/udp 57160/tcp 57160/udp 5629/tcp 5629/udp
    1080/tcp 1080/udp 2111/tcp 2111/udp 2096/tcp 2096/udp 3832/tcp 3832/udp
    8081/tcp 8081/udp 8082/tcp 8082/udp 2095/tcp 2095/udp 25349/tcp 25349/udp
    10000/tcp 10000/udp 11000/tcp 11000/udp 11100/tcp 11100/udp 11200/tcp 11200/udp
    11300/tcp 11300/udp 11400/tcp 11400/udp 11500/tcp 11500/udp 11600/tcp 11600/udp
    21653/tcp 21653/udp 21652/tcp 21652/udp 14848/tcp 14848/udp
    55150/tcp 55150/udp 55151/tcp 55151/udp 55250/tcp 55250/udp
    55251/tcp 55251/udp 55350/tcp 55350/udp 55351/tcp 55351/udp
    55450/tcp 55450/udp 55451/tcp 55451/udp 55550/tcp 55550/udp
    55551/tcp 55551/udp 55650/tcp 55650/udp 55651/tcp 55651/udp
    55750/tcp 55750/udp 55751/tcp 55751/udp 55850/tcp 55850/udp
    55851/tcp 55851/udp 55950/tcp 55950/udp 55951/tcp 55951/udp
    56050/tcp 56050/udp 56051/tcp 56051/udp 5666/tcp 5666/udp
    2083/tcp 2083/udp 5201/tcp 5201/udp 8880/tcp 8880/udp
    2087/tcp 2087/udp
  )

  for port in "${PORTS[@]}"; do
    ufw allow "$port"
  done

  BLOCKED_SUBNETS=(
    10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16
    173.245.0.0/16 141.101.0.0/16 240.0.0.0/4 25.10.40.0/24 25.11.10.0/24
    103.58.50.0/24 195.137.167.0/24 45.14.174.0/24 206.191.152.0/24
    216.218.185.0/24 114.208.187.0/24 185.235.87.0/24 185.235.86.0/24
    102.0.0.0/8 233.252.0.0/24 224.0.0.0/4 240.0.0.0/24 203.0.113.0/24
    198.51.100.0/24 198.18.0.0/15 192.88.99.0/24 192.0.2.0/24 192.0.0.0/24
    102.224.45.0/24
  )

  for subnet in "${BLOCKED_SUBNETS[@]}"; do
    ufw deny out from any to "$subnet"
  done

  echo "y" | sudo ufw enable
  echo ""
  echo -e "\033[1;34m[✓] Successfully\033[0m"
  read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m'
}

function install_bbr() {
  echo ""
  echo -e "\033[1;33m[*] Setting up...\033[0m"
  echo ""
  wget -N --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh
  chmod +x bbr.sh
  bash bbr.sh
  read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m'
  rm -f /root/install_bbr.log /root/bbr.sh
}

function optimize_network() {
  echo ""
  echo -e "\033[1;33m[*] Setting up...\033[0m"
  echo ""

  keys=(
    "net.ipv4.tcp_keepalive_time"
    "net.ipv4.tcp_keepalive_intvl"
    "net.ipv4.tcp_keepalive_probes"
    "net.ipv4.tcp_fastopen"
    "net.ipv4.tcp_slow_start_after_idle"
    "net.ipv4.tcp_mtu_probing"
  )

  for key in "${keys[@]}"; do
    value=""
    case $key in
      net.ipv4.tcp_keepalive_time) value=30 ;;
      net.ipv4.tcp_keepalive_intvl) value=10 ;;
      net.ipv4.tcp_keepalive_probes) value=3 ;;
      net.ipv4.tcp_fastopen) value=3 ;;
      net.ipv4.tcp_slow_start_after_idle) value=0 ;;
      net.ipv4.tcp_mtu_probing) value=1 ;;
    esac

    if grep -q "^$key" /etc/sysctl.conf; then
      sudo sed -i "s|^$key.*|$key = $value|" /etc/sysctl.conf
    else
      echo "$key = $value" | sudo tee -a /etc/sysctl.conf > /dev/null
    fi
  done

  sudo sysctl -p > /dev/null

  echo -e "\033[1;32m--- Active Network Settings ---\033[0m"
  for key in "${keys[@]}"; do
    current_val=$(sysctl -n $key)
    echo -e "\033[1;33m[✓] $key: $current_val\033[0m"
  done

  echo ""
  echo -e "\033[1;34m[✓] All optimizations applied successfully!\033[0m"
  read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m'
}


function change_ssh_port() {
  echo ""
  echo -e "\033[1;33m[*] Setting up...\033[0m"
  echo ""
  
  if grep -q "^#Port" /etc/ssh/sshd_config; then
    sed -i 's/^#Port .*/Port 57160/' /etc/ssh/sshd_config
  elif grep -q "^Port" /etc/ssh/sshd_config; then
    sed -i 's/^Port .*/Port 57160/' /etc/ssh/sshd_config
  else
    echo "Port 57160" >> /etc/ssh/sshd_config
  fi
  echo -e "\033[1;34m[✓] SSH port changed. Restarting service...\033[0m"
  service sshd restart || service ssh restart
  echo -e "\033[1;34m[✓] SSH is now running on port 57160\033[0m"
  read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m'
}

function change_root_password() {
  echo ""
  echo -e "\033[1;33m[*] Changing password...\033[0m"
  echo ""
  echo -e "1982Gonzoi!@#\n1982Gonzoi!@#" | passwd root
  echo ""
  echo -e "\033[1;34m[✓] Your new password is "1982Gonzoi!@#"\033[0m"
  read -n 1 -s -r -p $'\033[1;35m\nPress any key to return\033[0m'
}

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
    echo "-------------------------------"
    read -p "Select an option [1-4]: " marzban_choice

    case $marzban_choice in
      1)
            echo "Installing Marzban-node..."
            apt update && apt upgrade -y
            apt install socat curl git -y
            mkdir -p /var/lib/marzban-node/assets/
            wget -O /var/lib/marzban-node/assets/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
            wget -O /var/lib/marzban-node/assets/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
            wget -O /var/lib/marzban-node/assets/iran.dat https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat

            git clone https://github.com/Gozargah/Marzban-node
            cd Marzban-node
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
            apt install unzip -y
            unzip Xray-linux-64.zip && rm Xray-linux-64.zip

            cd ~/Marzban-node
            docker compose down --remove-orphans
            docker compose up -d

        echo -e "\n\033[1;32m✅ Marzban-node installation complete.\033[0m"
        read -p "Press any key to return to menu..." -n1
        ;;
      2)
        cd ~/Marzban-node && docker compose down && docker compose up -d
        echo -e "\033[1;32m✅ Marzban-node restarted.\033[0m"
        read -p "Press any key to return to menu..." -n1
        ;;
      3)
        cd ~/Marzban-node && docker compose down
        rm -rf /var/lib/marzban/xray-core
        mkdir -p /var/lib/marzban/xray-core && cd /var/lib/marzban/xray-core
        wget https://github.com/XTLS/xray-core/releases/latest/download/Xray-linux-64.zip
        unzip Xray-linux-64.zip && rm Xray-linux-64.zip
        cd ~/Marzban-node && docker compose up -d
        echo -e "\n\033[1;32m✅ Core updated.\033[0m\n"
        read -p "Press any key to return to menu..." -n1
        ;;
      4) break ;;
      *) echo "Invalid option."; sleep 1 ;;
    esac
  done
}


function Backhual() {
  while true; do
    clear
    echo "==============================="
    echo "         Backhaul Menu         "
    echo "==============================="
    echo "1. Install Backhaul Core⬇️"
    echo "2. Run 🔄"
    echo "3. Restart ♻️"
    echo "4. Stop ⛔"
    echo "5. Status 📊"
    echo "6. Return 🔙"
    echo "-------------------------------"
     read -p "Select an option [1-6]: " bh_choice

    case $bh_choice in
      1)
        rm -rf /tmp/my-uploads
        git clone https://github.com/Alighaemi9731/backhaul.git /tmp/my-uploads
        mkdir -p /opt/utunnel
        mv /tmp/my-uploads/utunnel /opt/utunnel/utunnel
        mv /tmp/my-uploads/utunnel_manager /root/utunnel_manager
        chmod +x /root/utunnel_manager
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      2) /root/utunnel_manager; read -n 1 -s -r -p $'\nPress any key...'; ;;
      3) sudo systemctl restart utunnel_king; read -n 1 -s -r -p $'\nDone...'; ;;
      4) sudo systemctl stop utunnel_king; read -n 1 -s -r -p $'\nStopped...'; ;;
      5) sudo systemctl status utunnel_king; read -n 1 -s -r -p $'\nPress any key...'; ;;
      6) break ;;
      *) echo "Invalid option!"; sleep 1 ;;
    esac
  done
}

function GostMenu() {
  while true; do
    clear
    echo "==============================="
    echo "         GOST Menu             "
    echo "==============================="
    echo "1. Install / Update Core⬇️"
    echo "2. Enable / Restart 🚀"
    echo "3. Stop ⛔"
    echo "4. Edit ✏️"
    echo "5. Return 🔙"
    echo "-------------------------------"
    read -p "Select an option [1-5]: " gost_choice

    case $gost_choice in
      1)
       if systemctl list-unit-files | grep -q gost.service; then
       sudo systemctl stop gost || true
       fi
       rm -rf /usr/local/bin/gost
        wget https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_amd64.tar.gz
        mkdir -p /usr/local/bin/gost
        tar -xvzf gost_3.2.6_linux_amd64.tar.gz -C /usr/local/bin/gost/
        rm -f gost_3.2.6_linux_amd64.tar.gz
        
        echo "1. Iran / 2. Kharej / 3. Skip Config"
        read -p "Choice: " region_choice
        if [ "$region_choice" = "1" ]; then
          cat <<EOF | sudo tee /usr/lib/systemd/system/gost.service > /dev/null
[Unit]
Description=GO Simple Tunnel
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost/gost -L=tcp://:2095 -F forward+tcp://30.0.0.2:443
[Install]
WantedBy=multi-user.target
EOF
        elif [ "$region_choice" = "2" ]; then
          cat <<EOF | sudo tee /usr/lib/systemd/system/gost.service > /dev/null
[Unit]
Description=GO Simple Tunnel
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost/gost -L=tcp://:443/:2095
[Install]
WantedBy=multi-user.target
EOF
        fi
        sudo systemctl daemon-reload && sudo systemctl enable gost && sudo systemctl restart gost
        read -n 1 -s -r -p $'\nDone...'; ;;
      2) sudo systemctl restart gost; read -n 1 -s -r -p $'\nDone...'; ;;
      3) sudo systemctl stop gost; read -n 1 -s -r -p $'\nStopped...'; ;;
      4) sudo nano /usr/lib/systemd/system/gost.service ;;
      5) break ;;
    esac
  done
}

function lena_tunnel() {
  bash <(curl -Ls https://raw.githubusercontent.com/MrAminiDev/LenaTunnel/main/install.sh)
  read -n 1 -s -r -p $'\nPress any key to return to the menu...'
}

function main_menu() {
  while true; do
    clear
    echo "==============================="
    echo -e "\033[1;35m       Server Tools Menu       \033[0m"
    echo -e "\033[1;35m        Version : $VERSION       \033[0m"
    echo "==============================="
    echo -e "\033[1;35m    Server IP : \033[1;34m$SERVER_IP\033[1;35m\033[0m"
    echo "==============================="
    echo "1) Setup Firewall 🔥"
    echo "2) Install BBR 🚀"
    echo "3) Optimize Network 🚀"
    echo "4) Change SSH Port 🔐"
    echo "5) Change Root Password 🔑"
    echo "6) Marzban Node"
    echo "7) Backhual Tunnel (Premium)"
    echo "8) GOST Tunnel"
    echo "9) Lena Tunnel"
    echo "10) Auto SSH Tunnel 🔗"
    echo "0) Exit ❌"
    echo "-------------------------------"
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
      10) auto_ssh_tunnel_menu ;;
      0) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

main_menu
