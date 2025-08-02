#!/bin/bash
VERSION="1.0.0"
SERVER_IP=$(hostname -I | awk '{print $1}')

set -e

function setup_firewall() {
  echo "[*] Setting up firewall rules..."

  PORTS=(
    ssh http https 53/tcp 53/udp 80/tcp 80/udp 2020/tcp 2020/udp
    443/tcp 443/udp 8000/tcp 8000/udp 57160/tcp 57160/udp 5629/tcp 5629/udp
    1080/tcp 1080/udp 2111/tcp 2111/udp 2096/tcp 2096/udp 3832/tcp 3832/udp
    8081/tcp 8081/udp 8082/tcp 8082/udp 2095/tcp 2095/udp 25349/tcp 25349/udp
    10000/tcp 10000/udp 11000/tcp 11000/udp 11100/tcp 11100/udp 11200/tcp 11200/udp
    11300/tcp 11300/udp 11400/tcp 11400/udp 11500/tcp 11500/udp 11600/tcp 11600/udp
    21653/tcp 21653/udp 21652/tcp 21652/udp
    55150/tcp 55150/udp 55151/tcp 55151/udp 55250/tcp 55250/udp
    55251/tcp 55251/udp 55350/tcp 55350/udp 55351/tcp 55351/udp
    55450/tcp 55450/udp 55451/tcp 55451/udp 55550/tcp 55550/udp
    55551/tcp 55551/udp 55650/tcp 55650/udp 55651/tcp 55651/udp
    55750/tcp 55750/udp 55751/tcp 55751/udp 55850/tcp 55850/udp
    55851/tcp 55851/udp 55950/tcp 55950/udp 55951/tcp 55951/udp
    56050/tcp 56050/udp 56051/tcp 56051/udp
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
  echo "[✓] Firewall enabled successfully."
  read -n 1 -s -r -p $'\nPress any key to return to the menu...'
}

function install_bbr() {
  echo "[*] Downloading and running BBR installer (teddysun)..."
  wget -N --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh
  chmod +x bbr.sh
  bash bbr.sh
  read -n 1 -s -r -p $'\nPress any key to return to the menu...'
  rm -f /root/install_bbr.log /root/bbr.sh
}

function optimize_network() {
  echo "[*] Applying system TCP keepalive optimizations..."

  # Update or add TCP keepalive settings in /etc/sysctl.conf
  for key in net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes; do
    value=""
    case $key in
      net.ipv4.tcp_keepalive_time) value=30 ;;
      net.ipv4.tcp_keepalive_intvl) value=10 ;;
      net.ipv4.tcp_keepalive_probes) value=3 ;;
    esac

    if grep -q "^$key" /etc/sysctl.conf; then
      sudo sed -i "s|^$key.*|$key = $value|" /etc/sysctl.conf
    else
      echo "$key = $value" | sudo tee -a /etc/sysctl.conf > /dev/null
    fi
  done

  # Apply the changes
  sudo sysctl -p

  # Show active settings
  echo ""
  echo "[✓] Keepalive time: $(sysctl -n net.ipv4.tcp_keepalive_time)"
  echo "[✓] Keepalive interval: $(sysctl -n net.ipv4.tcp_keepalive_intvl)"
  echo "[✓] Keepalive probes: $(sysctl -n net.ipv4.tcp_keepalive_probes)"

  echo ""
  echo "[✔] TCP Keepalive optimization completed successfully."
  read -n 1 -s -r -p $'\nPress any key to return to the menu...'
}


function change_ssh_port() {
  echo "[*] Changing SSH port to 57160..."

  if grep -q "^#Port" /etc/ssh/sshd_config; then
    sed -i 's/^#Port .*/Port 57160/' /etc/ssh/sshd_config
  elif grep -q "^Port" /etc/ssh/sshd_config; then
    sed -i 's/^Port .*/Port 57160/' /etc/ssh/sshd_config
  else
    echo "Port 57160" >> /etc/ssh/sshd_config
  fi

  echo "[✓] SSH port changed. Restarting service..."
  service sshd restart || service ssh restart
  echo "[✓] Done. SSH is now running on port 57160."
  read -n 1 -s -r -p $'\nPress any key to return to the menu...'
}

function change_root_password() {
  echo "[*] Changing root password to: 1982Gonzoi!@#"
  echo -e "1982Gonzoi!@#\n1982Gonzoi!@#" | passwd root
  echo -e "\n\033[1;32m✅ Password changed successfully.\033[0m"
  read -n 1 -s -r -p $'\nPress any key to return to the menu...'
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
            apt install socat -y && apt install curl socat -y && apt install git -y

            mkdir -p /var/lib/marzban-node/assets/

            wget -O /var/lib/marzban-node/assets/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
            wget -O /var/lib/marzban-node/assets/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
            wget -O /var/lib/marzban-node/assets/iran.dat https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat

            git clone https://github.com/Gozargah/Marzban-node
            cd Marzban-node

            curl -fsSL https://get.docker.com | sh
            docker compose up -d

            echo "Replace docker-compose.yml ..."
            cat > docker-compose.yml <<EOF
services:
  marzban-node:
    # build: .
    image: gozargah/marzban-node:latest
    restart: always
    network_mode: host

    # env_file: .env
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
            wget https://github.com/XTLS/xray-core/releases/latest/download/Xray-linux-64.zip
            apt install unzip -y
            unzip Xray-linux-64.zip
            rm Xray-linux-64.zip

            cd ~/Marzban-node
            docker compose down --remove-orphans
            docker compose up -d

        echo ""
        echo -e "\n\033[1;32m✅ Marzban-node installation complete.\033[0m"
        echo -e "\033[1;33m📌 Please copy your certificate file to:\033[0m \033[1;36m/var/lib/marzban-node/\033[0m"
        echo -e "\033[1;33m📌 File name should be:\033[0m \033[1;36mssl_client_cert.pem\033[0m\n"
        echo ""
        read -p "Press any key to return to menu..." -n1
        ;;
      2)
        cd ~/Marzban-node
        docker compose down --remove-orphans
        docker compose up -d
        echo -e "\033[1;32m✅ Marzban-node restarted.\033[0m"
        read -p "Press any key to return to menu..." -n1
        ;;
      3)
        cd ~/Marzban-node
        docker compose down

        rm -rf /var/lib/marzban/xray-core

        apt install unzip -y

        mkdir -p /var/lib/marzban/xray-core && cd /var/lib/marzban/xray-core

        wget https://github.com/XTLS/xray-core/releases/latest/download/Xray-linux-64.zip

        unzip Xray-linux-64.zip
        rm Xray-linux-64.zip

        cd ~/Marzban-node
        docker compose down --remove-orphans
        docker compose up -d

        echo -e "\n\033[1;32m✅ Core updated and Marzban-node restarted.\033[0m\n"
        read -p "Press any key to return to menu..." -n1
        ;;

      4)
        break
        ;;
      *)
        echo "Invalid option. Please choose 1, 2, or 3."
        sleep 1
        ;;
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
        echo "[*] Installing Backhaul..."
        rm -rf /tmp/my-uploads
        git clone https://github.com/Alighaemi9731/backhaul.git /tmp/my-uploads
        mkdir -p /opt/utunnel
        mv /tmp/my-uploads/utunnel /opt/utunnel/utunnel
        mv /tmp/my-uploads/utunnel_manager /root/utunnel_manager
        chmod +x /root/utunnel_manager
        echo "[✓] Backhaul installed successfully."
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      2)
        echo "[*] Running Backhaul..."
        /root/utunnel_manager
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      3)
        echo "[*] Restarting tunnel service..."
        sudo systemctl restart utunnel_king
        sudo systemctl enable utunnel_king
        echo "[✓] Tunnel restarted and enabled on boot."
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      4)
        echo "[*] Stopping tunnel service..."
        sudo systemctl stop utunnel_king
        sudo systemctl disable utunnel_king
        echo "[✓] Tunnel stopped and disabled from boot."
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      5)
        echo "[*] Tunnel status:"
        sudo systemctl status utunnel_king
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      6)
        echo "Returning to main menu..."
        break
        ;;
      *)
        echo "Invalid option! Please try again."
        sleep 1
        ;;
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
        echo "[*] Check if GOST service is running..."
        sudo systemctl stop gost
        sudo systemctl disable gost
        rm -rf /usr/local/bin/gost

        echo "[*] Installing GOST..."
        sudo apt install wget nano -y
        wget https://github.com/go-gost/gost/releases/download/v3.2.1-nightly.20250730/gost_3.2.1-nightly.20250730_linux_amd64.tar.gz
        mkdir -p /usr/local/bin/gost
        tar -xvzf gost_3.2.1-nightly.20250730_linux_amd64.tar.gz -C /usr/local/bin/gost/
        chmod +x /usr/local/bin/gost/
        rm -f /root/gost_3.2.1-nightly.20250730_linux_amd64.tar.gz
        echo "[✓] Files installed. Editing service file..."
        echo "Select your region:"
        echo "1. Iran"
        echo "2. Kharej"
        echo "3. Just Update Core"
        read -p "Enter choice [1-3]: " region_choice

        if [ "$region_choice" = "1" ]; then
          cat <<EOF | sudo tee /usr/lib/systemd/system/gost.service > /dev/null
[Unit]
Description=GO Simple Tunnel
After=network.target
Wants=network.target

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
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost/gost -L=tcp://:443/:2095

[Install]
WantedBy=multi-user.target
EOF
        else
          echo "[!] Skipping service config."
          echo "[*] Enabling and starting GOST service..."
          sudo systemctl daemon-reload
          sudo systemctl enable gost
          sudo systemctl start gost
          sudo systemctl restart gost
        fi

        echo "[✓] GOST installed successfully."
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      2)
        echo "[*] Enabling and starting GOST service..."
        sudo systemctl daemon-reload
        sudo systemctl enable gost
        sudo systemctl start gost
        sudo systemctl restart gost
        echo "[✓] GOST service is running."
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      3)
        echo "[*] Disabling and stopping GOST service..."
        sudo systemctl disable gost
        sudo systemctl stop gost
        sudo systemctl status gost
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      4)
        echo -e "\n\033[1;32m Opening service file for editing...\033[0m"
        sudo nano /usr/lib/systemd/system/gost.service
        read -n 1 -s -r -p $'\nPress any key to return to the menu...'
        ;;
      5)
        echo "Returning to previous menu..."
        break
        ;;
      *)
        echo "Invalid option! Please try again."
        sleep 1
        ;;
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
    echo -e "\033[1;34m        $SERVER_IP       \033[0m"
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
      0) echo -e "\033[1;34mExiting...\033[0m"; exit 0 ;;
      *) echo -e "\033[1;31mInvalid option\033[0m"; sleep 1 ;;
    esac
  done
}


main_menu
