#!/bin/bash

RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

disable_option=false
enable_ech=false
listen_port=""
override_port=""
ip_v4=""
ip_v6=""
record_content=""
record_type=""
record_name=""
obfs_password=""
domain=""
domain_name=""
up_mbps=""
down_mbps=""
certificate_path=""
private_key_path=""
public_key=""
private_key=""
multiplex_config=""
brutal_config=""
ech_key=()
ech_config=()
user_names=()
user_passwords=()
user_uuids=()
ss_passwords=()
stls_passwords=()
short_ids=()

function check_firewall_configuration() {
    local os_name=$(uname -s)
    local firewall
    if [[ $os_name == "Linux" ]]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            firewall="ufw"
        elif command -v ip6tables >/dev/null 2>&1 && ip6tables -S | grep -q "INPUT -j DROP"; then
            firewall="ip6tables"
        elif command -v iptables >/dev/null 2>&1 && iptables -S | grep -q "INPUT -j DROP"; then
            firewall="iptables"
        elif systemctl is-active --quiet netfilter-persistent; then
            firewall="iptables-persistent"
        elif systemctl is-active --quiet iptables.service; then
            firewall="iptables-service"
        elif command -v firewalld >/dev/null 2>&1 && firewall-cmd --state | grep -q "running"; then
            firewall="firewalld"
        fi
    fi
    if [[ -z $firewall ]]; then
        echo "No firewall configuration detected or firewall is not enabled, skipping firewall configuration."
        return
    fi
    echo "Checking firewall configuration..."
    case $firewall in
    ufw)
        if ! ufw status | grep -q "Status: active" 2>/dev/null; then
            ufw enable >/dev/null 2>&1
        fi
        if ! ufw status | grep -q " $listen_port" 2>/dev/null; then
            ufw allow "$listen_port" >/dev/null 2>&1
        fi

        if ! ufw status | grep -q " $override_port" 2>/dev/null; then
            ufw allow "$override_port" >/dev/null 2>&1
        fi

        if ! ufw status | grep -q " $fallback_port" 2>/dev/null; then
            ufw allow "$fallback_port" >/dev/null 2>&1
        fi

        if ! ufw status | grep -q " 80" 2>/dev/null; then
            ufw allow 80 >/dev/null 2>&1
        fi
        echo "Firewall configuration has been updated."
        ;;
    iptables | iptables-persistent | iptables-service)
        if ! iptables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p tcp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p udp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1
        fi

        if ! iptables -C INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p tcp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p tcp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p udp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p udp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1
        fi

        if ! ip6tables -C INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1; then
            ip6tables -A INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1
        fi

        if [[ -e /etc/iptables/rules.v4 ]]; then
            iptables-save >/etc/iptables/rules.v4
        elif [[ -e /etc/sysconfig/iptables ]]; then
            iptables-save >/etc/sysconfig/iptables
        fi

        if [[ -e /etc/iptables/rules.v6 ]]; then
            ip6tables-save >/etc/iptables/rules.v6
        elif [[ -e /etc/sysconfig/ip6tables ]]; then
            ip6tables-save >/etc/sysconfig/ip6tables
        fi
        echo "Firewall configuration has been updated."
        ;;
    firewalld)
        if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$override_port/tcp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$override_port/udp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$fallback_port/tcp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$fallback_port/udp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "80/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port=80/tcp --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "80/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port=80/udp --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$override_port/tcp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$override_port/udp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$fallback_port/tcp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port="$fallback_port/udp" --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "80/tcp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port=80/tcp --permanent >/dev/null 2>&1
        fi

        if ! firewall-cmd --zone=public --list-ports | grep -q "80/udp" 2>/dev/null; then
            firewall-cmd --zone=public --add-port=80/udp --permanent >/dev/null 2>&1
        fi
        firewall-cmd --reload
        echo "Firewall configuration has been updated."
        ;;
    esac
}

function create_sing_box_folders() {
    local folders=("/usr/local/etc/sing-box" "/etc/ssl/private")
    for folder in "${folders[@]}"; do
        if [[ ! -d "$folder" ]]; then
            mkdir -p "$folder"
            [ "$folder" = "/usr/local/etc/sing-box" ] && touch "$folder/config.json"
        fi
    done
}

function create_juicity_folder() {
    local folders=("/usr/local/etc/juicity" "/etc/ssl/private")
    for folder in "${folders[@]}"; do
        if [[ ! -d "$folder" ]]; then
            mkdir -p "$folder"
            [ "$folder" = "/usr/local/etc/juicity" ] && touch "$folder/config.json"
        fi
    done
}

function ensure_clash_yaml() {
    local clash_yaml="/usr/local/etc/sing-box/clash.yaml"
    if [ ! -e "$clash_yaml" ]; then
        touch "$clash_yaml"
    fi
}

function check_config_file_existence() {
    local config_file="/usr/local/etc/sing-box/config.json"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}sing-box config file does not exist, please build node first!${NC}"
        exit 1
    fi
}

function generate_naive_random_filename() {
    local dir="/usr/local/etc/sing-box"
    local filename=""

    while true; do
        random_value=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 5 | head -n 1)

        filename="naive_client_${random_value}.json"

        if [ ! -e "${dir}/${filename}" ]; then
            touch "${dir}/${filename}"
            naive_client_filename="${dir}/${filename}"
            break
        fi
    done
}

function get_temp_config_file() {
    temp_file=$(mktemp)
    curl -sSL "https://api.zeroteam.top/warp?format=sing-box" >"$temp_file"
}

function install_sing_box() {
    if [[ -f "/usr/local/bin/sing-box" && -f "/usr/local/etc/sing-box/config.json" ]]; then
        return 1
    else
        get_local_ip
        configure_dns64        
        select_sing_box_install_option
        configure_sing_box_service
        create_sing_box_folders
    fi
}

function configure_dns64() {
    if [[ -n $ip_v4 ]]; then
        return
    fi
    if [[ -n $ip_v6 ]]; then
        echo "Check that the machine is IPv6 single-stack network, configure DNS64..."
        sed -i '/^nameserver /s/^/#/' /etc/resolv.conf
        echo "nameserver 2001:67c:2b0::4" >>/etc/resolv.conf
        echo "nameserver 2001:67c:2b0::6" >>/etc/resolv.conf
        echo "DNS64 configuration is complete."
    fi
}

function enable_bbr() {
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "BBR is already enabled, skipping configuration."
        return
    fi
    while true; do
        read -p "Whether to enable BBR (Y/N, default N)? " -i "N" response
        response=${response:-"N"}
        if [[ $response == "y" || $response == "Y" ]]; then
            echo "Enable BBR..."
            echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
            sysctl -p >/dev/null
            echo "BBR has been enabled"
            break
        elif [[ $response == "n" || $response == "N" ]]; then
            echo "BBR will not be enabled."
            break
        else
            echo -e "${RED}Invalid input, please re-enter!${NC}"
        fi
    done
}

function select_sing_box_install_option() {
    while true; do
        echo "Please select sing-box installation method (default 1):"
        echo "1). Download and install sing-box (Latest version)"
        echo "2). Download and install sing-box (Beta version)"
        echo "3). Compile and install sing-box (full featured version)"
        read -p "Please select [1-3]: " install_option
        install_option="${install_option:-1}"        
        case $install_option in
        1)
            install_latest_sing_box
            break
            ;;
        2)
            install_Pre_release_sing_box
            break
            ;;
        3)
            install_go
            compile_install_sing_box
            break
            ;;
        *)
            echo -e "${RED}Invalid selection, please re-enter!${NC}"
            ;;
        esac
    done
}

function install_go() {
    if ! command -v go &>/dev/null; then
        echo "Downloading Go..."
        local go_arch
        case $(uname -m) in
        x86_64)
            go_arch="amd64"
            ;;
        i686)
            go_arch="386"
            ;;
        aarch64)
            go_arch="arm64"
            ;;
        armv6l)
            go_arch="armv6"
            ;;
        *)
            echo -e "${RED}unsupported architecture: $(uname -m)${NC}"
            exit 1
            ;;
        esac
        local go_version
        go_version=$(curl -sL "https://golang.org/VERSION?m=text" | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+')
        local go_download_url="https://go.dev/dl/$go_version.linux-$go_arch.tar.gz"
        wget -qO- "$go_download_url" | tar -xz -C /usr/local
        echo 'export PATH=$PATH:/usr/local/go/bin' | tee -a /etc/profile >/dev/null
        source /etc/profile
        go version
        echo "Go has been installed."
    else
        echo "Go is already installed, skipping installation."
    fi
}
function compile_install_sing_box() {
    local go_install_command="go install -v -tags \
with_quic,\
with_grpc,\
with_dhcp,\
with_wireguard,\
with_utls,\
with_acme,\
with_clash_api,\
with_v2ray_api,\
with_gvisor \
github.com/sagernet/sing-box/cmd/sing-box@latest"
    echo "Compiling and installing sing-box, please wait..."
    $go_install_command
    if [[ $? -eq 0 ]]; then
        mv ~/go/bin/sing-box /usr/local/bin/
        chmod +x /usr/local/bin/sing-box
        echo "sing-box has been compiled and installed successfully."
    else
        echo -e "${RED}sing-box compilation and installation failed.${NC}"
        exit 1
    fi
}

function install_latest_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url
    case $arch in
    x86_64 | amd64)
        download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64.tar.gz")
        ;;
    armv7l)
        download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-armv7.tar.gz")
        ;;
    aarch64 | arm64)
        download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-arm64.tar.gz")
        ;;
    amd64v3)
        download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64v3.tar.gz")
        ;;
    s390x)
        download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-s390x.tar.gz")
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $arch${NC}"
        return 1
        ;;
    esac
    if [ -n "$download_url" ]; then
        echo "Downloading Sing-Box..."
        wget -qO sing-box.tar.gz "$download_url" 2>&1 >/dev/null
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz
        chmod +x /usr/local/bin/sing-box
        echo "Sing-Box installed successfully."
    else
        echo -e "${RED}Unable to retrieve the download URL for Sing-Box.${NC}"
        return 1
    fi
}

function install_Pre_release_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases"
    local download_url
    case $arch in
    x86_64 | amd64)
        download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-amd64.tar.gz")) | .browser_download_url' | head -n 1)
        ;;
    armv7l)
        download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-armv7.tar.gz")) | .browser_download_url' | head -n 1)
        ;;
    aarch64 | arm64)
        download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-arm64.tar.gz")) | .browser_download_url' | head -n 1)
        ;;
    amd64v3)
        download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-amd64v3.tar.gz")) | .browser_download_url' | head -n 1)
        ;;
    s390x)
        download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-s390x.tar.gz")) | .browser_download_url' | head -n 1)
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $arch${NC}"
        return 1
        ;;
    esac
    if [ -n "$download_url" ]; then
        echo "Downloading Sing-Box..."
        wget -qO sing-box.tar.gz "$download_url" 2>&1 >/dev/null
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz
        chmod +x /usr/local/bin/sing-box

        echo "Sing-Box installed successfully."
    else
        echo -e "${RED}Unable to get pre-release download link for Sing-Box.${NC}"
        return 1
    fi
}

function install_latest_juicity() {
    local arch=$(uname -m)
    case $arch in
    "arm64")
        arch_suffix="arm64"
        ;;
    "armv5")
        arch_suffix="armv5"
        ;;
    "armv6")
        arch_suffix="armv6"
        ;;
    "armv7")
        arch_suffix="armv7"
        ;;
    "mips")
        arch_suffix="mips32"
        ;;
    "mipsel")
        arch_suffix="mips32le"
        ;;
    "mips64")
        arch_suffix="mips64"
        ;;
    "mips64el")
        arch_suffix="mips64le"
        ;;
    "riscv64")
        arch_suffix="riscv64"
        ;;
    "i686")
        arch_suffix="x86_32"
        ;;
    "x86_64")
        if [ -n "$(grep avx2 /proc/cpuinfo)" ]; then
            arch_suffix="x86_64_v3_avx2"
        else
            arch_suffix="x86_64_v2_sse"
        fi
        ;;
    *)
        echo "Unsupported architecture: $arch"
        return 1
        ;;
    esac
    local github_api_url="https://api.github.com/repos/juicity/juicity/releases/latest"
    local download_url=$(curl -s "$github_api_url" | grep "browser_download_url.*$arch_suffix.zip\"" | cut -d '"' -f 4)
    local temp_dir=$(mktemp -d)
    local install_path="/usr/local/bin/juicity-server"
    echo "Downloading the latest version of juicity-server..."
    wget -P "$temp_dir" "$download_url" >/dev/null 2>&1
    unzip "$temp_dir/*.zip" -d "$temp_dir" >/dev/null 2>&1
    mv "$temp_dir/juicity-server" "$install_path" >/dev/null 2>&1
    chmod +x /usr/local/bin/juicity-server
    echo "juicity-server has been downloaded."
    rm -rf "$temp_dir"
}

function configure_sing_box_service() {
    echo "Configuring sing-box startup service..."
    local service_file="/etc/systemd/system/sing-box.service"
    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    local service_config="[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target"
    echo "$service_config" >"$service_file"
    echo "sing-box startup service has been configured."
}
function configure_juicity_service() {
    echo "Configuring juicity startup service..."
    local service_file="/etc/systemd/system/juicity.service"
    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    local service_config="[Unit]
Description=juicity-server Service
Documentation=https://github.com/juicity/juicity
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Environment=QUIC_GO_ENABLE_GSO=true
ExecStart=/usr/local/bin/juicity-server run -c /usr/local/etc/juicity/config.json --disable-timestamp
Restart=on-failure
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target"
    echo "$service_config" >"$service_file"
    echo "juicity startup service has been configured."
}

function set_listen_port() {
    while true; do
        read -p "Please enter the listening port (default 443): " new_listen_port
        new_listen_port=${new_listen_port:-443}
        if [[ $new_listen_port =~ ^[1-9][0-9]{0,4}$ && $new_listen_port -le 65535 ]]; then
            check_result=$(netstat -tulpn | grep -E "\b${new_listen_port}\b")
            if [ -z "$check_result" ]; then
                echo "Listening Port: $new_listen_port"
                break
            else
                echo -e "${RED}Error: Port is already in use. Please select another port!${NC}" >&2
            fi
        else
            echo -e "${RED}Error: Port range is 1-65535. Please re-enter!${NC}" >&2
        fi
    done
    listen_port="$new_listen_port"
}

function set_user_name() {
    while true; do
        read -p "Please enter username (default randomly generated): " new_user_name
        if [[ -z "$new_user_name" ]]; then
            new_user_name=$(sing-box generate rand --base64 6 2>/dev/null || openssl rand -base64 5)
            echo "Username: $new_user_name"
            break
        elif [[ ! -z "$new_user_name" ]]; then
            break
        fi
    done
    user_names+=("$new_user_name")
}

function set_user_password() {
    while true; do
        read -p "Please enter password (default randomly generated): " new_user_password
        if [[ -z "$new_user_password" ]]; then
            new_user_password=$(sing-box generate rand --base64 9 2>/dev/null || openssl rand -base64 9)
            echo "Password: $new_user_password"
            break
        elif [[ ! -z "$new_user_password" ]]; then
            break
        fi
    done
    user_passwords+=("$new_user_password")
}

function set_ss_password() {
    while true; do
        read -p "Please enter Shadowsocks password (default randomly generated): " ss_user_password
        if [[ -z $ss_user_password ]]; then
            if [[ $encryption_choice == 1 || $encryption_choice == 2 ]]; then
                ss_password=$(sing-box generate rand --base64 32)
                echo "Shadowsocks Password: $ss_password"
            else
                ss_password=$(sing-box generate rand --base64 16)
                echo "Shadowsocks Password: $ss_password"
            fi
            ss_passwords+=("$ss_password")
            break
        elif [[ $encryption_choice == 1 || $encryption_choice == 2 ]] && [[ ${#ss_user_password} -eq 32 ]]; then
            ss_password="$ss_user_password"
            echo "Shadowsocks Password: $ss_password"
            ss_passwords+=("$ss_password")
            break
        elif [[ $encryption_choice != 1 && $encryption_choice != 2 ]] && [[ ${#ss_user_password} -eq 16 ]]; then
            ss_password="$ss_user_password"
            echo "Shadowsocks Password: $ss_password"
            ss_passwords+=("$ss_password")
            break
        else
            echo -e "${RED}Error: Password length does not meet requirements. Please re-enter!${NC}"
        fi
    done
}

function set_stls_password() {
    while true; do
        read -p "Please enter ShadowTLS password (default randomly generated): " stls_user_password
        if [[ -z $stls_user_password ]]; then
            if [[ $encryption_choice == 1 || $encryption_choice == 2 ]]; then
                stls_password=$(sing-box generate rand --base64 32)
                echo "ShadowTLS Password: $stls_password"
            else
                stls_password=$(sing-box generate rand --base64 16)
                echo "ShadowTLS Password: $stls_password"
            fi
            stls_passwords+=("$stls_password")
            break
        elif [[ $encryption_choice == 1 || $encryption_choice == 2 ]] && [[ ${#stls_user_password} -eq 32 ]]; then
            stls_password="$stls_user_password"
            echo "ShadowTLS Password: $stls_password"
            stls_passwords+=("$stls_password")
            break
        elif [[ $encryption_choice != 1 && $encryption_choice != 2 ]] && [[ ${#stls_user_password} -eq 16 ]]; then
            stls_password="$stls_user_password"
            echo "ShadowTLS Password: $stls_password"
            stls_passwords+=("$stls_password")
            break
        else
            echo -e "${RED}Error: Password length does not meet requirements. Please re-enter!${NC}"
        fi
    done
}

function set_up_speed() {
    while true; do
        read -p "Please enter upload speed (default 50): " new_up_mbps
        new_up_mbps=${new_up_mbps:-50}
        if [[ $new_up_mbps =~ ^[0-9]+$ ]]; then
            echo "Upload Speed: $new_up_mbps Mbps"
            break
        else
            echo -e "${RED}Error: Please enter a number as upload speed!${NC}"
        fi
    done
    up_mbps="$new_up_mbps"
}

function set_down_speed() {
    while true; do
        read -p "Please enter download speed (default 100): " new_down_mbps
        new_down_mbps=${new_down_mbps:-100}
        if [[ $new_down_mbps =~ ^[0-9]+$ ]]; then
            echo "Download Speed: $new_down_mbps Mbps"
            break
        else
            echo -e "${RED}Error: Please enter a number as download speed!${NC}"
        fi
    done
    down_mbps="$new_down_mbps"
}

function set_uuid() {
    while true; do
        read -p "Please enter UUID (default randomly generated): " new_user_uuid
        if [ -z "$new_user_uuid" ]; then
            new_user_uuid=$(sing-box generate uuid 2>/dev/null || openssl rand -hex 16 | awk '{print substr($1,1,8) "-" substr($1,9,4) "-" substr($1,13,4) "-" substr($1,17,4) "-" substr($1,21)}')
        fi
        if [[ $new_user_uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
            echo "UUID: $new_user_uuid"
            break
        else
            echo -e "${RED}Invalid UUID format, please re-enter!${NC}"
        fi
    done
    user_uuids+=("$new_user_uuid")
}

function set_override_port() {
    while true; do
        read -p "Please enter target port (default 443): " new_override_port
        new_override_port=${new_override_port:-443}
        if [[ $new_override_port =~ ^[1-9][0-9]{0,4}$ && $new_override_port -le 65535 ]]; then
            echo "Target Port: $new_override_port"
            break
        else
            echo -e "${RED}Error: Port range should be 1-65535, please re-enter!${NC}"
        fi
    done
    override_port="$new_override_port"
}

function generate_unique_tag() {
    local config_file="/usr/local/etc/sing-box/config.json"
    while true; do
        random_tag=$(head /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1)
        tag_label="${random_tag}-in"
        if ! grep -qE "\"tag\":\\s*\"$tag_label\"(,|$)" "$config_file"; then
            break
        fi
    done
}

function set_override_address() {
    while true; do
        read -p "Please enter target address (IP or domain name): " target_address
        if [[ -z "$target_address" ]]; then
            echo -e "${RED}Error: Target address cannot be empty!${NC}"
            continue
        fi
        if ([[ $target_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ $(grep -o '\.' <<<"$target_address" | wc -l) -eq 3 ]]) || ([[ $target_address =~ ^[a-fA-F0-9:]+$ ]] && [[ $(grep -o ':' <<<"$target_address" | wc -l) -ge 2 ]]); then
            break
        else
            resolved_ips=$(host -t A "$target_address" | awk '/has address/ { print $4 }')

            if [[ -n "$resolved_ips" ]] && ([[ "$resolved_ips" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$resolved_ips" =~ ^[a-fA-F0-9:]+$ ]]); then
                break
            else
                echo -e "${RED}Error: Please enter a valid IP address or domain name!${NC}"
            fi
        fi
    done
}

function set_server_name() {
    while true; do
        read -p "Please enter a list of available ServerNames (default is nijigen-works.jp): " user_input
        if [[ -z "$user_input" ]]; then
            server_name="nijigen-works.jp"
            echo "ServerName: $server_name"
            break
        else
            server_name="$user_input"
            echo "ServerName: $server_name"
            echo "Verifying server's TLS version support..."
            if command -v openssl >/dev/null 2>&1; then
                local openssl_output=$(timeout 10s openssl s_client -connect "$server_name:443" -tls1_3 2>&1)
                if [[ $openssl_output == *"TLS_AES_256_GCM_SHA384"* ||
                    $openssl_output == *"TLS_AES_128_GCM_SHA256"* ||
                    $openssl_output == *"TLS_CHACHA20_POLY1305_SHA256"* ||
                    $openssl_output == *"TLS_AES_128_CCM_SHA256"* ||
                    $openssl_output == *"TLS_AES_128_CCM_8_SHA256"* ]]; then
                    break
                else
                    echo -e "${RED}This website does not support TLS 1.3, please re-enter!${NC}"
                fi
            else
                echo "OpenSSL is not installed, cannot verify TLS support."
                break
            fi
        fi
    done
}

function set_target_server() {
    while true; do
        read -p "Please enter target website address (default is nijigen-works.jp): " user_input
        if [[ -z "$user_input" ]]; then
            target_server="nijigen-works.jp"
            echo "Target Website: $target_server"
            break
        else
            target_server="$user_input"
            echo "Target Website: $target_server"
            echo "Verifying server's TLS version support..."
            if command -v openssl >/dev/null 2>&1; then
                local openssl_output=$(timeout 10s openssl s_client -connect "$target_server:443" -tls1_3 2>&1)
                if [[ $openssl_output == *"TLS_AES_256_GCM_SHA384"* ||
                    $openssl_output == *"TLS_AES_128_GCM_SHA256"* ||
                    $openssl_output == *"TLS_CHACHA20_POLY1305_SHA256"* ||
                    $openssl_output == *"TLS_AES_128_CCM_SHA256"* ||
                    $openssl_output == *"TLS_AES_128_CCM_8_SHA256"* ]]; then
                    break
                else
                    echo -e "${RED}This target website address does not support TLS 1.3, please re-enter!${NC}"
                fi
            else
                echo "OpenSSL is not installed, cannot verify TLS support."
                break
            fi
        fi
    done
}

function get_local_ip() {
    local local_ip_v4
    local local_ip_v6
    local_ip_v4=$(wget -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=1 https://v4.ident.me)
        ip_v4="$local_ip_v4"

    local_ip_v6=$(wget -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=1 https://v6.ident.me)
        ip_v6="$local_ip_v6"

    if [[ -z "$ip_v4" && -z "$ip_v6" ]]; then
        echo -e "${RED}Unable to retrieve local IP address!${NC}"
    fi
}

function get_ech_keys() {
    local input_file="/etc/ssl/private/ech.tmp"
    local output_file="/etc/ssl/private/ech.pem"
    local ech_public_name="${domain:-${domain_name:-${server_name:-example.com}}}"
    sing-box generate ech-keypair "$ech_public_name" >"$input_file"
    IFS=$'\n' read -d '' -ra lines <"$input_file"
    exec 3>"$output_file"
    in_ech_keys_section=false
    in_ech_configs_section=false
    for line in "${lines[@]}"; do
        if [[ "$line" == *"BEGIN ECH KEYS"* ]]; then
            in_ech_keys_section=true
            ech_key+="            \"$line\",\n"
        elif [[ "$line" == *"END ECH KEYS"* ]]; then
            in_ech_keys_section=false
            ech_key+="            \"$line\""
        elif [[ "$line" == *"BEGIN ECH CONFIGS"* ]]; then
            in_ech_configs_section=true
            ech_config+="            \"$line\",\n"
        elif [[ "$line" == *"END ECH CONFIGS"* ]]; then
            in_ech_configs_section=false
            ech_config+="            \"$line\""
        elif [ "$in_ech_keys_section" = true ]; then
            ech_key+="            \"$line\",\n"
        elif [ "$in_ech_configs_section" = true ]; then
            ech_config+="            \"$line\",\n"
        else
            echo "\"$line\"," >&3
        fi
    done
    exec 3>&-
    rm "$input_file"
}

function get_domain() {
    while true; do
        read -p "Please enter domain (disable Cloudflare proxy): " user_domain
        resolved_ipv4=$(dig +short A "$user_domain" 2>/dev/null)
        resolved_ipv6=$(dig +short AAAA "$user_domain" 2>/dev/null)
        if [[ -z $user_domain ]]; then
            echo -e "${RED}Error: Domain cannot be empty, please re-enter!${NC}"
        else
            if [[ ("$resolved_ipv4" == "$ip_v4" && ! -z "$resolved_ipv4") || ("$resolved_ipv6" == "$ip_v6" && ! -z "$resolved_ipv6") ]]; then
                break
            else
                if [[ -z "$resolved_ipv4" && -n "$ip_v4" ]]; then
                    resolved_ip_v4=$(ping -4 "$user_domain" -c 1 2>/dev/null | sed '1{s/[^(]*(//;s/).*//;q}')
                    if [[ ("$resolved_ip_v4" == "$ip_v4" && ! -z "$resolved_ip_v4") ]]; then
                        break
                    fi
                fi
                if [[ -z "$resolved_ipv6" && -n "$ip_v6" ]]; then
                    resolved_ip_v6=$(ping -6 "$user_domain" -c 1 2>/dev/null | sed '1{s/[^(]*(//;s/).*//;q}')
                    if [[ ("$resolved_ip_v6" == "$ip_v6" && ! -z "$resolved_ip_v6") ]]; then
                        break
                    fi
                fi
                echo -e "${RED}Error: Domain is not bound to local IP, please re-enter!${NC}"
            fi
        fi
    done
    domain="$user_domain"
}

function verify_domain() {
    new_domain=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id" \
        -H "Authorization: Bearer $api_token" | jq -r '.result.name')
    if [[ $new_domain =~ \.(tk|ml|ga|gq|cf)$ ]]; then
        echo -e "${RED}Your domain is $new_domain, which does not support using CloudFlare's API to apply for a certificate, please choose another method to apply for the certificate!${NC}"
        domain_supported=false
    else
        while true; do
            read -p "Please enter the main domain prefix (if empty, use the main domain to apply for the certificate, no need to add DNS resolution record in CloudFlare): " domain_prefix

            if [ -z "$domain_prefix" ]; then
                domain="$new_domain"
                record_name="$domain_prefix"
                break
            else
                domain="$domain_prefix"."$new_domain"
                record_name="$domain_prefix"
                break
            fi
        done
        domain_supported=true
    fi
}

function set_dns_record() {
    if [[ -z "$record_name" ]]; then
        name_value="@"
    else
        name_value="$record_name"
    fi
    if [[ -n "$ip_v4" ]]; then
        record_content=" $ip_v4"
        record_type="A"
    elif [[ -z "$ip_v4" && -n "$ip_v6" ]]; then
        record_content=" $ip_v6"
        record_type="AAAA"
    fi
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_Zone_ID/dns_records" \
        -H "Authorization: Bearer $CF_Token" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"$record_type\",\"name\":\"$name_value\",\"content\":\"$record_content\",\"ttl\":120,\"proxied\":false}" >/dev/null
}

function get_api_token() {
    while true; do
        read -p "Please enter CloudFlare's restrictive API token: " api_token
        if [[ ! $api_token =~ ^[A-Za-z0-9_-]{40}$ ]]; then
            echo -e "${RED}Incorrect API token format, please re-enter!${NC}"
        else
            export CF_Token="$api_token"
            break
        fi
    done
}

function get_zone_id() {
    while true; do
        read -p "Please enter CloudFlare's zone ID: " zone_id
        if [[ ! $zone_id =~ ^[a-z0-9]{32}$ ]]; then
            echo -e "${RED}Incorrect CloudFlare zone ID format, please re-enter!${NC}"
        else
            export CF_Zone_ID="$zone_id"
            break
        fi
    done
}

function get_api_email() {
    while true; do
        read -p "Please enter CloudFlare login email: " api_email
        if [[ ! $api_email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$ ]]; then
            echo -e "${RED}Incorrect email format, please re-enter!${NC}"
        else
            export CF_Email="$api_email"
            break
        fi
    done
}

function set_fake_domain() {
    while true; do
        read -p "Please enter spoofed URL (default: www.fan-2000.com): " fake_domain
        fake_domain=${fake_domain:-"www.fan-2000.com"}
        if curl --output /dev/null --silent --head --fail "$fake_domain"; then
            echo "Spoofed URL: $fake_domain"
            break
        else
            echo -e "${RED}Invalid or unavailable spoofed URL, please re-enter!${NC}"
        fi
    done
}

function set_certificate_path() {
    while true; do
        read -p "Please enter PEM certificate location: " certificate_path_input
        if [[ ! -f "$certificate_path_input" ]]; then
            echo -e "${RED}Error: Certificate file does not exist, please re-enter!${NC}"
            continue
        fi
        certificate_file=$(basename "$certificate_path_input")
        allowed_extensions=("crt" "pem")
        if [[ ! "${allowed_extensions[@]}" =~ "${certificate_file##*.}" ]]; then
            echo -e "${RED}Error: Unsupported certificate format, please configure a .crt or .pem format certificate file!${NC}"
            continue
        fi
        certificate_path="$certificate_path_input"
        break
    done
}

function set_private_key_path() {
    while true; do
        read -p "Please enter PEM private key location: " private_key_path_input
        if [[ ! -f "$private_key_path_input" ]]; then
            echo -e "${RED}Error: Private key file does not exist, please re-enter!${NC}"
            continue
        fi
        private_key_file=$(basename "$private_key_path_input")
        allowed_extensions=("key" "pem")
        if [[ ! "${allowed_extensions[@]}" =~ "${private_key_file##*.}" ]]; then
            echo -e "${RED}Error: Unsupported private key format, please configure a .key or .pem format private key file!${NC}"
            continue
        fi
        private_key_path="$private_key_path_input"
        break
    done
}

function apply_certificate() {
    certificate_path="/etc/ssl/private/"$domain".crt"
    private_key_path="/etc/ssl/private/"$domain".key"
    local has_ipv4=false
    local ca_servers=("letsencrypt" "zerossl")
    local return_to_menu=false
    if [[ -n "$ip_v4" ]]; then
        has_ipv4=true
    fi
    echo "Requesting a certificate..."
    curl -s https://get.acme.sh | sh -s email=example@gmail.com 2>&1 | tail -n 1
    alias acme.sh=~/.acme.sh/acme.sh
    for ca_server in "${ca_servers[@]}"; do
        echo "Requesting a certificate from $ca_server..."
        ~/.acme.sh/acme.sh --set-default-ca --server "$ca_server"
        if $has_ipv4; then
            result=$(~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 2>&1)
        else
            result=$(~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --listen-v6 2>&1)
        fi
        if [[ $result == *"force"* ]]; then
            if $has_ipv4; then
                result=$(~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --force 2>&1)
            else
                result=$(~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --listen-v6 --force 2>&1)
            fi
        fi
        if [[ $result == *"log"* || $result == *"debug"* || $result == *"error"* ]]; then
            echo -e "${RED}$result ${NC}"
            continue
        fi
        if [[ $? -eq 0 ]]; then
            echo "Installing the certificate..."
            ~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --key-file "$private_key_path" --fullchain-file "$certificate_path"
            break
        else
            echo -e "${RED}Failed to obtain a certificate from $ca_server!${NC}"
            return_to_menu=true
        fi
    done
    if [ "$return_to_menu" = true ]; then
        echo -e "${RED}Certificate application failed, please use another method to apply for the certificate!${NC}"
        return 1
    fi
}

function Apply_api_certificate() {
    certificate_path="/etc/ssl/private/"$domain".crt"
    private_key_path="/etc/ssl/private/"$domain".key"
    local has_ipv4=false
    local ca_servers=("letsencrypt" "zerossl")
    if [[ -n "$ip_v4" ]]; then
        has_ipv4=true
    fi
    echo "Requesting a certificate..."
    curl -s https://get.acme.sh | sh -s email=example@gmail.com 2>&1 | tail -n 1
    alias acme.sh=~/.acme.sh/acme.sh
    for ca_server in "${ca_servers[@]}"; do
        echo "Requesting a certificate from $ca_server..."
        ~/.acme.sh/acme.sh --set-default-ca --server "$ca_server"
        if $has_ipv4; then
            result=$(~/.acme.sh/acme.sh --issue --dns dns_cf -d "$domain" -k ec-256 2>&1)
        else
            result=$(~/.acme.sh/acme.sh --issue --dns dns_cf -d "$domain" -k ec-256 --listen-v6 2>&1)
        fi
        if [[ $result == *"log"* || $result == *"debug"* || $result == *"error"* || $result == *"force"* ]]; then
            echo -e "${RED}$result ${NC}"
            return_to_menu=true
            continue
        fi
        if [[ $? -eq 0 ]]; then
            echo "Installing the certificate..."
            ~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --key-file "$private_key_path" --fullchain-file "$certificate_path"
            break
        else
            echo -e "${RED}Failed to obtain a certificate from $ca_server!${NC}"
            return_to_menu=true
        fi
    done
    if [ "$return_to_menu" = true ]; then
        echo -e "${RED}Certificate application failed, please use another method to apply for the certificate!${NC}"
        return 1
    fi
}

function Reapply_certificates() {
    local tls_info_file="/usr/local/etc/sing-box/tls_info.json"
    local has_ipv4=false
    if [ -n "$ip_v4" ]; then
        has_ipv4=true
    fi
    if ! command -v acme.sh &>/dev/null; then
        curl -s https://get.acme.sh | sh -s email=example@gmail.com
    fi
    alias acme.sh=~/.acme.sh/acme.sh
    echo "Setting CA server to Let's Encrypt..."
    ~/.acme.sh/acme.sh --set-default-ca --server "letsencrypt"
    jq -c '.[]' "$tls_info_file" | while read -r tls_info; do
        server_name=$(echo "$tls_info" | jq -r '.server_name')
        key_path=$(echo "$tls_info" | jq -r '.key_path')
        certificate_path=$(echo "$tls_info" | jq -r '.certificate_path')
        echo "Requesting certificate for $server_name..."
        result=$(
            if $has_ipv4; then
                ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$server_name" -k ec-256 --force
            else
                ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$server_name" -k ec-256 --listen-v6 --force
            fi
        )
        if [[ "$result" =~ "Cert success." ]]; then
            echo "Certificate for $server_name has been applied using Cloudflare DNS verification."
        else
            echo "Cloudflare DNS verification failed for $server_name. Trying standalone verification..."
            result=$(
                if $has_ipv4; then
                    ~/.acme.sh/acme.sh --issue -d "$server_name" --standalone --force
                else
                    ~/.acme.sh/acme.sh --issue -d "$server_name" --standalone --listen-v6 --force
                fi
            )
            if [[ "$result" =~ "BEGIN CERTIFICATE" && "$result" =~ "END CERTIFICATE" ]]; then
                echo "Certificate for $server_name has been applied using Let's Encrypt CA."
            else
                echo "Failed to obtain certificate for $server_name using standalone verification as well."
                return 1
            fi
        fi
        ~/.acme.sh/acme.sh --install-cert -d "$server_name" --ecc --key-file "$key_path" --fullchain-file "$certificate_path"
        echo "Certificate for $server_name has been installed."
    done
    rm -f "$tls_info_file"
}

function generate_private_key() {
    while true; do
        read -p "Please enter private key (default: generate a random private key): " local_private_key
        if [[ -z "$local_private_key" ]]; then
            local keypair_output=$(sing-box generate reality-keypair)
            local_private_key=$(echo "$keypair_output" | awk -F: '/PrivateKey/{gsub(/ /, "", $2); print $2}')
            local_public_key=$(echo "$keypair_output" | awk -F: '/PublicKey/{gsub(/ /, "", $2); print $2}')
            echo "private_key: $local_private_key"
            echo "public_key: $local_public_key"
            break
        else
            if [[ "$local_private_key" =~ ^[A-Za-z0-9_\-]{43}$ ]]; then
                read -p "Please enter public key: " local_public_key
                if ! [[ "$local_public_key" =~ ^[A-Za-z0-9_\-]{43}$ ]]; then
                    echo -e "${RED}Invalid public key, please re-enter!${NC}"
                else
                    break
                fi
            else
                echo -e "${RED}Invalid private key, please re-enter!${NC}"
            fi
        fi
    done
    public_key="$local_public_key"
    private_key="$local_private_key"
}

function create_self_signed_cert() {
    while true; do
        read -p "Please enter the domain for the self-signed certificate (default is bing.com): " user_domain
        domain_name=${user_domain:-"bing.com"}
        if curl --output /dev/null --silent --head --fail "$domain_name"; then
            openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout /etc/ssl/private/$domain_name.key -out /etc/ssl/private/$domain_name.crt -subj "/CN=$domain_name" -days 36500
            chmod 777 /etc/ssl/private/$domain_name.key
            chmod 777 /etc/ssl/private/$domain_name.crt
            break
        else
            echo -e "${RED}Invalid or unavailable domain name, please enter a valid domain!${NC}"
        fi
    done
    certificate_path="/etc/ssl/private/$domain_name.crt"
    private_key_path="/etc/ssl/private/$domain_name.key"
}

function select_encryption_method() {
    while true; do
        read -p "Please select encryption method (default 1):
1). 2022-blake3-chacha20-poly1305
2). 2022-blake3-aes-256-gcm
3). 2022-blake3-aes-128-gcm
4). xchacha20-ietf-poly1305
5). chacha20-ietf-poly1305
6). aes-256-gcm
7). aes-192-gcm
8). aes-128-gcm
Select [1-8]: " encryption_choice
        encryption_choice=${encryption_choice:-1}
        case $encryption_choice in
        1)
            ss_method="2022-blake3-chacha20-poly1305"
            ss_password=$(sing-box generate rand --base64 32)
            shadowtls_password=$(sing-box generate rand --base64 32)
            break
            ;;
        2)
            ss_method="2022-blake3-aes-256-gcm"
            ss_password=$(sing-box generate rand --base64 32)
            shadowtls_password=$(sing-box generate rand --base64 32)
            break
            ;;
        3)
            ss_method="2022-blake3-aes-128-gcm"
            ss_password=$(sing-box generate rand --base64 16)
            shadowtls_password=$(sing-box generate rand --base64 16)
            break
            ;;

        4)
            ss_method="xchacha20-ietf-poly1305"
            ss_password=$(sing-box generate rand --base64 16)
            shadowtls_password=$(sing-box generate rand --base64 16)
            break
            ;;
        5)
            ss_method="chacha20-ietf-poly1305"
            ss_password=$(sing-box generate rand --base64 16)
            shadowtls_password=$(sing-box generate rand --base64 16)
            break
            ;;
        6)
            ss_method="aes-256-gcm"
            ss_password=$(sing-box generate rand --base64 16)
            shadowtls_password=$(sing-box generate rand --base64 16)
            break
            ;;
        7)
            ss_method="aes-192-gcm"
            ss_password=$(sing-box generate rand --base64 16)
            shadowtls_password=$(sing-box generate rand --base64 16)
            break
            ;;
        8)
            ss_method="aes-128-gcm"
            ss_password=$(sing-box generate rand --base64 16)
            shadowtls_password=$(sing-box generate rand --base64 16)
            break
            ;;
        *)
            echo -e "${RED}Error: Invalid selection, please try again!${NC}"
            ;;
        esac
    done
}

function select_unlocked_items() {
    while true; do
        read -p "Please select items to unlock (supports multiple selection):
1). ChatGPT
2). Netflix
3). Disney+
4). YouTube
5). Google
6). Spotify
7). Reddit
Select [1-7]: " choices
        if [[ "$choices" =~ ^[1234567]+$ ]]; then
            selected=($(echo "$choices" | sed 's/./& /g'))
            break
        else
            echo -e "${RED}Error: Invalid selection, please try again!${NC}"
        fi
    done
}

function update_geosite_array() {
    for choice in "${selected[@]}"; do
        case $choice in
        1)
            geosite+=("\"openai\"")
            ;;
        2)
            geosite+=("\"netflix\"")
            ;;
        3)
            geosite+=("\"disney\"")
            ;;
        4)
            geosite+=("\"youtube\"")
            ;;
        5)
            geosite+=("\"google\"")
            ;;
        6)
            geosite+=("\"spotify\"")
            ;;  
        7)
            geosite+=("\"reddit\"")
            ;;    
        *)
            echo -e "${RED}Invalid choice: $choice${NC}"
            ;;
        esac
    done
}

function select_outbound() {
    while true; do
        read -p "Please select outbound network (default 1):
1). warp-IPv4
2). warp-IPv6
Select [1-2]: " outbound_choice
        case $outbound_choice in
        1 | "")
            outbound="wireguard-ep"
            warp_strategy="ipv4_only"
            break
            ;;
        2)
            outbound="wireguard-ep"
            warp_strategy="ipv6_only"
            break
            ;;
        *)
            echo -e "${RED}Error: Invalid option, please enter a valid choice!${NC}"
            ;;
        esac
    done
}

function select_congestion_control() {
    local default_congestion_control="bbr"
    while true; do
        read -p "Please select congestion control algorithm (default $default_congestion_control):
1). bbr
2). cubic
3). new_reno
Select [1-3]: " congestion_control

        case $congestion_control in
        1)
            congestion_control="bbr"
            break
            ;;
        2)
            congestion_control="cubic"
            break
            ;;
        3)
            congestion_control="new_reno"
            break
            ;;
        "")
            congestion_control=$default_congestion_control
            break
            ;;
        *)
            echo -e "${RED}Error: Invalid choice, please try again!${NC}"
            ;;
        esac
    done
}

function select_certificate_option() {
    local certificate_option
    local domain_supported=false
    local return_to_menu=false
    while true; do
        read -p "Please select certificate source (default 1):
1). Self-signed certificate
2). Request certificate listening on port 80 (standalone mode)
3). Cloudflare API certificate request (DNS API mode)
4). Custom certificate path
Select [1-4]: " certificate_option
        certificate_option=${certificate_option:-1}
        case $certificate_option in
        1)
            if $disable_option; then
                echo -e "${RED}NaiveProxy node doesn't support self-signed certificates, please use acme to request a certificate!${NC}"
                continue
            fi
            check_firewall_configuration
            create_self_signed_cert
            break
            ;;
        2)
            get_local_ip
            get_domain
            check_firewall_configuration
            apply_certificate
            if [ "$return_to_menu" == true ]; then
                return_to_menu=false
                continue
            fi
            break
            ;;
        3)
            get_local_ip
            get_api_token
            get_zone_id
            get_api_email
            verify_domain
            set_dns_record
            check_firewall_configuration
            if [ "$domain_supported" == "false" ]; then
                continue
            else
                Apply_api_certificate
                if [ "$return_to_menu" == true ]; then
                    return_to_menu=false
                    continue
                fi
                break
            fi
            ;;
        4)
            get_local_ip
            get_domain
            check_firewall_configuration
            set_certificate_path
            set_private_key_path
            break
            ;;
        *)
            echo -e "${RED}Error: Invalid selection, please try again!${NC}"
            ;;
        esac
    done
}

function select_vmess_type() {
    while true; do
        read -p "Please select node type (default 1):
1). VMess+TCP
2). VMess+WebSocket
3). VMess+gRPC
4). VMess+HTTPUpgrade
5). VMess+TCP+TLS
6). VMess+WebSocket+TLS
7). VMess+H2C+TLS
8). VMess+gRPC+TLS
9). VMess+HTTPUpgrade+TLS
Select [1-9]: " node_type
        case $node_type in
        "" | 1)
            tls_enabled=false
            break
            ;;
        2)
            transport_ws=true
            tls_enabled=false
            break
            ;;
        3)
            transport_grpc=true
            tls_enabled=false
            break
            ;;
        4)
            transport_httpupgrade=true
            tls_enabled=false
            break
            ;;
        5)
            tls_enabled=true
            break
            ;;
        6)
            transport_ws=true
            tls_enabled=true
            break
            ;;
        7)
            transport_http=true
            tls_enabled=true
            break
            ;;
        8)
            transport_grpc=true
            tls_enabled=true
            break
            ;;
        9)
            transport_httpupgrade=true
            tls_enabled=true
            break
            ;;
        *)
            echo -e "${RED}Invalid selection, please try again!${NC}"
            ;;
        esac
    done
}

function select_vless_type() {
    while true; do
        read -p "Please select node type (default 1):     
1). VLESS+TCP
2). VLESS+WebSocket
3). VLESS+gRPC
4). VLESS+HTTPUpgrade
5). VLESS+Vision+REALITY
6). VLESS+H2C+REALITY
7). VLESS+gRPC+REALITY
Select [1-7]: " flow_option
        case $flow_option in
        "" | 1)
            flow_type=""
            break
            ;;
        2)
            flow_type=""
            transport_ws=true
            break
            ;;
        3)
            flow_type=""
            transport_grpc=true
            break
            ;;
        4)
            flow_type=""
            transport_httpupgrade=true
            break
            ;;
        5)
            flow_type="xtls-rprx-vision"
            reality_enabled=true
            break
            ;;
        6)
            flow_type=""
            transport_http=true
            reality_enabled=true
            break
            ;;
        7)
            flow_type=""
            transport_grpc=true
            reality_enabled=true
            break
            ;;
        *)
            echo -e "${RED}Invalid option, please try again!${NC}" >&2
            ;;
        esac
    done
}

function select_trojan_type() {
    while true; do
        read -p "Please select node type (default 1):
1). Trojan+TCP
2). Trojan+WebSocket
3). Trojan+gRPC
4). Trojan+HTTPUpgrade
5). Trojan+TCP+TLS
6). Trojan+WebSocket+TLS
7). Trojan+H2C+TLS
8). Trojan+gRPC+TLS
9). Trojan+HTTPUpgrade+TLS
Select [1-9]: " setup_type
        case $setup_type in
        "" | 1)
            tls_enabled=false
            break
            ;;
        2)
            transport_ws=true
            tls_enabled=false
            break
            ;;
        3)
            transport_grpc=true
            tls_enabled=false
            break
            ;;
        4)
            transport_httpupgrade=true
            tls_enabled=false
            break
            ;;
        5)
            tls_enabled=true
            break
            ;;
        6)
            transport_ws=true
            tls_enabled=true
            break
            ;;
        7)
            transport_http=true
            tls_enabled=true
            break
            ;;
        8)
            transport_grpc=true
            tls_enabled=true
            break
            ;;
        9)
            transport_httpupgrade=true
            tls_enabled=true
            break
            ;;
        *)
            echo -e "${RED}Invalid selection, please try again!${NC}"
            ;;
        esac
    done
}

function set_short_id() {
    while true; do
        read -p "Please enter Short_Id (used to distinguish different clients, default is randomly generated): " short_id
        if [[ -z "$short_id" ]]; then
            short_id=$(openssl rand -hex 8)
            echo "Short_Id: $short_id"
            break
        elif [[ "$short_id" =~ ^[0-9a-fA-F]{2,16}$ ]]; then
            echo "Short_Id: $short_id"
            break
        else
            echo "Error: Please enter a hexadecimal string between two to sixteen characters!"
        fi
    done
    short_ids+=("$short_id")
}

function set_short_ids() {
    while true; do
        set_short_id
        for ((i = 0; i < ${#short_ids[@]}; i++)); do
            short_id="${short_ids[$i]}"
        done
        read -p "Would you like to continue adding short ids? (Y/N, default N): " -e choice
        if [[ -z "$choice" ]]; then
            choice="N"
        fi
        if [[ "$choice" == "N" || "$choice" == "n" ]]; then
            short_Ids+="\n            \"$short_id\""
            break
        elif [[ "$choice" == "Y" || "$choice" == "y" ]]; then
            short_Ids+="\n            \"$short_id\","
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function tuic_multiple_users() {
    while true; do
        set_user_name
        set_user_password
        set_uuid
        for ((i = 0; i < ${#user_names[@]}; i++)); do
            user_name="${user_names[$i]}"
            user_uuid="${user_uuids[$i]}"
            user_password="${user_passwords[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"uuid\": \"$user_uuid\",\n          \"password\": \"$user_password\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"uuid\": \"$user_uuid\",\n          \"password\": \"$user_password\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function vmess_multiple_users() {
    while true; do
        set_uuid
        for ((i = 0; i < ${#user_uuids[@]}; i++)); do
            user_uuid="${user_uuids[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"uuid\": \"$user_uuid\",\n          \"alterId\": 0\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"uuid\": \"$user_uuid\",\n          \"alterId\": 0\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function vless_multiple_users() {
    while true; do
        set_uuid
        for ((i = 0; i < ${#user_uuids[@]}; i++)); do
            user_uuid="${user_uuids[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"uuid\": \"$user_uuid\",\n          \"flow\": \"$flow_type\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"uuid\": \"$user_uuid\",\n          \"flow\": \"$flow_type\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function socks_naive_multiple_users() {
    while true; do
        set_user_name
        set_user_password
        for ((i = 0; i < ${#user_names[@]}; i++)); do
            user_name="${user_names[$i]}"
            user_password="${user_passwords[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"username\": \"$user_name\",\n          \"password\": \"$user_password\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"username\": \"$user_name\",\n          \"password\": \"$user_password\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function hysteria_multiple_users() {
    while true; do
        set_user_name
        set_user_password
        for ((i = 0; i < ${#user_names[@]}; i++)); do
            user_name="${user_names[$i]}"
            user_password="${user_passwords[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"auth_str\": \"$user_password\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"auth_str\": \"$user_password\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function hy2_multiple_users() {
    while true; do
        set_user_name
        set_user_password
        for ((i = 0; i < ${#user_names[@]}; i++)); do
            user_name="${user_names[$i]}"
            user_password="${user_passwords[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"password\": \"$user_password\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"password\": \"$user_password\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function trojan_multiple_users() {
    while true; do
        set_user_password
        for ((i = 0; i < ${#user_passwords[@]}; i++)); do
            user_password="${user_passwords[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"password\": \"$user_password\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"password\": \"$user_password\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function shadowtls_multiple_users() {
    while true; do
        set_user_name
        set_stls_password
        for ((i = 0; i < ${#user_names[@]}; i++)); do
            user_name="${user_names[$i]}"
            stls_password="${stls_passwords[$i]}"
        done
        read -p "Would you like to continue adding users? (Y/N, default N): " -e add_multiple_users
        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi
        if [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"password\": \"$stls_password\"\n        }"
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            users+="\n        {\n          \"name\": \"$user_name\",\n          \"password\": \"$stls_password\"\n        },"
            continue
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function generate_transport_config() {
    if [[ "$transport_ws" = true ]]; then
        read -p "Please enter the ws path (default: randomly generated): " transport_path_input
        transport_path=${transport_path_input:-/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)}
        if [[ ! "$transport_path" =~ ^/ ]]; then
            transport_path="/$transport_path"
        fi
        transport_config="\n      \"transport\": {\n        \"type\": \"ws\",\n        \"path\": \"$transport_path\",\n        \"max_early_data\": 2048,\n        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"\n      },"
    elif [[ "$transport_httpupgrade" = true ]]; then
        transport_path=${transport_path_input:-/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)}
        if [[ ! "$transport_path" =~ ^/ ]]; then
            transport_path="/$transport_path"
        fi
        transport_config="\n      \"transport\": {\n        \"type\": \"httpupgrade\",\n        \"path\": \"$transport_path\"\n      },"
    elif [[ "$transport_grpc" = true ]]; then
        service_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
        transport_config="\n      \"transport\": {\n        \"type\": \"grpc\",\n        \"service_name\": \"$service_name\"\n      },"
    elif [[ "$transport_http" = true ]]; then
        transport_config="\n      \"transport\": {\n        \"type\": \"http\"\n      },"
    else
        transport_config=""
    fi
}

function generate_tls_config() {
    if [[ "$tls_enabled" = true ]]; then
        select_certificate_option
        set_ech_config
    fi
    if [ -z "$domain_name" ]; then
        if [ -n "$domain" ]; then
            server_name="$domain"
        fi
    else
        server_name="$domain_name"
    fi

    if [[ "$tls_enabled" = true ]]; then
        tls_config=",\n      \"tls\": {\n        \"enabled\": true,\n        \"server_name\": \"$server_name\",\n        \"certificate_path\": \"$certificate_path\",\n        \"key_path\": \"$private_key_path\"$ech_server_config\n      }"
    fi
}

function set_ech_config() {
    while true; do
        read -p "Enable ECH? (Y/N, default: Y):" enable_ech
        enable_ech="${enable_ech:-Y}"
        if [[ "$enable_ech" == "y" || "$enable_ech" == "Y" ]]; then
            get_ech_keys
            enable_ech=true
            ech_server_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"key\": [\n$ech_key\n          ]\n        }"
            break
        elif [[ "$enable_ech" == "n" || "$enable_ech" == "N" ]]; then
            enable_ech=false
            ech_server_config=""
            break
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function generate_reality_config() {
    if [[ "$reality_enabled" = true ]]; then
        set_server_name
        set_target_server
        generate_private_key
        set_short_ids
        reality_config=",\n      \"tls\": {\n        \"enabled\": true,\n        \"server_name\": \"$server_name\",\n        \"reality\": {\n          \"enabled\": true,\n          \"handshake\": {\n            \"server\": \"$target_server\",\n            \"server_port\": 443\n          },\n          \"private_key\": \"$private_key\",\n          \"short_id\": [$short_Ids\n          ]\n        }\n      }"
    fi
}

function configure_quic_obfuscation() {
    while true; do
        read -p "Enable QUIC traffic obfuscation (if your network blocks QUIC or HTTP/3 traffic, choose to enable)? (Y/N, default: N): " choice
        choice="${choice:-N}"
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            read -p "Enter obfuscation password (default: randomly generated): " new_obfs_password
            if [[ -z "$new_obfs_password" ]]; then
                new_obfs_password=$(sing-box generate rand --base64 9 2>/dev/null || openssl rand -base64 9)
            fi
            obfs_config="\n      \"obfs\": {\n        \"type\": \"salamander\",\n        \"password\": \"$new_obfs_password\"\n      },"
            obfs_password="$new_obfs_password"
            echo "Obfuscation password: $obfs_password"
            break
        elif [[ "$choice" == "n" || "$choice" == "N" ]]; then
            obfs_config=""
            break
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function configure_obfuscation() {
    while true; do
        read -p "Enable obfuscation (used to bypass targeted DPI blocking or QoS)? (Y/N, default: N): " choice
        choice="${choice:-N}"
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            read -p "Enter obfuscation password (default: randomly generated): " new_obfs_password
            if [[ -z "$new_obfs_password" ]]; then
                new_obfs_password=$(sing-box generate rand --base64 9 2>/dev/null || openssl rand -base64 9)
            fi
            obfs_config="\n      \"obfs\": \"$new_obfs_password\","
            obfs_password="$new_obfs_password"
            echo "Obfuscation password: $obfs_password"
            break
        elif [[ "$choice" == "n" || "$choice" == "N" ]]; then
            obfs_config=""
            break
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function configure_multiplex() {
    while true; do
        read -p "Enable multiplexing? (Y/N, default: Y): " choice
        choice="${choice:-Y}"
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            configure_brutal
            multiplex_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"padding\": false$brutal_config\n      }"
            break
        elif [[ "$choice" == "n" || "$choice" == "N" ]]; then
            multiplex_config=""
            break
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function configure_brutal() {
    while true; do
        read -p "Enable TCP Brutal? (Y/N, default: N): " choice
        choice="${choice:-N}"
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            set_up_speed
            set_down_speed
            brutal_config=",\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $up_mbps,\n          \"down_mbps\": $down_mbps\n        }"
            break
        elif [[ "$choice" == "n" || "$choice" == "N" ]]; then
            brutal_config=""
            break
        else
            echo -e "${RED}Invalid input, please try again!${NC}"
        fi
    done
}

function extract_tls_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tls_info_file="/usr/local/etc/sing-box/tls_info.json"
    jq '.inbounds[].tls | select(.server_name and .certificate_path and .key_path) | {server_name: .server_name, certificate_path: .certificate_path, key_path: .key_path}' "$config_file" | jq -s 'unique' >"$tls_info_file"
}

function validate_tls_info() {
    local tls_info_file="/usr/local/etc/sing-box/tls_info.json"
    local temp_tls_file="/usr/local/etc/sing-box/temp_tls_info.json"
    server_names=($(jq -r '.[].server_name' "$tls_info_file"))
    for server_name in "${server_names[@]}"; do
        local resolved_ipv4=$(dig +short A "$server_name" 2>/dev/null)
        local resolved_ipv6=$(dig +short AAAA "$server_name" 2>/dev/null)
        if [[ (-n "$resolved_ipv4" && "$resolved_ipv4" == "$ip_v4") || (-n "$resolved_ipv6" && "$resolved_ipv6" == "$ip_v6") ]]; then
            continue
        else
            jq 'map(select(.server_name != "'"$server_name"'"))' "$tls_info_file" >"$temp_tls_file"
            mv "$temp_tls_file" "$tls_info_file"
        fi
    done
}

function modify_route_rules() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local temp_config_file="/usr/local/etc/sing-box/temp_config.json"
    jq '.route.rules = (
        [{"action": "sniff"}]
        + ((.route.rules // []) | map(select(.action != "sniff" and .rule_set != null)))
        + ((.route.rules // []) | map(select(.action != "sniff" and .rule_set == null)))
    )' "$config_file" >"$temp_config_file" && mv "$temp_config_file" "$config_file"
}

function extract_variables_and_cleanup() {
    if jq -e '.peers[0]' "$temp_file" >/dev/null 2>&1; then
        server=$(jq -r '.peers[0].address' "$temp_file")
        server_port=$(jq -r '.peers[0].port' "$temp_file")
        local_address_ipv4=$(jq -r '.address[0]' "$temp_file")
        local_address_ipv6=$(jq -r '.address[1] // empty' "$temp_file")
        private_key=$(jq -r '.private_key' "$temp_file")
        peer_public_key=$(jq -r '.peers[0].public_key' "$temp_file")
        reserved=$(jq -c '.peers[0].reserved // [0,0,0]' "$temp_file")
    else
        server=$(jq -r '.server' "$temp_file")
        server_port=$(jq -r '.server_port' "$temp_file")
        local_address_ipv4=$(jq -r '.local_address[0]' "$temp_file")
        local_address_ipv6=$(jq -r '.local_address[1] // empty' "$temp_file")
        private_key=$(jq -r '.private_key' "$temp_file")
        peer_public_key=$(jq -r '.peer_public_key' "$temp_file")
        reserved=$(jq -c '.reserved // [0,0,0]' "$temp_file")
    fi
    mtu=$(jq -r '.mtu // 1280' "$temp_file")
    rm "$temp_file"
}

function check_sing_box_version() {
    if ! command -v sing-box >/dev/null 2>&1; then
        return 0
    fi
    local version major minor
    version=$(sing-box version 2>/dev/null | head -n 1 | awk '{print $3}')
    version=${version#v}
    major=${version%%.*}
    minor=${version#*.}
    minor=${minor%%.*}
    if [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]]; then
        if ((major < 1 || (major == 1 && minor < 14))); then
            echo -e "${YELLOW}Warning: installed sing-box is $version, but the configuration generated by this script targets sing-box 1.14 or newer. Please update the kernel from the main menu first!${NC}"
        fi
    fi
}

function expand_empty_arrays() {
    local config_file="/usr/local/etc/sing-box/config.json"
    sed -i -E 's/^([[:space:]]*"(inbounds|rules)": )\[\](,?)[[:space:]]*$/\1[\n  ]\3/' "$config_file"
}

function validate_sing_box_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local result
    if ! command -v sing-box >/dev/null 2>&1; then
        return 0
    fi
    if ! result=$(sing-box check -c "$config_file" 2>&1); then
        echo -e "${RED}sing-box configuration check failed:${NC}"
        echo "$result"
        echo -e "${YELLOW}If a backup (config.json.bak-*) exists in /usr/local/etc/sing-box, you can restore it.${NC}"
        return 1
    fi
    return 0
}

function migrate_existing_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tmp_file="/usr/local/etc/sing-box/config.migrate.tmp"
    [[ -s "$config_file" ]] || return 0
    jq empty "$config_file" >/dev/null 2>&1 || return 0
    jq '
    def ensure_local_dns:
        .dns.servers = ((.dns.servers // []) | if any(.[]; .tag == "local") then . else . + [{"type": "local", "tag": "local"}] end);
    def to_array: if type == "array" then . else [.] end;

    .inbounds = ((.inbounds // []) | map(
        del(.sniff, .sniff_override_destination, .sniff_timeout, .proxy_protocol, .proxy_protocol_accept_no_header)
        | if (.tls.ech // null) != null then .tls.ech |= del(.pq_signature_schemes_enabled, .dynamic_record_sizing_disabled) else . end
    ))
    | .route = (.route // {})
    | .route.rules = (.route.rules // [])
    | del(.route.geoip, .route.geosite)
    | ([.route.rules[] | select(.geosite != null) | (.geosite | to_array)[] | "geosite-" + .] | unique) as $gs_tags
    | .route.rules |= map(if .geosite != null then (.rule_set = (.geosite | to_array | map("geosite-" + .))) | del(.geosite) else . end)
    | (.route.rule_set // []) as $old_sets
    | .route.rule_set = ($old_sets + ($gs_tags | map(select(. as $t | ($old_sets | map(.tag) | index($t)) == null)) | map({tag: ., type: "remote", format: "binary", url: ("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/" + . + ".srs")})))
    | if (.route.rule_set | length) == 0 then del(.route.rule_set) else . end
    | if ((.route.rule_set // []) | any(.[]; .type == "remote")) then
        .route.rule_set |= map(del(.download_detour))
        | .http_clients = ((.http_clients // []) | if any(.[]; .tag == "direct-http") then . else . + [{"tag": "direct-http", "detour": "direct"}] end)
        | .route.default_http_client = (.route.default_http_client // "direct-http")
        | .experimental.cache_file.enabled = true
      else . end
    | (.outbounds // []) as $obs
    | ($obs | map(select(.type == "direct" and (.detour == "wireguard-out" or .detour == "wireguard-ep")) | {key: .tag, value: (.domain_strategy // .domain_resolver.strategy // "prefer_ipv4")}) | from_entries) as $warp
    | ($obs | map(select(.type == "wireguard"))) as $wgs
    | if ($wgs | length) > 0 then
        .endpoints = ((.endpoints // []) + ($wgs | map({
            type: "wireguard",
            tag: ((.tag // "wireguard-ep") | if . == "wireguard-out" then "wireguard-ep" else . end),
            mtu: (.mtu // 1408),
            address: (.local_address // []),
            private_key: .private_key,
            peers: [({address: .server, port: .server_port, public_key: .peer_public_key, allowed_ips: ["0.0.0.0/0", "::/0"], reserved: (.reserved // [0, 0, 0])}
                     + (if .pre_shared_key then {pre_shared_key: .pre_shared_key} else {} end))]
        })))
        | .outbounds = ($obs | map(select(.type != "wireguard")))
        | .route.rules |= map(if .outbound == "wireguard-out" then .outbound = "wireguard-ep" else . end)
      else . end
    | .route.rules |= (map(if (.outbound != null and $warp[.outbound] != null) then
            [((del(.outbound, .action)) + {"action": "resolve", "strategy": $warp[.outbound]}), (. + {"action": "route", "outbound": "wireguard-ep"})]
        else [.] end) | add // [])
    | .outbounds |= map(select((.tag as $t | $warp[$t]) == null))
    | .outbounds = ((.outbounds // []) | map(select(.type != "block" and .type != "dns")))
    | .route.rules |= map(if .outbound == "block" then (del(.outbound) | .action = "reject") else . end)
    | .outbounds |= map(if .domain_strategy != null then (.domain_resolver = {"server": "local", "strategy": .domain_strategy}) | del(.domain_strategy) else . end)
    | if (any(.outbounds[]; .domain_resolver != null) or any(.route.rules[]; .action == "resolve")) then (ensure_local_dns | .route.default_domain_resolver = (.route.default_domain_resolver // "local")) else . end
    | .route.rules |= map(if .action == null and .outbound != null then .action = "route" else . end)
    | .route.rules = ([{"action": "sniff"}] + (.route.rules | map(select(.action != "sniff"))))
    ' "$config_file" >"$tmp_file" 2>/dev/null
    if [[ $? -ne 0 || ! -s "$tmp_file" ]]; then
        rm -f "$tmp_file"
        return 1
    fi
    if ! cmp -s <(jq -S . "$config_file") <(jq -S . "$tmp_file"); then
        cp "$config_file" "${config_file}.bak-$(date +%Y%m%d%H%M%S)"
        mv "$tmp_file" "$config_file"
        echo "Existing sing-box configuration has been migrated to the current format (backup saved as config.json.bak-*)."
    else
        rm -f "$tmp_file"
    fi
}

function log_outbound_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    check_sing_box_version
    if ! grep -q '"log": {' "$config_file" || ! grep -q '"route": {' "$config_file" || ! grep -q '"inbounds": \[' "$config_file" || ! grep -q '"outbounds": \[' "$config_file"; then
        cat >"$config_file" <<'EOF'
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "local"
      }
    ]
  },
  "route": {
    "rules": [
      {
        "action": "sniff"
      }
    ],
    "default_domain_resolver": "local"
  },
  "inbounds": [
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
    else
        migrate_existing_config
    fi
    expand_empty_arrays
}

function modify_format_inbounds_and_outbounds() {
    local file_path="/usr/local/etc/sing-box/config.json"
    sed -z -E -i 's/,([[:space:]]*[]}])/\1/g' "$file_path"
    if jq empty "$file_path" >/dev/null 2>&1; then
        jq . "$file_path" >"$file_path.tmp" && mv "$file_path.tmp" "$file_path"
    else
        echo -e "${RED}Warning: the generated config.json is not valid JSON!${NC}"
    fi
}

function generate_http_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    tls_enabled=true
    local tag_label
    generate_unique_tag
    set_listen_port
    socks_naive_multiple_users
    get_local_ip
    generate_tls_config
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v tls_config="$tls_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"http\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"set_system_proxy\": false,"; print "      \"users\": [" users ""; print "      ]" tls_config ""; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v target_address="$target_address" -v override_port="$override_port" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"override_address\": \"" target_address "\","; print "      \"override_port\": " override_port; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_ss_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    configure_multiplex
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" -v multiplex_config="$multiplex_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"method\": \"" ss_method "\","; print "      \"password\": \"" ss_password "\"" multiplex_config ""; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_vmess_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local tag_label
    generate_unique_tag
    select_vmess_type
    set_listen_port
    vmess_multiple_users
    generate_transport_config
    if [ "$transport_grpc" != true ] && [ "$transport_http" != true ]; then
        configure_multiplex
    fi
    get_local_ip
    generate_tls_config
    check_firewall_configuration
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v transport_config="$transport_config" -v tls_config="$tls_config" -v multiplex_config="$multiplex_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "" transport_config ""; print "      \"users\": [" users ""; print "      ]" tls_config "" multiplex_config ""; print "    },"; found=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_socks_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    set_listen_port
    socks_naive_multiple_users
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"socks\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"users\": [" users ""; print "      ]"; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_naive_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    disable_option=true
    local tag_label
    generate_unique_tag
    set_listen_port
    socks_naive_multiple_users
    get_local_ip
    select_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"naive\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"users\": [" users ""; print "      ],"; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_tuic_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    set_listen_port
    tuic_multiple_users
    select_congestion_control
    get_local_ip
    select_certificate_option
    set_ech_config
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local found_rules=0
    local found_inbounds=0
    local server_name="$domain"
    if [ -z "$domain" ]; then
        server_name="$domain_name"
    fi
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v congestion_control="$congestion_control" -v server_name="$server_name" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" -v ech_server_config="$ech_server_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"users\": [" users ""; print "      ],"; print "      \"congestion_control\": \"" congestion_control "\","; print "      \"auth_timeout\": \"3s\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\"" ech_server_config ""; print "      }"; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    set_listen_port
    set_up_speed
    set_down_speed
    hysteria_multiple_users
    configure_obfuscation
    get_local_ip
    select_certificate_option
    set_ech_config
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local found_rules=0
    local found_inbounds=0
    local server_name="$domain"
    if [ -z "$domain" ]; then
        server_name="$domain_name"
    fi
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v obfs_config="$obfs_config" -v users="$users" -v server_name="$server_name" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" -v ech_server_config="$ech_server_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"up_mbps\": " up_mbps ","; print "      \"down_mbps\": " down_mbps ","obfs_config""; print "      \"users\": [" users ""; print "      ],"; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\"" ech_server_config ""; print "      }"; print "    },"; found_inbounds=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    tag_label1="$tag_label"
    generate_unique_tag
    tag_label2="$tag_label"
    set_listen_port
    select_encryption_method
    shadowtls_multiple_users
    set_ss_password
    set_target_server
    configure_multiplex
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label1="$tag_label1" -v tag_label2="$tag_label2" -v listen_port="$listen_port" -v users="$users" -v target_server="$target_server" -v ss_method="$ss_method" -v ss_password="$ss_password" -v multiplex_config="$multiplex_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label1 "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"" tag_label1 "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"version\": 3,"; print "      \"users\": [" users ""; print "      ],"; print "      \"handshake\": {"; print "        \"server\": \"" target_server "\","; print "        \"server_port\": 443"; print "      },"; print "      \"strict_mode\": true,"; print "      \"detour\": \"" tag_label2 "\""; print "    },"; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" tag_label2 "\","; print "      \"listen\": \"127.0.0.1\","; print "      \"method\": \"" ss_method "\","; print "      \"password\": \"" ss_password "\"" multiplex_config ""; print "    },"; found=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_juicity_config() {
    local config_file="/usr/local/etc/juicity/config.json"
    set_listen_port
    set_uuid
    set_user_password
    select_congestion_control
    get_local_ip
    select_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    awk -v listen_port="$listen_port" -v user_uuids="$user_uuids" -v user_passwords="$user_passwords" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" -v congestion_control="$congestion_control" 'BEGIN { print "{"; printf "  \"listen\": \":%s\",\n", listen_port; printf "  \"users\": {\n"; printf "    \"%s\": \"%s\"\n", user_uuids, user_passwords; printf "  },\n"; printf "  \"certificate\": \"%s\",\n", certificate_path; printf "  \"private_key\": \"%s\",\n", private_key_path; printf "  \"congestion_control\": \"%s\",\n", congestion_control; printf "  \"disable_outbound_udp443\": true,\n"; print "  \"log_level\": \"info\""; print "}"}' >"$config_file"
}

function generate_vless_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    select_vless_type
    set_listen_port
    vless_multiple_users
    generate_transport_config
    generate_reality_config
    if [[ "$flow_type" != xtls-rprx-vision ]] && [[ "$transport_grpc" != true ]] && [[ "$transport_http" != true ]]; then
        configure_multiplex
    fi
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v transport_config="$transport_config" -v reality_config="$reality_config" -v multiplex_config="$multiplex_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "" transport_config ""; print "      \"users\": [" users ""; print "      ]"reality_config"" multiplex_config ""; print "    },"; found=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Hy2_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    set_listen_port
    set_up_speed
    set_down_speed
    hy2_multiple_users
    configure_quic_obfuscation
    set_fake_domain
    get_local_ip
    select_certificate_option
    set_ech_config
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local found_rules=0
    local found_inbounds=0
    local server_name="$domain"
    if [ -z "$domain" ]; then
        server_name="$domain_name"
    fi
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v obfs_config="$obfs_config" -v users="$users" -v fake_domain="$fake_domain" -v server_name="$server_name" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" -v ech_server_config="$ech_server_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"up_mbps\": " up_mbps ","; print "      \"down_mbps\": " down_mbps ","obfs_config""; print "      \"users\": [" users ""; print "      ],"; print "      \"ignore_client_bandwidth\": false,"; print "      \"masquerade\": \"https://" fake_domain "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\"" ech_server_config ""; print "      }"; print "    },"; found=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_trojan_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    select_trojan_type
    set_listen_port
    trojan_multiple_users
    generate_transport_config
    if [ "$transport_grpc" != true ] && [ "$transport_http" != true ]; then
        configure_multiplex
    fi
    get_local_ip
    generate_tls_config
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    check_firewall_configuration
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v transport_config="$transport_config" -v tls_config="$tls_config" -v multiplex_config="$multiplex_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"action\": \"route\","; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "" transport_config ""; print "      \"users\": [" users ""; print "      ]" tls_config "" multiplex_config ""; print "    },"; found=0}
    ' "$config_file" >"$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function update_route_file() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local temp_config_file="/usr/local/etc/sing-box/temp_config.json"
    local rule_set_tags
    rule_set_tags=$(printf '%s\n' "${geosite[@]}" | tr -d '"' | jq -R '"geosite-" + .' | jq -s -c '.')
    echo "Configuring WireGuard..."
    jq --argjson tags "$rule_set_tags" --arg outbound "$1" --arg strategy "${warp_strategy:-ipv4_only}" '
        .route.rules = ([
            {"rule_set": $tags, "action": "resolve", "strategy": $strategy},
            {"rule_set": $tags, "action": "route", "outbound": $outbound}
        ] + (.route.rules // []))
        | .route.rule_set = ((.route.rule_set // []) + ($tags | map({tag: ., type: "remote", format: "binary", url: ("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/" + . + ".srs")})))
        | .route.rule_set |= unique_by(.tag)
        | .http_clients = ((.http_clients // []) | if any(.[]; .tag == "direct-http") then . else . + [{"tag": "direct-http", "detour": "direct"}] end)
        | .route.default_http_client = (.route.default_http_client // "direct-http")
        | .experimental.cache_file.enabled = true
    ' "$config_file" >"$temp_config_file" && mv "$temp_config_file" "$config_file"
}

function update_outbound_file() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local temp_config_file="/usr/local/etc/sing-box/temp_config.json"
    jq --arg server "$server" --argjson server_port "$server_port" \
        --arg v4 "$local_address_ipv4" --arg v6 "$local_address_ipv6" \
        --arg private_key "$private_key" --arg peer_public_key "$peer_public_key" \
        --argjson reserved "$reserved" --argjson mtu "$mtu" '
        .endpoints = ((.endpoints // []) + [{
            "type": "wireguard",
            "tag": "wireguard-ep",
            "mtu": $mtu,
            "address": ([$v4, $v6] | map(select(. != ""))),
            "private_key": $private_key,
            "peers": [{
                "address": $server,
                "port": $server_port,
                "public_key": $peer_public_key,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "reserved": $reserved
            }]
        }])
        | .dns.servers = ((.dns.servers // []) | if any(.[]; .tag == "local") then . else . + [{"type": "local", "tag": "local"}] end)
        | .route.default_domain_resolver = (.route.default_domain_resolver // "local")
    ' "$config_file" >"$temp_config_file" && mv "$temp_config_file" "$config_file"
    echo "WireGuard configuration is complete."
}

function write_phone_client_file() {
    local dir="/usr/local/etc/sing-box"
    local phone_client="${dir}/phone_client.json"
    if [ ! -s "${phone_client}" ]; then
        cat >"${phone_client}" <<'EOF'
{
  "log": {
    "disabled": false,
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "https",
        "tag": "dns_proxy",
        "server": "dns.google",
        "domain_resolver": "dns_local",
        "detour": "select"
      },
      {
        "type": "https",
        "tag": "dns_direct",
        "server": "dns.alidns.com",
        "domain_resolver": "dns_local",
        "detour": "direct"
      },
      {
        "type": "fakeip",
        "tag": "dns_fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      },
      {
        "type": "udp",
        "tag": "dns_local",
        "server": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": "geosite-category-ads-all",
        "action": "predefined",
        "rcode": "NOERROR"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "action": "route",
        "server": "dns_fakeip"
      },
      {
        "clash_mode": "Direct",
        "action": "route",
        "server": "dns_direct"
      },
      {
        "clash_mode": "Global",
        "action": "route",
        "server": "dns_proxy"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "rule_set": "geosite-geolocation-!cn",
            "invert": true
          },
          {
            "rule_set": [
              "geosite-cn",
              "geosite-category-companies@cn"
            ]
          }
        ],
        "action": "route",
        "server": "dns_direct"
      }
    ],
    "final": "dns_proxy"
  },
  "http_clients": [
    {
      "tag": "proxy-http",
      "detour": "select"
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
      },
      {
        "tag": "geosite-geolocation-!cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
      },
      {
        "tag": "geosite-category-companies@cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-companies@cn.srs"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
      }
    ],
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "clash_mode": "Direct",
        "action": "route",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "action": "route",
        "outbound": "select"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "rule_set": "geosite-geolocation-!cn",
            "invert": true
          },
          {
            "rule_set": [
              "geosite-cn",
              "geosite-category-companies@cn"
            ]
          }
        ],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": "geoip-cn",
        "action": "route",
        "outbound": "direct"
      }
    ],
    "final": "select",
    "auto_detect_interface": true,
    "default_http_client": "proxy-http",
    "default_domain_resolver": {
      "server": "dns_local",
      "strategy": "ipv4_only"
    }
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ],
      "auto_route": true,
      "strict_route": true
    }
  ],
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": [
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    },
    {
      "type": "selector",
      "tag": "select",
      "outbounds": [
        "auto"
      ],
      "default": "auto",
      "interrupt_exist_connections": false
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOF
    fi
}

function write_win_client_file() {
    local dir="/usr/local/etc/sing-box"
    local win_client="${dir}/win_client.json"
    if [ ! -s "${win_client}" ]; then
        cat >"${win_client}" <<'EOF'
{
  "log": {
    "disabled": false,
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "https",
        "tag": "dns_proxy",
        "server": "dns.google",
        "domain_resolver": "dns_local",
        "detour": "select"
      },
      {
        "type": "https",
        "tag": "dns_direct",
        "server": "dns.alidns.com",
        "domain_resolver": "dns_local",
        "detour": "direct"
      },
      {
        "type": "fakeip",
        "tag": "dns_fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      },
      {
        "type": "udp",
        "tag": "dns_local",
        "server": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": "geosite-category-ads-all",
        "action": "predefined",
        "rcode": "NOERROR"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "action": "route",
        "server": "dns_fakeip"
      },
      {
        "clash_mode": "Direct",
        "action": "route",
        "server": "dns_direct"
      },
      {
        "clash_mode": "Global",
        "action": "route",
        "server": "dns_proxy"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "rule_set": "geosite-geolocation-!cn",
            "invert": true
          },
          {
            "rule_set": [
              "geosite-cn",
              "geosite-category-companies@cn"
            ]
          }
        ],
        "action": "route",
        "server": "dns_direct"
      }
    ],
    "final": "dns_proxy"
  },
  "http_clients": [
    {
      "tag": "proxy-http",
      "detour": "select"
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
      },
      {
        "tag": "geosite-geolocation-!cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
      },
      {
        "tag": "geosite-category-companies@cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-companies@cn.srs"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
      }
    ],
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "clash_mode": "Direct",
        "action": "route",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "action": "route",
        "outbound": "select"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "rule_set": "geosite-geolocation-!cn",
            "invert": true
          },
          {
            "rule_set": [
              "geosite-cn",
              "geosite-category-companies@cn"
            ]
          }
        ],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": "geoip-cn",
        "action": "route",
        "outbound": "direct"
      }
    ],
    "final": "select",
    "auto_detect_interface": true,
    "default_http_client": "proxy-http",
    "default_domain_resolver": {
      "server": "dns_local",
      "strategy": "ipv4_only"
    }
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": 1080,
      "set_system_proxy": false
    }
  ],
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": [
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    },
    {
      "type": "selector",
      "tag": "select",
      "outbounds": [
        "auto"
      ],
      "default": "auto",
      "interrupt_exist_connections": false
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOF
    fi
}

function write_clash_yaml() {
    local dir="/usr/local/etc/sing-box"
    local clash_yaml="${dir}/clash.yaml"
    if [ ! -s "${clash_yaml}" ]; then
        awk 'BEGIN { print "mixed-port: 10801"; print "allow-lan: true"; print "bind-address: \"*\""; print "find-process-mode: strict"; print "mode: rule"; print "geodata-mode: true"; print "geox-url:"; print "  geoip: \"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat\""; print "  geosite: \"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat\""; print "  mmdb: \"https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb\""; print "log-level: info"; print "ipv6: true"; print "global-client-fingerprint: chrome"; print "tun:"; print "  enable: true"; print "  stack: system"; print "  dns-hijack:"; print "    - 0.0.0.0:53"; print "  auto-detect-interface: true"; print "  auto-route: true"; print "  mtu: 9000"; print "profile:"; print "  store-selected: false"; print "  store-fake-ip: true"; print "sniffer:"; print "  enable: true"; print "  override-destination: false"; print "  sniff:"; print "    TLS:"; print "      ports: [443, 8443]"; print "    HTTP:"; print "      ports: [80, 8080-8880]"; print "      override-destination: true"; print "dns:"; print "  enable: true"; print "  prefer-h3: true"; print "  listen: 0.0.0.0:53"; print "  ipv6: true"; print "  ipv6-timeout: 300"; print "  default-nameserver:"; print "    - 223.5.5.5"; print "  enhanced-mode: fake-ip"; print "  fake-ip-range: 198.18.0.1/16"; print "  nameserver:"; print "    - https://doh.pub/dns-query"; print "    - https://dns.alidns.com/dns-query"; print "  fallback:"; print "    - https://dns.google/dns-query"; print "    - https://1.1.1.1/dns-query"; print "  fallback-filter:"; print "    geoip: true"; print "    geoip-code: CN"; print "    geosite:"; print "      - gfw"; print "    ipcidr:"; print "      - 240.0.0.0/4"; print "    domain:"; print "      - \"+.google.com\""; print "      - \"+.facebook.com\""; print "      - \"+.youtube.com\""; print "  nameserver-policy:"; print "    \"geosite:cn,private\":"; print "      - https://doh.pub/dns-query"; print "      - https://dns.alidns.com/dns-query"; print "    \"geosite:category-ads-all\": rcode://success"; print "proxies:"; print "proxy-groups:"; print "  - name: Proxy"; print "    type: select"; print "    proxies:"; print "      - auto"; print "  - name: auto"; print "    type: url-test"; print "    proxies:"; print "    url: \"https://cp.cloudflare.com/generate_204\""; print "    interval: 300"; print "rules:"; print "  - GEOSITE,private,DIRECT"; print "  - GEOSITE,category-ads-all,REJECT"; print "  - GEOSITE,cn,DIRECT"; print "  - GEOIP,cn,DIRECT"; print "  - MATCH,Proxy"; }' >"${clash_yaml}"
        sed -i'' -e '/^      - "+\.google\.com"/s/"/'\''/g' "${clash_yaml}"
        sed -i'' -e '/^      - "+\.facebook\.com"/s/"/'\''/g' "${clash_yaml}"
        sed -i'' -e '/^      - "+\.youtube\.com"/s/"/'\''/g' "${clash_yaml}"
    fi
}

function write_naive_client_file() {
    local naive_client_file="$naive_client_filename"
    awk -v naive_client_file="$naive_client_file" 'BEGIN { print "{"; print "  \"listen\":  \"socks://127.0.0.1:1080\","; print "  \"proxy\": \"https://user_name:user_password@server_name:listen_port\""; print "}" }' >"$naive_client_file"
}

function generate_shadowsocks_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local proxy_name
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    while true; do
        proxy_name="ss-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"method\": \"" ss_method "\", "; print "      \"password\": \"" ss_password "\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_shadowsocks_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local proxy_name
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    while true; do
        proxy_name="ss-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"method\": \"" ss_method "\", "; print "      \"password\": \"" ss_password "\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_shadowsocks_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="ss-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: ss"; print "    server:", local_ip; print "    port:", listen_port; print "    cipher:", ss_method; print "    password:", "\"" ss_password "\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_juicity_win_client_config() {
    local client_file="/usr/local/etc/juicity/client.json"
    local server_name="$domain"
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    awk -v listen_port="$listen_port" -v server_value="$server_value" -v user_uuids="$user_uuids" -v user_passwords="$user_passwords" -v server_name="$server_name" -v tls_insecure="$tls_insecure" -v congestion_control="$congestion_control" 'BEGIN { print "{"; printf "  \"listen\": \":%s\",\n", 1080; printf "  \"server\": \"%s:%s\",\n", server_value, listen_port; printf "  \"uuid\": \"%s\",\n", user_uuids; printf "  \"password\": \"%s\",\n", user_passwords; printf "  \"sni\": \"%s\",\n", server_name; printf "  \"allow_insecure\": %s,\n", tls_insecure; printf "  \"congestion_control\": \"%s\",\n", congestion_control; printf "  \"log_level\": \"info\"\n"; print "}"}' >"$client_file"
    echo "The client configuration file has been saved to $client_file, please download and use it!"
}

function generate_tuic_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="tuic-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v user_password="$user_password" -v congestion_control="$congestion_control" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\", "; print "      \"password\": \"" user_password "\", "; print "      \"congestion_control\": \""congestion_control"\","; print "      \"udp_relay_mode\": \"native\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]" ech_client_config ""; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_tuic_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="tuic-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v user_password="$user_password" -v congestion_control="$congestion_control" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\", "; print "      \"password\": \"" user_password "\", "; print "      \"congestion_control\": \""congestion_control"\","; print "      \"udp_relay_mode\": \"native\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]" ech_client_config ""; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_tuic_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="tuic-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v user_password="$user_password" -v congestion_control="$congestion_control" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    server:", server_value; print "    port:", listen_port; print "    type: tuic"; print "    uuid:", user_uuid; print "    password:", user_password; print "    sni:", server_name; print "    alpn: [h3]"; print "    request-timeout: 8000"; print "    udp-relay-mode: native"; print "    skip-cert-verify:", tls_insecure; print "    congestion-controller:", congestion_control; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_socks_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local proxy_name
    while true; do
        proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_name="$user_name" -v user_password="$user_password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"socks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"username\": \"" user_name "\", "; print "      \"password\": \"" user_password "\" "; print "    },";}
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_socks_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local proxy_name
    while true; do
        proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_name="$user_name" -v user_password="$user_password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"socks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"username\": \"" user_name "\", "; print "      \"password\": \"" user_password "\" "; print "    },";}
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_socks_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_name="$user_name" -v user_password="$user_password" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: socks5"; print "    server:", local_ip; print "    port:", listen_port; print "    username:", user_name; print "    password:", user_password; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_Hysteria_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$obfs_password" ]; then
        obfs_config="\n      \"obfs\": \"$obfs_password\","
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="Hysteria-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v obfs_config="$obfs_config" -v user_password="$user_password" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " down_mbps ", "; print "      \"down_mbps\": " up_mbps ","obfs_config""; print "      \"auth_str\": \""user_password"\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]" ech_client_config ""; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_Hysteria_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$obfs_password" ]; then
        obfs_config="\n      \"obfs\": \"$obfs_password\","
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="Hysteria-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v obfs_config="$obfs_config" -v user_password="$user_password" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " down_mbps ", "; print "      \"down_mbps\": " up_mbps ","obfs_config""; print "      \"auth_str\": \""user_password"\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]" ech_client_config ""; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_Hysteria_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$obfs_password" ]; then
        obfs_config="
    obfs: $obfs_password"
    fi

    while true; do
        proxy_name="hysteria-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v user_password="$user_password" -v obfs_config="$obfs_config" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: hysteria"; print "    server:", server_value; print "    port:", listen_port; print "    auth-str:", user_password obfs_config; print "    sni:", server_name; print "    skip-cert-verify:", tls_insecure; print "    alpn:"; print "      - h3"; print "    protocol: udp"; print "    up: \"" down_mbps " Mbps\""; print "    down: \"" up_mbps " Mbps\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vmess_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local proxy_name
    local server_name="$domain"
    local server_value
    local tls_insecure
    if [[ -z "$domain" && -n "$domain_name" ]]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    elif [[ -z "$domain" && -z "$domain_name" ]]; then
        server_value="$local_ip"
    elif [[ -z "$domain_name" && -n "$domain" ]]; then
        server_name="$domain"
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="vmess-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    if [[ -n "$domain" || -n "$domain_name" ]]; then
        awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_config="$transport_config" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" -v multiplex_client_config="$multiplex_client_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\"" ech_client_config ""; print "      },"; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$win_client_file" >"$win_client_file.tmp"
    else
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\"," transport_config " "; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$win_client_file" >"$win_client_file.tmp"
    fi
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_vmess_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local proxy_name
    local server_name="$domain"
    local server_value
    local tls_insecure
    if [[ -z "$domain" && -n "$domain_name" ]]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    elif [[ -z "$domain" && -z "$domain_name" ]]; then
        server_value="$local_ip"
    elif [[ -z "$domain_name" && -n "$domain" ]]; then
        server_name="$domain"
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="vmess-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    if [[ -n "$domain" || -n "$domain_name" ]]; then
        awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_config="$transport_config" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" -v multiplex_client_config="$multiplex_client_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\"" ech_client_config ""; print "      },"; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\"" multiplex_client_config ""; print "    },";}       
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }     
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    else
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\"," transport_config " "; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    fi
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_vmess_tcp_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vmess-tcp-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    alterId: 0"; print "    cipher: auto"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vmess_tcp_tls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="vmess-tcp-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", server_value; print "    port:", listen_port; print "    uuid:", user_uuid; print "    alterId: 0"; print "    cipher: auto"; print "    tls: true"; print "    skip-cert-verify:", tls_insecure; print "    servername: " server_name; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vmess_ws_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vmess-ws-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_path="$transport_path" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: ws"; print "    ws-opts:"; print "      path: " transport_path; print "      max-early-data: 2048"; print "      early-data-header-name: Sec-WebSocket-Protocol"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vmess_ws_tls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="vmess-ws-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_path="$transport_path" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", server_value; print "    port:", listen_port; print "    uuid:", user_uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: ws"; print "    tls: true"; print "    skip-cert-verify:", tls_insecure; print "    servername:", server_name; print "    ws-opts:"; print "      path: " transport_path; print "      max-early-data: 2048"; print "      early-data-header-name: Sec-WebSocket-Protocol"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vmess_grpc_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vmess-grpc-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: grpc"; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vmess_grpc_tls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="vmess-grpc-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_service_name="$transport_service_name" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", server_value; print "    port:", listen_port; print "    uuid:", user_uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: grpc"; print "    tls: true"; print "    skip-cert-verify:", tls_insecure; print "    servername:", server_name; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_http_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="http-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_name="$user_name" -v user_password="$user_password" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"http\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"username\": \"" user_name "\", "; print "      \"password\": \"" user_password "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\"" ech_client_config ""; print "      }"; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_http_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="http-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_name="$user_name" -v user_password="$user_password" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"http\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"username\": \"" user_name "\", "; print "      \"password\": \"" user_password "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\"" ech_client_config ""; print "      }"; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_http_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="http-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_name="$user_name" -v user_password="$user_password" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: http"; print "    server:", server_value; print "    port:", listen_port; print "    username:", user_name; print "    password:", user_password; print "    tls: true"; print "    sni:", server_name; print "    skip-cert-verify:", tls_insecure; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_Hysteria2_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$obfs_password" ]; then
        obfs_config="\n      \"obfs\": {\n        \"type\": \"salamander\",\n        \"password\": \"$obfs_password\"\n      },"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="Hysteria2-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v obfs_config="$obfs_config" -v user_password="$user_password" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " down_mbps ", "; print "      \"down_mbps\": " up_mbps ","obfs_config""; print "      \"password\": \"" user_password "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]" ech_client_config ""; print "      }"; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_Hysteria2_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$obfs_password" ]; then
        obfs_config="\n      \"obfs\": {\n        \"type\": \"salamander\",\n        \"password\": \"$obfs_password\"\n      },"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="Hysteria2-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v obfs_config="$obfs_config" -v user_password="$user_password" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " down_mbps ", "; print "      \"down_mbps\": " up_mbps ","obfs_config""; print "      \"password\": \"" user_password "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]" ech_client_config ""; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_Hysteria2_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$obfs_password" ]; then
        obfs_config="
    obfs: salamander
    obfs-password: $obfs_password"
    fi
    while true; do
        proxy_name="hysteria2-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v user_password="$user_password" -v obfs_config="$obfs_config" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: hysteria2"; print "    server:", server_value; print "    port:", listen_port; print "    password:", user_password obfs_config; print "    alpn:"; print "      - h3"; print "    sni:", server_name; print "    skip-cert-verify:", tls_insecure; print "    up: \"" down_mbps " Mbps\""; print "    down: \"" up_mbps " Mbps\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vless_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local proxy_name
    local server_name_in_config=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    while true; do
        proxy_name="vless-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    if [ "$server_name_in_config" != "null" ]; then
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v flow_type="$flow_type" -v public_key="$public_key" -v short_id="$short_id" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\", "; print "      \"flow\": \"" flow_type "\"," transport_config ""; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\""; print "        },"; print "        \"reality\": {"; print "          \"enabled\": true,"; print "          \"public_key\": \"" public_key "\","; print "          \"short_id\": \"" short_id "\""; print "        }"; print "      }" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    else
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v flow_type="$flow_type" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\"," transport_config ""; print "      \"flow\": \"" flow_type "\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    fi
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_vless_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local proxy_name
    local server_name_in_config=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    while true; do
        proxy_name="vless-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    if [ "$server_name_in_config" != "null" ]; then
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v flow_type="$flow_type" -v public_key="$public_key" -v short_id="$short_id" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\", "; print "      \"flow\": \"" flow_type "\"," transport_config ""; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\""; print "        },"; print "        \"reality\": {"; print "          \"enabled\": true,"; print "          \"public_key\": \"" public_key "\","; print "          \"short_id\": \"" short_id "\""; print "        }"; print "      }" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    else
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v flow_type="$flow_type" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" user_uuid "\"," transport_config ""; print "      \"flow\": \"" flow_type "\"" multiplex_client_config ""; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    fi
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_vless_tcp_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vless-tcp-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    network: tcp"; print "    udp: true"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vless_ws_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vless-ws-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_path="$transport_path" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    network: ws"; print "    udp: true"; print "    ws-opts:"; print "      path: " transport_path; print "      max-early-data: 2048"; print "      early-data-header-name: Sec-WebSocket-Protocol"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vless_grpc_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vless-grpc-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    network: grpc"; print "    udp: true"; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vless_reality_vision_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vless-reality-vision-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v public_key="$public_key" -v short_id="$short_id" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    network: tcp"; print "    udp: true"; print "    tls: true"; print "    flow: xtls-rprx-vision"; print "    servername:", server_name; print "    reality-opts:"; print "      public-key:", public_key; print "      short-id:", short_id; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_vless_reality_grpc_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="vless-reality-grpc-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v user_uuid="$user_uuid" -v public_key="$public_key" -v short_id="$short_id" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", user_uuid; print "    network: grpc"; print "    udp: true"; print "    tls: true"; print "    flow: "; print "    servername:", server_name; print "    reality-opts:"; print "      public-key:", public_key; print "      short-id:", short_id; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_trojan_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local proxy_name
    local server_name="$domain"
    local server_value
    local tls_insecure
    if [[ -z "$domain" && -n "$domain_name" ]]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    elif [[ -z "$domain" && -z "$domain_name" ]]; then
        server_value="$local_ip"
    elif [[ -z "$domain_name" && -n "$domain" ]]; then
        server_name="$domain"
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="trojan-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file"; then
            break
        fi
    done
    if [[ -n "$domain" || -n "$domain_name" ]]; then
        awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_password="$user_password" -v transport_config="$transport_config" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"password\": \"" user_password "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\"" ech_client_config ""; print "      }"multiplex_client_config""; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    else
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_password="$user_password" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port "," transport_config " "; print "      \"password\": \"" user_password "\""multiplex_client_config""; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    fi
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_trojan_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local proxy_name
    local server_name="$domain"
    local server_value
    local tls_insecure
    if [[ -z "$domain" && -n "$domain_name" ]]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    elif [[ -z "$domain" && -z "$domain_name" ]]; then
        server_value="$local_ip"
    elif [[ -z "$domain_name" && -n "$domain" ]]; then
        server_name="$domain"
        server_value="$domain"
        tls_insecure="false"
    fi
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    if [ -n "$ech_config" ]; then
        ech_client_config=",\n        \"ech\": {\n          \"enabled\": true,\n          \"config\": [\n$ech_config\n          ]\n        }"
    fi
    while true; do
        proxy_name="trojan-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file"; then
            break
        fi
    done
    if [[ -n "$domain" || -n "$domain_name" ]]; then
        awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_password="$user_password" -v transport_config="$transport_config" -v tls_insecure="$tls_insecure" -v ech_client_config="$ech_client_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_value "\", "; print "      \"server_port\": " listen_port ","; print "      \"password\": \"" user_password "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"insecure\": " tls_insecure ","; print "        \"server_name\": \"" server_name "\"" ech_client_config ""; print "      }"multiplex_client_config""; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    else
        awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v user_password="$user_password" -v transport_config="$transport_config" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port "," transport_config " "; print "      \"password\": \"" user_password "\""multiplex_client_config""; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    fi
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_trojan_tcp_tls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="trojan-tcp-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_password="$user_password" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: trojan"; print "    server:", server_value; print "    port:", listen_port; print "    password:", user_password; print "    udp: true"; print "    sni:", server_name; print "    skip-cert-verify:", tls_insecure; print "    alpn:"; print "      - h2"; print "      - http/1.1"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_trojan_ws_tls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="trojan-ws-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_password="$user_password" -v transport_path="$transport_path" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: trojan"; print "    server:", server_value; print "    port:", listen_port; print "    password:", "\"" user_password "\""; print "    network: ws"; print "    sni:", server_name; print "    skip-cert-verify:", tls_insecure; print "    udp: true"; print "    ws-opts:"; print "      path:", transport_path; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_trojan_grpc_tls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local server_name="$domain"
    local proxy_name
    local server_value
    local tls_insecure
    if [ -z "$domain" ]; then
        server_name="$domain_name"
        server_value="$local_ip"
        tls_insecure="true"
    else
        server_value="$domain"
        tls_insecure="false"
    fi
    while true; do
        proxy_name="trojan-grpc-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v server_value="$server_value" -v server_name="$server_name" -v listen_port="$listen_port" -v user_password="$user_password" -v transport_service_name="$transport_service_name" -v tls_insecure="$tls_insecure" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: trojan"; print "    server:", server_value; print "    port:", listen_port; print "    password:", "\"" user_password "\""; print "    network: grpc"; print "    sni:", server_name; print "    udp: true"; print "    skip-cert-verify:", tls_insecure; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_shadowtls_win_client_config() {
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local proxy_name
    local shadowtls_out
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    while true; do
        proxy_name="shadowtls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        shadowtls_out="stl-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$win_client_file" && ! grep -q "name: $shadowtls_out" "$win_client_file" && [ "$proxy_name" != "$shadowtls_out" ]; then
            break
        fi
    done
    awk -v shadowtls_out="$shadowtls_out" -v proxy_name="$proxy_name" -v method="$method" -v ss_password="$ss_password" -v local_ip="$local_ip" -v listen_port="$listen_port" -v stls_password="$stls_password" -v user_input="$user_input" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"method\": \"" method "\", "; print "      \"password\": \"" ss_password "\","; print "      \"detour\": \"" shadowtls_out "\""multiplex_client_config""; print "    },"; print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"" shadowtls_out "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"version\": 3, "; print "      \"password\": \""stls_password"\", "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" user_input "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\" "; print "        }"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
}

function generate_shadowtls_phone_client_config() {
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local proxy_name
    local shadowtls_out
    if [ -n "$multiplex_config" ] && [ -n "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false,\n        \"brutal\": {\n          \"enabled\": true,\n          \"up_mbps\": $down_mbps,\n          \"down_mbps\": $up_mbps\n        }\n      }"
    elif [ -n "$multiplex_config" ] && [ -z "$brutal_config" ]; then
        multiplex_client_config=",\n      \"multiplex\": {\n        \"enabled\": true,\n        \"protocol\": \"h2mux\",\n        \"max_connections\": 1,\n        \"min_streams\": 4,\n        \"padding\": false\n      }"
    fi
    while true; do
        proxy_name="shadowtls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        shadowtls_out="stl-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$phone_client_file" && ! grep -q "name: $shadowtls_out" "$phone_client_file" && [ "$proxy_name" != "$shadowtls_out" ]; then
            break
        fi
    done
    awk -v shadowtls_out="$shadowtls_out" -v proxy_name="$proxy_name" -v method="$method" -v ss_password="$ss_password" -v local_ip="$local_ip" -v listen_port="$listen_port" -v stls_password="$stls_password" -v user_input="$user_input" -v multiplex_client_config="$multiplex_client_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"method\": \"" method "\", "; print "      \"password\": \"" ss_password "\","; print "      \"detour\": \"" shadowtls_out "\""multiplex_client_config""; print "    },"; print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"" shadowtls_out "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"version\": 3, "; print "      \"password\": \""stls_password"\", "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" user_input "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\" "; print "        }"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_shadowtls_yaml() {
    local filename="/usr/local/etc/sing-box/clash.yaml"
    local proxy_name
    while true; do
        proxy_name="shadowtls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
        if ! grep -q "name: $proxy_name" "$filename"; then
            break
        fi
    done
    awk -v proxy_name="$proxy_name" -v method="$method" -v ss_password="$ss_password" -v local_ip="$local_ip" -v listen_port="$listen_port" -v stls_password="$stls_password" -v user_input="$user_input" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: ss"; print "    server:", local_ip; print "    port:", listen_port; print "    cipher:", method; print "    password:", "\"" ss_password "\""; print "    plugin: shadow-tls"; print "    plugin-opts:"; print "      host: \"" user_input "\""; print "      password:", "\"" stls_password "\""; print "      version: 3"; print ""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" >temp_file && mv temp_file "$filename"
}

function generate_naive_win_client_config() {
    local naive_client_file="$naive_client_filename"
    sed -i -e "s,user_name,$user_name," -e "s,user_password,$user_password," -e "s,listen_port,$listen_port," -e "s,server_name,$domain," "$naive_client_file"
    echo "Computer-side configuration file has been saved to $naive_client_file, please download and use it!"
}

function extract_types_tags() {
    local config_file="/usr/local/etc/sing-box/config.json"
    filtered_tags=()
    types=()
    tags=($(jq -r '.inbounds[] | select(.tag != null) | .tag' "$config_file"))
    detour_tag=$(jq -r '.inbounds[] | select(.type == "shadowtls") | .detour' "$config_file")
    wireguard_type=$(jq -r '(.endpoints // [])[] | select(.type == "wireguard" and .tag == "wireguard-ep") | .type' "$config_file")
    if [ -z "$tags" ] && [ -z "$wireguard_type" ]; then
        echo "No node configurations detected, please build nodes before using this option!"
        exit 0
    fi
    filtered_tags=()
    for tag in "${tags[@]}"; do
        if [ "$tag" != "$detour_tag" ]; then
            filtered_tags+=("$tag")
        fi
    done
    max_length=0
    for tag in "${filtered_tags[@]}"; do
        tag_length=${#tag}
        if ((tag_length > max_length)); then
            max_length=$tag_length
        fi
    done
    for ((i = 0; i < ${#filtered_tags[@]}; i++)); do
        type=$(jq -r --arg tag "${filtered_tags[$i]}" '.inbounds[] | select(.tag == $tag) | .type' "$config_file")
        types[$i]=$type
        printf "%d).Protocol Type: %-20s Inbound Tag: %s\n" "$((i + 1))" "$type" "${filtered_tags[$i]}"
    done
    if [ ! -z "$wireguard_type" ]; then
        types[$i]=$wireguard_type
        printf "%d).Protocol Type: %-20s Endpoint Tag: %s\n" "$((i + 1))" "$wireguard_type" "wireguard-ep"
    fi
}

function delete_choice() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local clash_yaml="/usr/local/etc/sing-box/clash.yaml"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local temp_json="/usr/local/etc/sing-box/temp.json"
    local temp_yaml="/usr/local/etc/sing-box/temp.yaml"
    extract_types_tags
    valid_choice=false
    while [ "$valid_choice" == false ]; do
        read -p "Please select the node configuration to delete (input the corresponding number): " choice
        if [[ ! $choice =~ ^[0-9]+$ || $choice -lt 1 || $choice -gt ${#types[@]} ]]; then
            echo -e "${RED}Error: Invalid selection, please re-enter!${NC}"
        else
            valid_choice=true
        fi
    done
    selected_tag="${filtered_tags[$choice - 1]}"
    selected_type="${types[$choice - 1]}"
    listen_port=$(jq -r --arg selected_tag "$selected_tag" '.inbounds[] | select(.tag == $selected_tag) | .listen_port' "$config_file" | awk '{print int($0)}')
    if [ "$selected_type" == "wireguard" ]; then
        jq '(.endpoints // []) |= map(select(.tag != "wireguard-ep"))
            | if (.endpoints | length) == 0 then del(.endpoints) else . end
            | .route.rules |= map(select(.outbound != "wireguard-ep" and .outbound != "warp-IPv4-out" and .outbound != "warp-IPv6-out" and (.action != "resolve" or .rule_set == null)))
            | .outbounds |= map(select(.tag != "warp-IPv4-out" and .tag != "warp-IPv6-out"))
            | ([.route.rules[]? | .rule_set? // empty | (if type == "array" then .[] else . end)]) as $used
            | if .route.rule_set then .route.rule_set |= map(select(.tag as $t | $used | index($t))) else . end
            | if (.route.rule_set // [1]) == [] then del(.route.rule_set) else . end' "$config_file" >"$temp_json"
        mv "$temp_json" "$config_file"
    else
        detour_tag=$(jq -r --arg selected_tag "$selected_tag" '.inbounds[] | select(.type == "shadowtls" and .tag == $selected_tag) | .detour' "$config_file")
        jq --arg selected_tag "$selected_tag" --arg detour_tag "$detour_tag" '.inbounds |= map(select(.tag != $selected_tag and .tag != $detour_tag))' "$config_file" >"$temp_json"
        mv "$temp_json" "$config_file"
        jq --arg selected_tag "$selected_tag" '.route.rules |= map(select(.inbound[0] != $selected_tag))' "$config_file" >"$temp_json"
        mv "$temp_json" "$config_file"
    fi
    if [ "$selected_type" != "wireguard" ]; then
        awk -v port="$listen_port" '$0 ~ "Listening Port: " port {print; in_block=1; next} in_block && NF == 0 {in_block=0} !in_block' "$output_file" >"$output_file.tmp1"
        mv "$output_file.tmp1" "$output_file"
        awk -v port="$listen_port" '$0 ~ "Listening Port: " port {start=NR; next} {lines[NR]=$0} END {for (i=1; i<=NR; i++) if (i < start - 4 || i > start) print lines[i]}' "$output_file" >"$output_file.tmp2"
        mv "$output_file.tmp2" "$output_file"
        sed -i '/./,$!d' "$output_file"
    fi
    if [ -f "$clash_yaml" ]; then
        get_clash_tags=$(awk '/proxies:/ {in_proxies_block=1} in_proxies_block && /- name:/ {name = $3} in_proxies_block && /port:/ {port = $2; print "Name:", name, "Port:", port}' "$clash_yaml" >"$temp_yaml")
        matching_clash_tag=$(grep "Port: $listen_port" "$temp_yaml" | awk '{print $2}')
    fi
    if [ -n "$listen_port" ]; then
        phone_matching_tag=$(jq -r --argjson listen_port "$listen_port" '.outbounds[] | select(.server_port == $listen_port) | .tag' "$phone_client_file")
        win_matching_tag=$(jq -r --argjson listen_port "$listen_port" '.outbounds[] | select(.server_port == $listen_port) | .tag' "$win_client_file")
    fi
    jq --arg tag "$phone_matching_tag" '.outbounds |= map(select(.tag != $tag))' "$phone_client_file" >"$temp_json"
    mv "$temp_json" "$phone_client_file"
    jq --arg tag "$win_matching_tag" '.outbounds |= map(select(.tag != $tag))' "$win_client_file" >"$temp_json"
    mv "$temp_json" "$win_client_file"
    if [ -n "$matching_clash_tag" ] && [ "$selected_type" != "wireguard" ]; then
        sed -i "/^  - name: $matching_clash_tag$/,/^\s*$/d" "$clash_yaml"
        sed -i "/proxy-groups:/,/^\s*$/ {/      - $matching_clash_tag/d}" "$clash_yaml"
    fi
    phone_matching_detour=$(jq -r --arg phone_matching_tag "$phone_matching_tag" '.outbounds[] | select(.detour == $phone_matching_tag) | .detour' "$phone_client_file")
    win_matching_detour=$(jq -r --arg win_matching_tag "$win_matching_tag" '.outbounds[] | select(.detour == $win_matching_tag) | .detour' "$win_client_file")
    phone_matching_detour_tag=$(jq -r --arg phone_matching_detour "$phone_matching_detour" '.outbounds[] | select(.detour == $phone_matching_detour) | .tag' "$phone_client_file")
    win_matching_detour_tag=$(jq -r --arg win_matching_detour "$win_matching_detour" '.outbounds[] | select(.detour == $win_matching_detour) | .tag' "$win_client_file")
    awk -v phone_matching_tag="$phone_matching_tag" '!/^      "outbounds": \[$/,/^\s*]/{if (!($0 ~ "^ * \"" phone_matching_tag "\"")) print; else next; }' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
    awk -v win_matching_tag="$win_matching_tag" '!/^      "outbounds": \[$/,/^\s*]/{if (!($0 ~ "^ * \"" win_matching_tag "\"")) print; else next; }' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
    if [ "$phone_matching_tag" == "$phone_matching_detour" ]; then
        jq --arg phone_matching_detour "$phone_matching_detour" '.outbounds |= map(select(.detour != $phone_matching_detour))' "$phone_client_file" >"$temp_json"
        mv "$temp_json" "$phone_client_file"
        awk -v phone_matching_detour_tag="$phone_matching_detour_tag" '!/^      "outbounds": \[$/,/^\s*]/{if (!($0 ~ "^ * \"" phone_matching_detour_tag "\"")) print; else next; }' "$phone_client_file" >"$phone_client_file.tmp"
        mv "$phone_client_file.tmp" "$phone_client_file"
    fi
    if [ "$win_matching_tag" == "$win_matching_detour" ]; then
        jq --arg win_matching_detour "$win_matching_detour" '.outbounds |= map(select(.detour != $win_matching_detour))' "$win_client_file" >"$temp_json"
        mv "$temp_json" "$win_client_file"
        awk -v win_matching_detour_tag="$win_matching_detour_tag" '!/^      "outbounds": \[$/,/^\s*]/{if (!($0 ~ "^ * \"" win_matching_detour_tag "\"")) print; else next; }' "$win_client_file" >"$win_client_file.tmp"
        mv "$win_client_file.tmp" "$win_client_file"
    fi
    awk '{if ($0 ~ /],$/ && p ~ /,$/) sub(/,$/, "", p); if (NR > 1) print p; p = $0;}END{print p;}' "$phone_client_file" >"$phone_client_file.tmp"
    mv "$phone_client_file.tmp" "$phone_client_file"
    awk '{if ($0 ~ /],$/ && p ~ /,$/) sub(/,$/, "", p); if (NR > 1) print p; p = $0;}END{print p;}' "$win_client_file" >"$win_client_file.tmp"
    mv "$win_client_file.tmp" "$win_client_file"
    [ -f "$temp_yaml" ] && rm "$temp_yaml"
    if ! jq -e 'select(.inbounds[] | .listen == "::")' "$config_file" >/dev/null; then
        sed -i 's/"rules": \[\]/"rules": [\n    ]/' "$config_file"
        sed -i 's/^  "inbounds": \[\],/  "inbounds": [\n  ],/' "$config_file"
        sed -i 's/^      "outbounds": \[\],/      "outbounds": [\n      ],/' "$win_client_file"
        sed -i 's/^      "outbounds": \[\],/      "outbounds": [\n      ],/' "$phone_client_file"
    fi
    systemctl restart sing-box
    echo "$selected_type configuration information has been deleted. Server and client configuration information have been updated. Please download the new configuration file to use!"
}

function display_naive_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local num_users=${#user_names[@]}
    echo -e "${CYAN}NaiveProxy Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $domain" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "User Name                                  Password" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < num_users; i++)); do
        local user_name="${user_names[i]}"
        local user_password="${user_passwords[i]}"
        printf "%-38s %s\n" "$user_name" "$user_password" | tee -a "$output_file"
    done
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function generate_naive_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local naive_client_file="$naive_client_filename"
    local num_users=${#user_names[@]}
    for ((i = 0; i < num_users; i++)); do
        local user_name="${user_names[i]}"
        local user_password="${user_passwords[i]}"
        generate_naive_random_filename
        write_naive_client_file
        generate_naive_win_client_config "$user_name" "$user_password" "$listen_port" "$domain"
    done
}

function display_Direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local override_address=$(jq -r '.inbounds[0].override_address' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    echo -e "${CYAN}Direct Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Relay Address: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Target Address: $override_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Target Port: $override_port" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_juicity_config() {
    local config_file="/usr/local/etc/juicity/config.json"
    local output_file="/usr/local/etc/juicity/output.txt"
    local server_address
    local congestion_control=$(jq -r '.congestion_control' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [ -z "$domain" ]; then
        server_address="$local_ip"
    else
        server_address="$domain"
    fi
    echo -e "${CYAN}Juicity Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "UUID: $user_uuids         Password: $user_passwords      " | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Congestion Control Algorithm: $congestion_control" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Share Link:"
    juicity-server generate-sharelink -c "$config_file"
    generate_juicity_win_client_config
    echo "Configuration information has been saved to $output_file"
}

function display_http_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local num_users=${#user_names[@]}
    local server_address
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [ -z "$domain" ]; then
        server_address="$local_ip"
    else
        server_address="$domain"
    fi
    echo -e "${CYAN}HTTP Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Username                                  Password" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < num_users; i++)); do
        local user_name="${user_names[i]}"
        local user_password="${user_passwords[i]}"
        printf "%-38s %s\n" "$user_name" "$user_password" | tee -a "$output_file"
    done
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_http_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    for ((i = 0; i < ${#user_passwords[@]}; i++)); do
        user_password="${user_passwords[$i]}"
        if [ "$enable_ech" = true ]; then
            write_phone_client_file
            write_win_client_file
            generate_http_win_client_config "$user_password"
            generate_http_phone_client_config "$user_password"
        else
            write_phone_client_file
            write_win_client_file
            generate_http_win_client_config "$user_password"
            generate_http_phone_client_config "$user_password"
            ensure_clash_yaml
            write_clash_yaml
            generate_http_yaml
        fi
    done
    if [ "$enable_ech" = true ]; then
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    else
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
}

function display_tuic_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local server_address
    local congestion_control=$(jq -r '.inbounds[0].congestion_control' "$config_file")
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [ -z "$domain" ]; then
        server_address="$local_ip"
    else
        server_address="$domain"
    fi
    echo -e "${CYAN}TUIC Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "User Password List:" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    echo "  Username                    UUID                             Password" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < ${#user_names[@]}; i++)); do
        user_name="${user_names[$i]}"
        user_uuid="${user_uuids[$i]}"
        user_password="${user_passwords[$i]}"
        printf "%-13s %-42s %s\n" "$user_name" "$user_uuid" "$user_password" | tee -a "$output_file"
    done
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Congestion Control Algorithm: $congestion_control" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "ALPN: $alpn" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_tuic_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local congestion_control=$(jq -r '.inbounds[0].congestion_control' "$config_file")
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    local num_users=${#user_uuids[@]}
    for ((i = 0; i < num_users; i++)); do
        local user_uuid="${user_uuids[i]}"
        local user_password="${user_passwords[i]}"
        if [ "$enable_ech" = true ]; then
            write_phone_client_file
            write_win_client_file
            generate_tuic_win_client_config "$user_uuid" "$user_password"
            generate_tuic_phone_client_config "$user_uuid" "$user_password"
        else
            write_phone_client_file
            write_win_client_file
            generate_tuic_win_client_config "$user_uuid" "$user_password"
            generate_tuic_phone_client_config "$user_uuid" "$user_password"
            ensure_clash_yaml
            write_clash_yaml
            generate_tuic_yaml
        fi
    done
    if [ "$enable_ech" = true ]; then
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    else
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
}

function display_Shadowsocks_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local ss_method=$(jq -r '.inbounds[0].method' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    echo -e "${CYAN}Shadowsocks Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Encryption Method: $ss_method" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Password: $ss_passwords" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_Shadowsocks_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local ss_method=$(jq -r '.inbounds[0].method' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    write_phone_client_file
    write_win_client_file
    generate_shadowsocks_win_client_config
    generate_shadowsocks_phone_client_config
    ensure_clash_yaml
    write_clash_yaml
    generate_shadowsocks_yaml
    echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
    echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    echo "Clash configuration file has been saved to $clash_file. Please download and use!"
}

function display_socks_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    echo -e "${CYAN}SOCKS Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "User Password List:" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    echo "Username                                 Password" | tee -a "$output_file"
    for ((i = 0; i < ${#user_names[@]}; i++)); do
        user_name="${user_names[$i]}"
        user_password="${user_passwords[$i]}"
        printf "%-35s %s\n" "$user_name" "$user_password" | tee -a "$output_file"
    done
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Node configuration information has been saved to $output_file"
}

function display_socks_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local num_users=${#user_names[@]}
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    for ((i = 0; i < num_users; i++)); do
        local user_name="${user_names[i]}"
        local user_password="${user_passwords[i]}"
        write_phone_client_file
        write_win_client_file
        generate_socks_win_client_config "$user_name" "$user_password"
        generate_socks_phone_client_config "$user_name" "$user_password"
        ensure_clash_yaml
        write_clash_yaml
        generate_socks_yaml
    done
    echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
    echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    echo "Clash configuration file has been saved to $clash_file. Please download and use!"
}

function display_Hysteria_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local server_address
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [ -z "$domain" ]; then
        server_address="$local_ip"
    else
        server_address="$domain"
    fi
    echo -e "${CYAN}Hysteria Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Upload Speed: ${up_mbps}Mbps" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Download Speed: ${down_mbps}Mbps" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "ALPN: $alpn" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Username                                   Password" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < ${#user_names[@]}; i++)); do
        user_name="${user_names[$i]}"
        user_password="${user_passwords[$i]}"
        printf "%-35s %s\n" "$user_name" "$user_password" | tee -a "$output_file"
    done
    if [ -n "$obfs_password" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "obfs Obfuscation Password: $obfs_password" | tee -a "$output_file"
    fi
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_Hysteria_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    for ((i = 0; i < ${#user_passwords[@]}; i++)); do
        user_password="${user_passwords[$i]}"
        if [ "$enable_ech" = true ]; then
            write_phone_client_file
            write_win_client_file
            generate_Hysteria_win_client_config "$user_password"
            generate_Hysteria_phone_client_config "$user_password"
        else
            write_phone_client_file
            write_win_client_file
            generate_Hysteria_win_client_config "$user_password"
            generate_Hysteria_phone_client_config "$user_password"
            ensure_clash_yaml
            write_clash_yaml
            generate_Hysteria_yaml
        fi
    done
    if [ "$enable_ech" = true ]; then
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    else
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
}

function display_Hy2_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local server_address
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [ -z "$domain" ]; then
        server_address="$local_ip"
    else
        server_address="$domain"
    fi
    echo -e "${CYAN}Hysteria2 Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Upload Speed: ${up_mbps}Mbps" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Download Speed: ${down_mbps}Mbps" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "ALPN: $alpn" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Username                                   Password" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < ${#user_names[@]}; i++)); do
        user_name="${user_names[$i]}"
        user_password="${user_passwords[$i]}"
        printf "%-35s %s\n" "$user_name" "$user_password" | tee -a "$output_file"
    done
    if [ -n "$obfs_password" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "QUIC Traffic Obfuscation Password: $obfs_password" | tee -a "$output_file"
    fi
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_Hy2_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    for ((i = 0; i < ${#user_passwords[@]}; i++)); do
        user_password="${user_passwords[$i]}"
        if [ "$enable_ech" = true ]; then
            write_phone_client_file
            write_win_client_file
            generate_Hysteria2_win_client_config "$user_password"
            generate_Hysteria2_phone_client_config "$user_password"
        else
            write_phone_client_file
            write_win_client_file
            generate_Hysteria2_win_client_config "$user_password"
            generate_Hysteria2_phone_client_config "$user_password"
            ensure_clash_yaml
            write_clash_yaml
            generate_Hysteria2_yaml
        fi
    done
    if [ "$enable_ech" = true ]; then
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    else
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
}

function display_reality_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local flow_type=$(jq -r '.inbounds[0].users[0].flow' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local target_server=$(jq -r '.inbounds[0].tls.reality.handshake.server' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")
    local lobal_public_key="$public_key"
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [[ "$flow_type" == "xtls-rprx-vision" ]]; then
        transport_type="tcp"
    fi
    echo -e "${CYAN}VLESS Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "UUID List:" | tee -a "$output_file"
    for ((i = 0; i < ${#user_uuids[@]}; i++)); do
        user_uuid="${user_uuids[$i]}"
        echo "$user_uuid" | tee -a "$output_file"
    done
    if [ -n "$flow_type" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "Flow Control Type: $flow_type" | tee -a "$output_file"
    fi
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    if [ "$transport_type" != "null" ]; then
        echo "Transport Protocol: $transport_type" | tee -a "$output_file"
        if [ "$transport_type" == "ws" ]; then
            echo "Path: $transport_path" | tee -a "$output_file"
        elif [ "$transport_type" == "httpupgrade" ]; then
            echo "Path: $transport_path" | tee -a "$output_file"
        elif [ "$transport_type" == "grpc" ]; then
            echo "gRPC Service Name: $transport_service_name" | tee -a "$output_file"
        fi
    else
        echo "Transport Protocol: tcp" | tee -a "$output_file"
    fi
    if [ -n "$server_name" ] && [ "$server_name" != "null" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "ServerName: $server_name" | tee -a "$output_file"
    fi
    if [ -n "$target_server" ] && [ "$target_server" != "null" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "Target Server Address: $target_server" | tee -a "$output_file"
    fi
    if [ -n "$short_id" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "Short ID:" | tee -a "$output_file"
        for ((i = 0; i < ${#short_ids[@]}; i++)); do
            short_id="${short_ids[$i]}"
            echo "$short_id" | tee -a "$output_file"
        done
    fi
    if [ -n "$public_key" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
        echo "PublicKey: $public_key" | tee -a "$output_file"
    fi
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_reality_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local flow_type=$(jq -r '.inbounds[0].users[0].flow' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local target_server=$(jq -r '.inbounds[0].tls.reality.handshake.server' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")
    local lobal_public_key="$public_key"
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    for ((i = 0; i < ${#user_uuids[@]}; i++)); do
        local user_uuid="${user_uuids[$i]}"
        write_phone_client_file
        write_win_client_file
        if [[ "$server_name" == "null" ]] && [[ "$transport_type" == "null" ]]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vless_tcp_yaml
            generate_vless_win_client_config
            generate_vless_phone_client_config
        elif [[ "$server_name" == "null" ]] && [[ "$transport_type" == "ws" ]]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vless_ws_yaml
            generate_vless_win_client_config
            generate_vless_phone_client_config
        elif [[ "$server_name" == "null" ]] && [[ "$transport_type" == "grpc" ]]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vless_grpc_yaml
            generate_vless_win_client_config
            generate_vless_phone_client_config
        elif [[ "$server_name" == "null" ]] && [[ "$transport_type" == "httpupgrade" ]]; then
            generate_vless_win_client_config
            generate_vless_phone_client_config
        fi
        for ((j = 0; j < ${#short_ids[@]}; j++)); do
            local short_id="${short_ids[$j]}"
            write_phone_client_file
            write_win_client_file
            if [[ -n "$server_name" ]] && [[ "$server_name" != "null" ]] && [[ "$transport_type" == "null" ]]; then
                ensure_clash_yaml
                write_clash_yaml
                generate_vless_reality_vision_yaml
                generate_vless_win_client_config
                generate_vless_phone_client_config
            elif [[ -n "$server_name" ]] && [[ "$server_name" != "null" ]] && [[ "$transport_type" == "http" ]]; then
                generate_vless_win_client_config
                generate_vless_phone_client_config
            elif [[ -n "$server_name" ]] && [[ "$server_name" != "null" ]] && [[ "$transport_type" == "grpc" ]]; then
                ensure_clash_yaml
                write_clash_yaml
                generate_vless_reality_grpc_yaml
                generate_vless_win_client_config
                generate_vless_phone_client_config
            fi
        done
    done
    if [[ "$transport_type" != "http" && "$transport_type" != "httpupgrade" ]]; then
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
    echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
    echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
}

function display_vmess_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local server_address
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [[ -z "$domain" && -n "$domain_name" ]]; then
        server_address="$local_ip"
    elif [[ -z "$domain" && -z "$domain_name" ]]; then
        server_address="$local_ip"
    elif [[ -n "$domain" ]]; then
        server_address="$domain"
    fi
    echo -e "${CYAN}VMess Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "UUID List:" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < ${#user_uuids[@]}; i++)); do
        user_uuid="${user_uuids[$i]}"
        echo "$user_uuid" | tee -a "$output_file"
    done
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    if [ "$transport_type" != "null" ]; then
        echo "Transport Protocol: $transport_type" | tee -a "$output_file"
        if [ "$transport_type" == "ws" ]; then
            echo "Path: $transport_path" | tee -a "$output_file"
        elif [ "$transport_type" == "httpupgrade" ]; then
            echo "Path: $transport_path" | tee -a "$output_file"
        elif [ "$transport_type" == "grpc" ]; then
            echo "gRPC Service Name: $transport_service_name" | tee -a "$output_file"
        fi
    else
        echo "Transport Protocol: tcp" | tee -a "$output_file"
    fi
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_vmess_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")
    local show_clash_message=true
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    for ((i = 0; i < ${#user_uuids[@]}; i++)); do
        user_uuid="${user_uuids[$i]}"
        write_phone_client_file
        write_win_client_file
        generate_vmess_win_client_config
        generate_vmess_phone_client_config
        if [ "$enable_ech" != true ] && [ -z "$domain" ] && [ -z "$domain_name" ] && [ "$transport_type" == "null" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_tcp_yaml
        elif [ "$enable_ech" != true ] && [ -z "$domain" ] && [ -z "$domain_name" ] && [ "$transport_type" == "ws" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_ws_yaml
        elif [ "$enable_ech" != true ] && [ -z "$domain" ] && [ -z "$domain_name" ] && [ "$transport_type" == "grpc" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_grpc_yaml
        elif [ "$enable_ech" != true ] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "null" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_tcp_tls_yaml
        elif [ "$enable_ech" != true ] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "ws" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_ws_tls_yaml
        elif [ "$enable_ech" != true ] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "grpc" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_grpc_tls_yaml
        elif [ "$enable_ech" != true ] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "http" ]; then
            show_clash_message=false
        fi
    done
    if [ "$transport_type" == "http" ] || [ "$transport_type" == "httpupgrade" ] || [ "$enable_ech" = true ]; then
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    else
        echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
        echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
}

function display_trojan_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local server_address
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    if [[ -z "$domain" && -n "$domain_name" ]]; then
        server_address="$local_ip"
    elif [[ -z "$domain" && -z "$domain_name" ]]; then
        server_address="$local_ip"
    elif [[ -n "$domain" ]]; then
        server_address="$domain"
    fi
    echo -e "${CYAN}Trojan Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $server_address" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Password List:" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < ${#user_passwords[@]}; i++)); do
        user_password="${user_passwords[i]}"
        echo "$user_password" | tee -a "$output_file"
    done
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    if [ "$transport_type" != "null" ]; then
        echo "Transport Protocol: $transport_type" | tee -a "$output_file"
        if [ "$transport_type" == "ws" ]; then
            echo "Path: $transport_path" | tee -a "$output_file"
        elif [ "$transport_type" == "httpupgrade" ]; then
            echo "Path: $transport_path" | tee -a "$output_file"
        elif [ "$transport_type" == "grpc" ]; then
            echo "gRPC Service Name: $transport_service_name" | tee -a "$output_file"
        fi
    else
        echo "Transport Protocol: tcp" | tee -a "$output_file"
    fi
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_trojan_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    for ((i = 0; i < ${#user_passwords[@]}; i++)); do
        user_password="${user_passwords[i]}"
        write_phone_client_file
        write_win_client_file
        generate_trojan_win_client_config
        generate_trojan_phone_client_config
        if [[ "$enable_ech" != true ]] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "null" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_trojan_tcp_tls_yaml
        elif [[ "$enable_ech" != true ]] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "ws" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_trojan_ws_tls_yaml
        elif [[ "$enable_ech" != true ]] && [[ -n "$domain" || -n "$domain_name" ]] && [ "$transport_type" == "grpc" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_trojan_grpc_tls_yaml
        fi
    done
    if [[ "$enable_ech" != true ]] && [[ -n "$domain" || -n "$domain_name" ]] && [[ "$transport_type" != "http" || "$transport_type" != "httpupgrade" ]]; then
        echo "Clash configuration file has been saved to $clash_file. Please download and use!"
    fi
    echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
    echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
}

function display_shadowtls_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local user_input=$(jq -r '.inbounds[0].handshake.server' "$config_file")
    local method=$(jq -r '.inbounds[1].method' "$config_file")
    if [[ -n "$ip_v4" ]]; then
        local_ip="$ip_v4"
    elif [[ -n "$ip_v6" ]]; then
        local_ip="$ip_v6"
    fi
    echo -e "${CYAN}ShadowTLS Node Configuration Information:${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "Server Address: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Listening Port: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Encryption Method: $method" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "ShadowTLS Username                  ShadowTLS Password" | tee -a "$output_file"
    echo "------------------------------------------------------------------------------" | tee -a "$output_file"
    for ((i = 0; i < ${#stls_passwords[@]}; i++)); do
        local stls_password="${stls_passwords[i]}"
        printf "%-25s %s\n" "$user_name" "$stls_password" | tee -a "$output_file"
    done
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Shadowsocks Password: $ss_passwords" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Handshake Server Address: $user_input" | tee -a "$output_file"
    echo -e "${CYAN}==============================================================================${NC}" | tee -a "$output_file"
    echo "" >>"$output_file"
    echo "Configuration information has been saved to $output_file"
}

function display_shadowtls_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
    local win_client_file="/usr/local/etc/sing-box/win_client.json"
    local user_input=$(jq -r '.inbounds[0].handshake.server' "$config_file")
    local method=$(jq -r '.inbounds[1].method' "$config_file")
    for ((i = 0; i < ${#stls_passwords[@]}; i++)); do
        local stls_password="${stls_passwords[i]}"
        write_phone_client_file
        write_win_client_file
        generate_shadowtls_win_client_config "$stls_password"
        generate_shadowtls_phone_client_config "$stls_password"
        ensure_clash_yaml
        write_clash_yaml
        generate_shadowtls_yaml
    done
    echo "Phone client configuration file has been saved to $phone_client_file. Please download and use!"
    echo "Win client configuration file has been saved to $win_client_file. Please download and use!"
    echo "Clash configuration file has been saved to $clash_file. Please download and use!"
}

function view_saved_config() {
    local config_paths=(
        "/usr/local/etc/sing-box/output.txt"
        "/usr/local/etc/juicity/output.txt"
    )
    local found=false
    for path in "${config_paths[@]}"; do
        if [[ -f "$path" ]]; then
            echo "Configuration information file ($path):"
            cat "$path"
            found=true
        fi
    done

    if [[ "$found" == false ]]; then
        echo "No saved configuration information file found!"
    fi
}

function check_and_restart_services() {
    if [ -f "/etc/systemd/system/sing-box.service" ]; then
        systemctl restart sing-box.service
        systemctl status --no-pager sing-box.service
    fi
    if [ -f "/etc/systemd/system/juicity.service" ]; then
        systemctl restart juicity.service
        systemctl status --no-pager juicity.service
    fi
}

function uninstall_sing_box() {
    echo "Uninstalling sing-box..."
    systemctl stop sing-box
    systemctl disable sing-box
    rm -rf /usr/local/bin/sing-box
    rm -rf /usr/local/etc/sing-box
    rm -rf /etc/systemd/system/sing-box.service
    systemctl daemon-reload
    echo "sing-box has been uninstalled."
}

function uninstall_juicity() {
    echo "Uninstalling juicity..."
    systemctl stop juicity.service
    systemctl disable juicity.service
    rm -rf /etc/systemd/system/juicity.service
    rm -rf /usr/local/etc/juicity
    rm -rf /usr/local/bin/juicity-server
    echo "juicity has been uninstalled."
}

function update_proxy_tool() {
    if [ -e /usr/local/bin/juicity-server ]; then
        install_latest_juicity
    fi
    if [ -e /usr/local/bin/sing-box ]; then
        select_sing_box_install_option
        migrate_existing_config
        if validate_sing_box_config; then
            systemctl restart sing-box
        fi
    fi
}

function uninstall() {
    local uninstall_sing_box=false
    local uninstall_juicity=false
    if [[ -f "/etc/systemd/system/sing-box.service" ]] || [[ -f "/usr/local/bin/sing-box" ]] || [[ -d "/usr/local/etc/sing-box/" ]]; then
        uninstall_sing_box=true
    fi
    if [[ -f "/etc/systemd/system/juicity.service" ]] || [[ -f "/usr/local/bin/juicity-server" ]] || [[ -d "/usr/local/etc/juicity/" ]]; then
        uninstall_juicity=true
    fi
    if [[ "$uninstall_sing_box" == true ]]; then
        uninstall_sing_box
    fi
    if [[ "$uninstall_juicity" == true ]]; then
        uninstall_juicity
    fi
}

function check_wireguard_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    if grep -q "wireguard" "$config_file"; then
        echo -e "${RED}Warp is already installed. Please do not install it again!${NC}"
        exit 1
    fi
}

function Update_Script() {
    wget -O /root/singbox.sh https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/Install.sh
    chmod +x /root/singbox.sh
}

function add_cron_job() {
    if command -v crontab >/dev/null && crontab -l | grep -q "singbox.sh"; then
        echo "Cron job already exists."
    else
        (
            crontab -l 2>/dev/null
            echo "0 2 * * 1 /bin/bash /root/singbox.sh >> /usr/local/etc/certificate.log 2>&1"
        ) | crontab -
        echo "Cron job added successfully."
    fi
}

function juicity_install() {
    configure_dns64
    enable_bbr
    create_juicity_folder
    install_latest_juicity
    get_local_ip
    generate_juicity_config
    add_cron_job
    configure_juicity_service
    systemctl daemon-reload
    systemctl enable juicity.service
    systemctl start juicity.service
    systemctl restart juicity.service
    display_juicity_config
}

function Direct_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    set_listen_port
    set_override_address
    set_override_port
    generate_Direct_config
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    check_firewall_configuration
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    get_local_ip
    display_Direct_config
}

function Shadowsocks_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    set_listen_port
    select_encryption_method
    set_ss_password
    generate_ss_config
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    check_firewall_configuration
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    get_local_ip
    display_Shadowsocks_config_info
    display_Shadowsocks_config_files
}

function socks_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_socks_config
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    check_firewall_configuration
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    get_local_ip
    display_socks_config_info
    display_socks_config_files
}

function NaiveProxy_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_naive_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_naive_config_info
    generate_naive_config_files
}

function http_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_http_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_http_config_info
    display_http_config_files
}

function tuic_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_tuic_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    get_local_ip
    display_tuic_config_info
    display_tuic_config_files
}

function Hysteria_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_Hysteria_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Hysteria_config_info
    display_Hysteria_config_files
}

function shadowtls_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_shadowtls_config
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    check_firewall_configuration
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    get_local_ip
    display_shadowtls_config_info
    display_shadowtls_config_files
}

function reality_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_vless_config
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    check_firewall_configuration
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    get_local_ip
    display_reality_config_info
    display_reality_config_files
}

function Hysteria2_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_Hy2_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Hy2_config_info
    display_Hy2_config_files
}

function trojan_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    generate_trojan_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_trojan_config_info
    display_trojan_config_files
}

function vmess_install() {
    install_sing_box
    enable_bbr
    log_outbound_config
    get_local_ip
    generate_vmess_config
    add_cron_job
    modify_format_inbounds_and_outbounds
    modify_route_rules
    validate_sing_box_config
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_vmess_config_info
    display_vmess_config_files
}

function wireguard_install() {
    check_wireguard_config
    check_config_file_existence
    select_unlocked_items
    geosite=()
    update_geosite_array
    select_outbound
    update_route_file "$outbound"
    get_temp_config_file
    extract_variables_and_cleanup
    update_outbound_file
    modify_route_rules
    if validate_sing_box_config; then
        systemctl restart sing-box
    fi
}

function Update_certificate() {
    get_local_ip
    extract_tls_info
    validate_tls_info
    Reapply_certificates
}

function main_menu() {
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo -e "║ ${YELLOW}      ░██████╗██╗███╗░░██╗░██████╗░░░░░░░██████╗░░█████╗░██╗░░██╗${NC}      ║"
    echo -e "║ ${YELLOW}      ██╔════╝██║████╗░██║██╔════╝░░░░░░░██╔══██╗██╔══██╗╚██╗██╔╝${NC}      ║"
    echo -e "║ ${YELLOW}      ╚█████╗░██║██╔██╗██║██║░░██╗░█████╗██████╦╝██║░░██║░╚███╔╝░${NC}      ║"
    echo -e "║ ${YELLOW}      ░╚═══██╗██║██║╚████║██║░░╚██╗╚════╝██╔══██╗██║░░██║░██╔██╗░${NC}      ║"
    echo -e "║ ${YELLOW}      ██████╔╝██║██║░╚███║╚██████╔╝░░░░░░██████╦╝╚█████╔╝██╔╝╚██╗${NC}      ║"
    echo -e "║ ${YELLOW}      ╚═════╝░╚═╝╚═╝░░╚══╝░╚═════╝░░░░░░░╚═════╝░░╚════╝░╚═╝░░╚═╝${NC}      ║"
    echo -e "║                                                                        ║"
    echo -e "║ ${YELLOW}     ███╗░░░███╗░█████╗░███╗░░██╗░█████╗░░██████╗░███████╗██████╗░${NC}     ║"
    echo -e "║ ${YELLOW}     ████╗░████║██╔══██╗████╗░██║██╔══██╗██╔════╝░██╔════╝██╔══██╗${NC}     ║"
    echo -e "║ ${YELLOW}     ██╔████╔██║███████║██╔██╗██║███████║██║░░██╗░█████╗░░██████╔╝${NC}     ║"
    echo -e "║ ${YELLOW}     ██║╚██╔╝██║██╔══██║██║╚████║██╔══██║██║░░╚██╗██╔══╝░░██╔══██╗${NC}     ║"
    echo -e "║ ${YELLOW}     ██║░╚═╝░██║██║░░██║██║░╚███║██║░░██║╚██████╔╝███████╗██║░░██║${NC}     ║"
    echo -e "║ ${YELLOW}     ╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝░╚═════╝░╚══════╝╚═╝░░╚═╝${NC}     ║"
    echo "╠════════════════════════════════════════════════════════════════════════╣"
    echo "║ Please choose an action to execute:                                    ║"
    echo -e "║ ${CYAN}[1]${NC}  SOCKS                             ${CYAN}[2]${NC}  Direct                     ║"
    echo -e "║ ${CYAN}[3]${NC}  HTTP                              ${CYAN}[4]${NC}  VMess                      ║"
    echo -e "║ ${CYAN}[5]${NC}  VLESS                             ${CYAN}[6]${NC}  TUIC                       ║"
    echo -e "║ ${CYAN}[7]${NC}  Juicity                           ${CYAN}[8]${NC}  Trojan                     ║"
    echo -e "║ ${CYAN}[9]${NC}  Hysteria                          ${CYAN}[10]${NC} Hysteria2                  ║"
    echo -e "║ ${CYAN}[11]${NC} ShadowTLS                         ${CYAN}[12]${NC} NaiveProxy                 ║"
    echo -e "║ ${CYAN}[13]${NC} Shadowsocks                       ${CYAN}[14]${NC} WireGuard                  ║"
    echo -e "║ ${CYAN}[15]${NC} View Node Information             ${CYAN}[16]${NC} Update Kernel              ║"
    echo -e "║ ${CYAN}[17]${NC} Update Script                     ${CYAN}[18]${NC} Update Certificate         ║"
    echo -e "║ ${CYAN}[19]${NC} Restart Services                  ${CYAN}[20]${NC} Node Management            ║"
    echo -e "║ ${CYAN}[21]${NC} Uninstall                         ${CYAN}[0]${NC}  Exit                       ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"

    local choice
    read -p "Please select [0-21]: " choice

    case $choice in
    1)
        socks_install
        exit 0
        ;;
    2)
        Direct_install
        exit 0
        ;;
    3)
        http_install
        exit 0
        ;;
    4)
        vmess_install
        exit 0
        ;;
    5)
        reality_install
        exit 0
        ;;
    6)
        tuic_install
        exit 0
        ;;
    7)
        juicity_install
        exit 0
        ;;
    8)
        trojan_install
        exit 0
        ;;
    9)
        Hysteria_install
        exit 0
        ;;
    10)
        Hysteria2_install
        exit 0
        ;;
    11)
        shadowtls_install
        exit 0
        ;;
    12)
        NaiveProxy_install
        exit 0
        ;;
    13)
        Shadowsocks_install
        exit 0
        ;;
    14)
        wireguard_install
        exit 0
        ;;
    15)
        view_saved_config
        exit 0
        ;;

    16)
        update_proxy_tool
        exit 0
        ;;
    17)
        Update_Script
        exit 0
        ;;
    18)
        Update_certificate
        ;;
    19)
        check_and_restart_services
        exit 0
        ;;
    20)
        delete_choice
        exit 0
        ;;
    21)
        uninstall
        exit 0
        ;;
    0)
        echo "Thanks for using! goodbye!"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid selection, please re-enter.${NC}"
        main_menu
        ;;
    esac
}

function run_option() {
    case "$1" in
    "18")
        Update_certificate
        exit 0
        ;;
    esac
}

if [ $# -eq 0 ]; then
    main_menu
else
    run_option "$1"
fi

main_menu
