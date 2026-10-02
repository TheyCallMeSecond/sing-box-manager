<div align="center">

[![banner](https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/img/01.png?raw=true "banner")](https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/img/01.png?raw=true "banner")

</div>

# **Updated content**
- **V 1.4**
- **Requires sing-box 1.14+.** Generated server and client configurations follow the current configuration format and no longer use any option that sing-box has removed (up to and including 1.14).
- **Server: legacy inbound fields (`sniff`, `sniff_override_destination`, `sniff_timeout`, `proxy_protocol`) are removed; sniffing is now a `sniff` route rule that is always kept first.**
- **Server: WireGuard (WARP) is now configured as a WireGuard endpoint instead of an outbound. The IPv4/IPv6 choice is applied with a `resolve` route action.**
- **Server: GeoSite rules are written as remote rule-sets, with `http_clients` and `route.default_http_client` configured explicitly.**
- **ECH: removed the obsolete `pq_signature_schemes_enabled` and `dynamic_record_sizing_disabled` options, and the ECH key pair is now generated for the certificate domain.**
- **Client profiles (phone / computer) rewritten: new DNS server format with `domain_resolver`, `predefined` ad blocking, `sniff` and `hijack-dns` route actions, rule-sets instead of GeoIP/GeoSite, TUN `address` instead of `inet4_address`/`inet6_address`, TUN `stack` removed, and the `block` / `dns` outbounds removed.**
- **Existing installations are migrated automatically.** Whenever you install a node or update the kernel (menu option 16), the script converts the old server configuration to the new format, keeps a backup (`config.json.bak-*`), and only restarts sing-box if `sing-box check` passes.
- **Every install flow now validates the generated configuration with `sing-box check` and warns if the installed kernel is older than 1.14.**
- **Config editing is now done with `jq` instead of line-number patching, which fixes breakage when adding nodes after a WARP setup or a node deletion.**
- **Compiling from source: removed the build tags that no longer exist (`with_ech`, `with_reality_server`, `with_shadowsocksr`, `with_lwip`).**

<details>
   <summary><b>Historical update content</b></summary>

- **V 1.3**
- **Support sing-box 1.8+ rule-set**
- **Support sing-box 1.8+ cache file**

<br>

- **V 1.2**
- **Client profile added Clash API support.**
- **Other optimizations and fixes.**

<br>

- **V 1.1**
- **Modify the DNS configuration section of the client configuration file.**

<br>

- **V 1.1-beta.3**
- **Add HTTPUpgrade transport layer.**

<br>

- **V 1.1-beta.2**
- **Fix the automatic update certificate issue.**
- **Fix Cron detection rules.**

<br>

- **V 1.1-beta.1** 
- **Add Multiplex (multiplexing), TCP Brutal (congestion control algorithm), ECH (TLS extension) configuration; to enable Multiplex and TCP Brutal, please use the sing-box kernel above 1.7.0, please Install TCP Brutal on your own.**
- **Add support for Juicity node link generation.**
- **Add support for HTTP protocol.**
- **Other optimizations and fixes.**

<br>

- **V 1.0** 
- **Add WireGuard unblock YouTube option.**
- **Add node management options to support deleting the configuration of any node, including server and client configuration files.**
- **Deleting node configuration only supports Version: 1.0 and later.**
- **Other optimizations and fixes.** 
</details>

# **Notes**
- **The script uses sing-box and Juicity kernel.**
- **The script targets sing-box 1.14 or newer. Client apps that load the generated `phone_client.json` / `win_client.json` must also be sing-box 1.14 or newer (older clients do not understand `http_clients`).**
- **Script supports CentOS 8+, Debian 10+, Ubuntu 20+ operating systems.**
- **All protocols of the script support self-signed certificates (except NaiveProxy).**
- **Script supports multiple users.**
- **Script supports coexistence of all protocols.**
- **Script supports self-signed 100-year certificates.**
- **Script supports automatic renewal of certificates.**
- **The script supports HTTP, WebSocket, gRPC, HTTPUpgrade transport protocols.**
- **The script supports Multiplex, TCP Brutal, and ECH configuration; to enable Multiplex and TCP Brutal, the sing-box kernel needs to be ≥1.7.0, and please install TCP Brutal on the server.**
- **Since Clash does not support TCP Brutal and ECH configurations, the Clash configuration file will not be automatically generated if these configurations are enabled.**
- **Upgrading from an older version of the script: choose "Update Kernel" (option 16). The existing server configuration is migrated automatically and backed up first. Client configuration files from older versions are not migrated; delete them and regenerate them by adding a node, or re-download the new ones.**

# **Install**
- **Debian&&Ubuntu use the following command to install dependencies**
```
apt update && apt -y install curl wget tar socat jq git openssl uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev dnsutils cron
```
- **CentOS uses the following command to install dependencies**
```
yum update && yum -y install curl wget tar socat jq git openssl util-linux gcc-c++ zlib-devel openssl-devel libevent-devel bind-utils cronie
```
- **Run the script using the following command**
```
wget -N -O /root/singbox.sh https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/Install.sh && chmod +x /root/singbox.sh && ln -sf /root/singbox.sh /usr/local/bin/singbox && bash /root/singbox.sh
```

# **Instructions**
- **The Clash client configuration file is located in /usr/local/etc/sing-box/clash.yaml. After downloading, it can be used by loading it into the Clash client. It needs to cooperate with the Meta kernel.**
- **sing-box computer configuration file is located in /usr/local/etc/sing-box/win_client.json. After downloading, it can be loaded into V2rayN and SFM clients for use (sing-box 1.14+).**
- **sing-box mobile phone configuration file is located in /usr/local/etc/sing-box/phone_client.json. After downloading, it can be loaded into SFA and SFI clients for use (sing-box 1.14+).**
- **WireGuard (WARP) is stored in the `endpoints` section of /usr/local/etc/sing-box/config.json with the tag `wireguard-ep`.**

# **Node types supported by script**
- **SOCKS**
- **HTTP**
- **TUIC V5**
- **Juicity**
- **WireGuard--Unlock ChatGPT, Netflix, Disney+, Google, Spotify**
- **Hysteria2**
- **VLESS+TCP**
- **VLESS+WebSocket**
- **VLESS+gRPC**
- **VLESS+HTTPUpgrade**
- **VLESS+Vision+REALITY**
- **VLESS+H2C+REALITY**
- **VLESS+gRPC+REALITY**
- **Direct--sing-box**
- **Trojan+TCP**
- **Trojan+WebSocket**
- **Trojan+gRPC**
- **Trojan+HTTPUpgrade**
- **Trojan+TCP+TLS**
- **Trojan+H2C+TLS**
- **Trojan+gRPC+TLS**
- **Trojan+WebSocket+TLS**
- **Trojan+HTTPUpgrade+TLS**
- **Hysteria**
- **ShadowTLS V3**
- **NaiveProxy**
- **Shadowsocks**
- **VMess+TCP**
- **VMess+WebSocket**
- **VMess+gRPC**
- **VMess+HTTPUpgrade**   
- **VMess+TCP+TLS**
- **VMess+WebSocket+TLS** 
- **VMess+H2C+TLS**
- **VMess+gRPC+TLS** 
- **VMess+HTTPUpgrade+TLS**
