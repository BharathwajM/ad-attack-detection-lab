#!/usr/bin/env bash
# Runs ON SPLUNK01 (Ubuntu 24.04) over SSH. Installs Docker, runs Splunk Enterprise in a container,
# and prepares it as the lab SIEM. The Splunk admin password is passed in via the SPLUNK_PW env var
# (read from lab-credentials.local.txt on the host and piped in) so it is never written to this file.
set -euo pipefail

: "${SPLUNK_PW:?SPLUNK_PW must be set by the caller}"

# --- 1. Static IP 10.10.10.30 on the NAT-network interface -----------------------------------------
IFACE="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
[ -z "$IFACE" ] && IFACE="$(ls /sys/class/net | grep -E '^(enp|eth)' | head -n1)"
sudo tee /etc/netplan/99-adlab.yaml >/dev/null <<YAML
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses: [10.10.10.30/24]
      routes:
        - to: default
          via: 10.10.10.1
      nameservers:
        addresses: [10.10.10.10, 1.1.1.1]
YAML
sudo chmod 600 /etc/netplan/99-adlab.yaml
sudo netplan apply || true

# --- 2. Docker engine ------------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
sudo systemctl enable --now docker

# --- 3. Splunk Enterprise container ---------------------------------------------------------------
# Free license (500 MB/day) is applied after first start. Accepting the Splunk license was approved by the user.
sudo docker rm -f splunk 2>/dev/null || true
sudo docker run -d --name splunk --restart unless-stopped \
  -p 8000:8000 -p 8089:8089 -p 9997:9997 -p 1514:1514 \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD="${SPLUNK_PW}" \
  -v splunk-var:/opt/splunk/var \
  -v splunk-etc:/opt/splunk/etc \
  splunk/splunk:10.4

echo "Waiting for Splunk to come up..."
for i in $(seq 1 60); do
  if sudo docker exec splunk /opt/splunk/bin/splunk status 2>/dev/null | grep -q "is running"; then
    break
  fi
  sleep 10
done

# --- 4. Switch to the Free license, enable a receiver on 9997, create the index --------------------
sudo docker exec splunk /opt/splunk/bin/splunk edit licenser-localslave -use_group Free \
  -auth "admin:${SPLUNK_PW}" || true
sudo docker exec splunk /opt/splunk/bin/splunk enable listen 9997 -auth "admin:${SPLUNK_PW}" || true
sudo docker exec splunk /opt/splunk/bin/splunk add index winlogs -auth "admin:${SPLUNK_PW}" || true
# Free license drops the login requirement; restart so it takes effect.
sudo docker exec splunk /opt/splunk/bin/splunk restart || true

echo "SPLUNK01 setup complete. Web UI: http://127.0.0.1:8000 (from host, via port-forward)."
