#!/usr/bin/env bash
set -euo pipefail

# Ultimate Ubuntu hardening script (bastion or general)
# - Changes SSH port, disables root/password logins
# - Creates sudo user and installs its SSH public key (or generates a new keypair)
# - Configures UFW, Fail2ban, Unattended Upgrades, Auditd
# - Installs Lynis (audit) and optionally CrowdSec (free, open-source security monitoring + ban lists)
#
# Usage (examples):
#   bash harden-ubuntu.sh --user admin --ssh-port 2222 --pubkey "ssh-ed25519 AAA..." --role bastion --enable-crowdsec
#   bash harden-ubuntu.sh --user admin --ssh-port 2222 --generate-key --role general --allow-ssh-from 203.0.113.10
#
# Notes:
# - If --pubkey is omitted and --generate-key is set, an ed25519 keypair will be created on the server;
#   the private key will be printed once (store it on your workstation).
# - If --allow-ssh-from is set (IP/CIDR), SSH is restricted to that source via UFW.
# - CrowdSec is optional but recommended on the bastion.

########################
# Defaults / Arguments #
########################

SSH_PORT="${SSH_PORT:-2222}"
NEW_USER=""
PUBKEY=""
GENERATE_KEY="false"
ROLE="general"            # bastion|general
ALLOW_SSH_FROM=""         # e.g. 203.0.113.10 or 203.0.113.0/24
ENABLE_CROWDSEC="false"

function usage() {
  cat <<EOF
Usage:
  $0 --user <name> [--ssh-port 2222] [--pubkey "<ssh-ed25519 ...>"] [--generate-key]
     [--role bastion|general] [--allow-ssh-from <IP/CIDR>] [--enable-crowdsec]

Required:
  --user                 Username to create and grant sudo

Optional:
  --ssh-port             SSH port to use (default: 2222)
  --pubkey               Public key string to authorize for the new user
  --generate-key         Generate an ed25519 keypair on this server if no --pubkey given
  --role                 "bastion" or "general" (default: general)
  --allow-ssh-from       Limit SSH ingress to this IP/CIDR via UFW
  --enable-crowdsec      Install CrowdSec + firewall bouncer
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) NEW_USER="$2"; shift 2;;
    --ssh-port) SSH_PORT="$2"; shift 2;;
    --pubkey) PUBKEY="$2"; shift 2;;
    --generate-key) GENERATE_KEY="true"; shift 1;;
    --role) ROLE="$2"; shift 2;;
    --allow-ssh-from) ALLOW_SSH_FROM="$2"; shift 2;;
    --enable-crowdsec) ENABLE_CROWDSEC="true"; shift 1;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if [[ -z "$NEW_USER" ]]; then
  echo "ERROR: --user is required"; usage; exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: Run as root."
  exit 1
fi

echo "[*] Role: $ROLE"
echo "[*] New user: $NEW_USER"
echo "[*] SSH port: $SSH_PORT"
[[ -n "$ALLOW_SSH_FROM" ]] && echo "[*] SSH limited to: $ALLOW_SSH_FROM"
[[ "$ENABLE_CROWDSEC" == "true" ]] && echo "[*] CrowdSec: enabled"

########################
# System updates       #
########################
echo "[*] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

########################
# Essentials           #
########################
echo "[*] Installing base security tools..."
apt-get install -y \
  sudo ufw fail2ban curl wget git unzip ca-certificates \
  unattended-upgrades apt-listchanges bsd-mailx \
  auditd audispd-plugins lynis

########################
# Create admin user    #
########################
if ! id "$NEW_USER" &>/dev/null; then
  echo "[*] Creating user: $NEW_USER"
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

# SSH directory
USER_HOME=$(eval echo "~$NEW_USER")
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
touch "$USER_HOME/.ssh/authorized_keys"
chmod 600 "$USER_HOME/.ssh/authorized_keys"
chown -R "$NEW_USER:$NEW_USER" "$USER_HOME/.ssh"

########################
# Handle key material  #
########################
if [[ -n "$PUBKEY" ]]; then
  echo "[*] Installing provided public key for $NEW_USER"
  if ! grep -qF "$PUBKEY" "$USER_HOME/.ssh/authorized_keys"; then
    echo "$PUBKEY" >> "$USER_HOME/.ssh/authorized_keys"
  fi
elif [[ "$GENERATE_KEY" == "true" ]]; then
  KEY_PATH="$USER_HOME/.ssh/id_ed25519"
  if [[ -f "$KEY_PATH" ]]; then
    echo "[*] Key already exists at $KEY_PATH (skipping generation)."
  else
    echo "[*] Generating ed25519 keypair for $NEW_USER (no passphrase)..."
    sudo -u "$NEW_USER" ssh-keygen -t ed25519 -N "" -f "$KEY_PATH"
    cat "${KEY_PATH}.pub" >> "$USER_HOME/.ssh/authorized_keys"
    echo
    echo "==== COPY THIS PRIVATE KEY NOW AND STORE SECURELY ===="
    cat "$KEY_PATH"
    echo "==== END PRIVATE KEY (will remain at $KEY_PATH) ======"
    echo
  fi
else
  echo "[*] No public key provided and --generate-key not set. You must add a key manually before disabling password auth."
fi

########################
# SSH hardening        #
########################
echo "[*] Hardening SSH configuration..."
SSHD="/etc/ssh/sshd_config"

# Backup once
[[ ! -f "${SSHD}.bak" ]] && cp "$SSHD" "${SSHD}.bak"

# Safe edits (handle commented/uncommented cases)
sed -i -E "s/^#?Port .*/Port $SSH_PORT/" "$SSHD"
sed -i -E "s/^#?PermitRootLogin .*/PermitRootLogin no/" "$SSHD"
sed -i -E "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" "$SSHD"
sed -i -E "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" "$SSHD"
sed -i -E "s/^#?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" "$SSHD"
sed -i -E "s/^#?X11Forwarding .*/X11Forwarding no/" "$SSHD"
sed -i -E "s/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/" "$SSHD"
# KeepAlive
grep -qE "^ClientAliveInterval" "$SSHD" || echo "ClientAliveInterval 300" >> "$SSHD"
grep -qE "^ClientAliveCountMax" "$SSHD" || echo "ClientAliveCountMax 2" >> "$SSHD"

# Banner (optional, simple warning)
if ! grep -q "^Banner " "$SSHD"; then
  echo "Banner /etc/issue.net" >> "$SSHD"
  echo "Authorized access only. Disconnect if you are not authorized." > /etc/issue.net
fi

systemctl reload ssh || systemctl restart ssh

########################
# UFW firewall         #
########################
echo "[*] Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH from specific source if given, else from anywhere (best to use source)
if [[ -n "$ALLOW_SSH_FROM" ]]; then
  ufw allow from "$ALLOW_SSH_FROM" to any port "$SSH_PORT" proto tcp
else
  ufw allow "$SSH_PORT"/tcp
fi

# Optionally open HTTP/HTTPS on general role (for typical servers/mgmt); bastion stays SSH-only
if [[ "$ROLE" == "general" ]]; then
  # Comment these if you truly want zero web access
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
fi

# Rate-limit SSH
ufw limit "$SSH_PORT"/tcp || true

ufw --force enable
ufw status verbose

########################
# Fail2ban             #
########################
echo "[*] Configuring Fail2ban..."
cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = $SSH_PORT
logpath = %(sshd_log)s
EOF

systemctl enable --now fail2ban
fail2ban-client status sshd || true

########################
# Unattended upgrades  #
########################
echo "[*] Enabling automatic security updates..."
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true

# Make sure periodic config exists
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

########################
# Auditd               #
########################
echo "[*] Enabling auditd..."
systemctl enable --now auditd

########################
# Lynis (audit)        #
########################
echo "[*] Running initial Lynis quick audit..."
lynis audit system --quick || true

########################
# CrowdSec (optional)  #
########################
if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
  echo "[*] Installing CrowdSec (engine + firewall bouncer)..."
  # Minimal, distro-agnostic install via script (kept simple for fresh hosts)
  # You can swap to pinned repo steps later if you prefer.
  curl -s https://install.crowdsec.net | bash || true

  # Ensure service is up
  systemctl enable --now crowdsec || true

  # Install firewall bouncer
  apt-get install -y crowdsec-firewall-bouncer-iptables || true
  systemctl enable --now crowdsec-firewall-bouncer || true

  # Enable common SSH collection
  cscli hub update || true
  cscli collections install crowdsecurity/ssh || true
  systemctl reload crowdsec || true

  echo "[*] CrowdSec installed. Current decisions:"
  cscli decisions list || true
fi

########################
# Final info           #
########################
IP=$(curl -4 -s ifconfig.co || echo "<your-server-ip>")
echo
echo "=============================================================="
echo "[*] Completed hardening for role: $ROLE"
echo "[*] SSH is on port: $SSH_PORT"
if [[ -n "$ALLOW_SSH_FROM" ]]; then
  echo "[*] SSH allowed only from: $ALLOW_SSH_FROM"
fi
echo "[*] Connect like:"
echo "    ssh -p $SSH_PORT $NEW_USER@$IP"
echo "=============================================================="
