#!/usr/bin/env bash
set -euo pipefail
set -o errtrace

# Ultimate Ubuntu hardening script (bastion or general)
# Changes:
# - Reliable CrowdSec ENGINE + bouncer install + API key wire-up
# - Stronger SSH hardening (extra strict for --role bastion)
# - Auditd baseline rules
# - Kernel/sysctl hardening
# - PAM/password policy + tighter umask
# - Legal banners (no info leaks)
# - Fail2ban: bantime increment + recidive
# - Optional MTA purge (postfix), or harden if present
# - Optional unattended-upgrades auto-reboot
# - Safer key handling (no private key printed by default)

trap 'echo "[!] Error on line $LINENO. Aborting."; exit 1' ERR

########################
# Defaults / Arguments #
########################

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

SSH_PORT="${SSH_PORT:-2222}"
NEW_USER=""
PUBKEY=""
GENERATE_KEY="false"
PRINT_PRIVATE_KEY="false"   # safer default = false
ROLE="general"              # bastion|general
ALLOW_SSH_FROM=""           # comma-separated list of IPv4/IPv6 CIDRs or IPs
ENABLE_CROWDSEC="false"
PURGE_MTA="false"
AUTO_REBOOT="false"         # unattended-upgrades auto reboot at 03:30 if true

usage() {
  cat <<EOF
Usage:
  $0 --user <name>
     [--ssh-port 2222]
     [--pubkey "<ssh-ed25519 ...>"] [--generate-key] [--print-private-key]
     [--role bastion|general]
     [--allow-ssh-from "<IP/CIDR>[,<IP6/CIDR6>...]"]
     [--enable-crowdsec]
     [--purge-mta]            # purge postfix if present
     [--auto-reboot]          # unattended-upgrades auto reboot at 03:30

Examples:
  bash $0 --user admin --ssh-port 2222 --generate-key --role bastion --enable-crowdsec --purge-mta
  bash $0 --user admin --role general --allow-ssh-from 203.0.113.10,2001:db8::/32
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) NEW_USER="$2"; shift 2;;
    --ssh-port) SSH_PORT="$2"; shift 2;;
    --pubkey) PUBKEY="$2"; shift 2;;
    --generate-key) GENERATE_KEY="true"; shift 1;;
    --print-private-key) PRINT_PRIVATE_KEY="true"; shift 1;;
    --role) ROLE="$2"; shift 2;;
    --allow-ssh-from) ALLOW_SSH_FROM="$2"; shift 2;;
    --enable-crowdsec) ENABLE_CROWDSEC="true"; shift 1;;
    --purge-mta) PURGE_MTA="true"; shift 1;;
    --auto-reboot) AUTO_REBOOT="true"; shift 1;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

[[ -z "$NEW_USER" ]] && { echo "ERROR: --user is required"; usage; exit 1; }
[[ "$EUID" -ne 0 ]] && { echo "ERROR: Run as root."; exit 1; }

echo "[*] Role: $ROLE"
echo "[*] New user: $NEW_USER"
echo "[*] SSH port: $SSH_PORT"
[[ -n "$ALLOW_SSH_FROM" ]] && echo "[*] SSH limited to: $ALLOW_SSH_FROM"
[[ "$ENABLE_CROWDSEC" == "true" ]] && echo "[*] CrowdSec: enabled"
[[ "$PURGE_MTA" == "true" ]] && echo "[*] Will purge local MTA if found (postfix)"
[[ "$AUTO_REBOOT" == "true" ]] && echo "[*] Unattended upgrades will auto-reboot nightly"

########################
# System updates       #
########################
echo "[*] Updating system packages..."
apt-get update -y
apt-get upgrade -y

########################
# Essentials           #
########################
echo "[*] Installing base security tools..."
apt-get install -y \
  sudo ufw fail2ban curl wget git unzip ca-certificates \
  unattended-upgrades apt-listchanges bsd-mailx \
  auditd audispd-plugins lynis whois

########################
# Optional: MTA purge  #
########################
if [[ "$PURGE_MTA" == "true" ]]; then
  if dpkg -s postfix >/dev/null 2>&1; then
    echo "[*] Purging postfix..."
    apt-get purge -y postfix
    apt-get autoremove -y
  fi
else
  # If postfix is present, harden banner + disable VRFY
  if dpkg -s postfix >/dev/null 2>&1; then
    echo "[*] Hardening postfix banner + disabling VRFY..."
    postconf -e 'smtpd_banner=$myhostname ESMTP'
    postconf -e 'disable_vrfy_command=yes'
    systemctl reload postfix || true
  fi
fi

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
    chmod 600 "$KEY_PATH" "${KEY_PATH}.pub"
    chown "$NEW_USER:$NEW_USER" "$KEY_PATH" "${KEY_PATH}.pub"
    if [[ "$PRINT_PRIVATE_KEY" == "true" ]]; then
      echo
      echo "==== PRIVATE KEY (copy and store securely) ===="
      cat "$KEY_PATH"
      echo "==== END PRIVATE KEY =========================="
      echo
    else
      echo "[i] Private key stored at $KEY_PATH (not printed)."
      echo "[i] Copy it out with (example):"
      echo "    scp -P $SSH_PORT $NEW_USER@\$(curl -4 -s ifconfig.co):$KEY_PATH ~/.ssh/id_ed25519_${NEW_USER}"
    fi
  fi
else
  echo "[*] No public key provided and --generate-key not set. Add a key before disabling password auth."
fi

########################
# SSH hardening        #
########################
echo "[*] Hardening SSH configuration..."
SSHD="/etc/ssh/sshd_config"
[[ ! -f "${SSHD}.bak" ]] && cp "$SSHD" "${SSHD}.bak"

# Base secure settings
sed -i -E "s/^#?Port .*/Port $SSH_PORT/" "$SSHD"
sed -i -E "s/^#?PermitRootLogin .*/PermitRootLogin no/" "$SSHD"
sed -i -E "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" "$SSHD"
sed -i -E "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" "$SSHD"
sed -i -E "s/^#?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" "$SSHD"
sed -i -E "s/^#?X11Forwarding .*/X11Forwarding no/" "$SSHD"
sed -i -E "s/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/" "$SSHD"
grep -qE "^ClientAliveInterval" "$SSHD" || echo "ClientAliveInterval 300" >> "$SSHD"
grep -qE "^ClientAliveCountMax" "$SSHD" || echo "ClientAliveCountMax 2" >> "$SSHD"
grep -qE "^UseDNS" "$SSHD" || echo "UseDNS no" >> "$SSHD"
grep -qE "^AuthenticationMethods" "$SSHD" || echo "AuthenticationMethods publickey" >> "$SSHD"

# Banner (legal, non-informative)
if ! grep -q "^Banner " "$SSHD"; then
  echo "Banner /etc/issue.net" >> "$SSHD"
fi
cat >/etc/issue <<'EOF'
*** Authorized Use Only ***
This system is for authorized users only. Individuals using this computer system
without authority, or in excess of their authority, are subject to having all
their activities on this system monitored and recorded. All activities are logged.
EOF
cp /etc/issue /etc/issue.net

# Extra strict for bastion
if [[ "$ROLE" == "bastion" ]]; then
  add_or_replace() {
    local key="$1" val="$2"
    if grep -qE "^[#\s]*${key}\b" "$SSHD"; then
      sed -i -E "s|^[#\s]*${key}.*|${key} ${val}|" "$SSHD"
    else
      echo "${key} ${val}" >> "$SSHD"
    fi
  }
  add_or_replace "AllowTcpForwarding" "no"
  add_or_replace "AllowAgentForwarding" "no"
  add_or_replace "TCPKeepAlive" "no"
  add_or_replace "LogLevel" "VERBOSE"
  add_or_replace "MaxAuthTries" "3"
  add_or_replace "MaxSessions" "2"
fi

systemctl reload ssh || systemctl restart ssh

########################
# UFW firewall         #
########################
echo "[*] Configuring UFW..."
# Ensure IPv6 is enabled
if grep -q '^IPV6=' /etc/default/ufw; then
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
else
  echo 'IPV6=yes' >> /etc/default/ufw
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (from given sources if provided)
if [[ -n "$ALLOW_SSH_FROM" ]]; then
  IFS=',' read -r -a sources <<<"$ALLOW_SSH_FROM"
  for src in "${sources[@]}"; do
    ufw allow from "$src" to any port "$SSH_PORT" proto tcp || true
  done
else
  ufw allow "$SSH_PORT"/tcp
fi

# Open HTTP/HTTPS on general role
if [[ "$ROLE" == "general" ]]; then
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
bantime.increment = true

[sshd]
enabled = true
port    = $SSH_PORT
logpath = %(sshd_log)s

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 5
EOF

systemctl enable --now fail2ban
fail2ban-client status sshd || true

########################
# Unattended upgrades  #
########################
echo "[*] Enabling automatic security updates..."
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

if [[ "$AUTO_REBOOT" == "true" ]]; then
  cat >/etc/apt/apt.conf.d/51unattended-upgrades-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
EOF
fi

########################
# PAM & password policy#
########################
echo "[*] Applying PAM/password policy and tighter defaults..."
apt-get install -y libpam-pwquality || true

# login.defs: password aging and umask 027
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs || true
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs || true
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs || true
if grep -q '^UMASK' /etc/login.defs; then
  sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
else
  echo 'UMASK		027' >> /etc/login.defs
fi

# Ensure pwquality in common-password (idempotent best-effort)
if grep -q 'pam_pwquality.so' /etc/pam.d/common-password; then
  sed -i -E 's#(pam_pwquality\.so).*#\1 retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1#g' /etc/pam.d/common-password
else
  sed -i '/pam_unix.so/s/^/# pwquality added below\npassword\trequisite\tpam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n/' /etc/pam.d/common-password
fi

########################
# Auditd               #
########################
echo "[*] Enabling auditd + baseline rules..."
systemctl enable --now auditd
cat >/etc/audit/rules.d/10-hardening.rules <<'EOF'
-D
-b 8192
# Identity & auth
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
# Process exec tracking
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
EOF
augenrules --load || true
systemctl restart auditd || true

########################
# Kernel/sysctl        #
########################
echo "[*] Applying sysctl kernel/network hardening..."
cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
fs.protected_fifos=2
fs.protected_regular=2
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
sysctl --system

########################
# Lynis (audit)        #
########################
echo "[*] Running initial Lynis quick audit..."
lynis audit system --quick || true

########################
# CrowdSec (optional)  #
########################
if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
  echo "[*] Installing CrowdSec engine + firewall bouncer..."
  # Install from repo (more reliable on 22.04/24.04 than the bootstrapper)
  apt-get update -y
  apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables || true

  if command -v cscli >/dev/null 2>&1; then
    systemctl enable --now crowdsec || true
    cscli hub update || true
    # baseline collections
    cscli collections install crowdsecurity/linux crowdsecurity/sshd || true
    systemctl reload crowdsec || true

    # Register bouncer and write API key to bouncer config
    API_KEY="$(cscli bouncers add firewall-bouncer -o raw 2>/dev/null || true)"
    if [[ -n "${API_KEY:-}" ]]; then
      BCFG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
      if [[ -f "$BCFG" ]]; then
        if grep -q '^api_key:' "$BCFG"; then
          sed -i "s/^api_key:.*/api_key: ${API_KEY}/" "$BCFG"
        else
          echo "api_key: ${API_KEY}" >> "$BCFG"
        fi
      fi
    fi

    systemctl enable --now crowdsec-firewall-bouncer || true

    echo "[*] CrowdSec status:"
    cscli metrics show || true
    cscli decisions list || true
  else
    echo "[!] cscli not found; CrowdSec engine may not have installed correctly."
  fi
fi

########################
# Final info           #
########################
IP=$(curl -4 -s ifconfig.co || echo "<your-server-ip>")
echo
echo "=============================================================="
echo "[*] Completed hardening for role: $ROLE"
echo "[*] SSH is on port: $SSH_PORT"
[[ -n "$ALLOW_SSH_FROM" ]] && echo "[*] SSH allowed only from: $ALLOW_SSH_FROM"
echo "[*] Connect like:  ssh -p $SSH_PORT $NEW_USER@$IP"
if [[ "$GENERATE_KEY" == "true" && "$PRINT_PRIVATE_KEY" != "true" ]]; then
  echo "[*] Copy your key (example):"
  echo "    scp -P $SSH_PORT $NEW_USER@$IP:$USER_HOME/.ssh/id_ed25519 ~/.ssh/id_ed25519_${NEW_USER}"
fi
echo "=============================================================="
