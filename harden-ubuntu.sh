#!/usr/bin/env bash
set -euo pipefail
set -o errtrace

trap 'echo "[!] Error on line $LINENO. Aborting."; exit 1' ERR

########################
# Defaults / Arguments #
########################

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

SSH_PORT="${SSH_PORT:-2222}"
NEW_USER=""
PUBKEY=""
GENERATE_KEY="false"

# Per your request: keep printing private key if generated.
PRINT_PRIVATE_KEY="true"

ROLE="general"              # bastion|general
ALLOW_SSH_FROM=""           # comma-separated list of IPv4/IPv6 CIDRs or IPs
ENABLE_CROWDSEC="false"
PURGE_MTA="false"
AUTO_REBOOT="false"         # unattended-upgrades auto reboot at 03:30 if true
KEEP_SSH_22="false"         # keep port 22 open after port change, for safe cutover

# Advanced CrowdSec handling
CROWDSEC_FORCE_TAINTED="true"      # force-enable tainted items (safe for idempotent infra-as-code)
CROWDSEC_ALLOW_REPO_ADD="true"     # add official CrowdSec repo if bouncer packages missing

usage() {
  cat <<EOF
Usage:
  $0 --user <name>
     [--ssh-port 2222]
     [--pubkey "<ssh-ed25519 ...>"] [--generate-key]
     [--role bastion|general]
     [--allow-ssh-from "<IP/CIDR>[,<IP6/CIDR6>...]"]
     [--enable-crowdsec]
     [--purge-mta]
     [--auto-reboot]
     [--keep-ssh-22]

Notes:
  - PasswordAuthentication will be disabled ONLY if authorized_keys is non-empty.
  - When --generate-key is used, the private key will be generated and printed.
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
    --purge-mta) PURGE_MTA="true"; shift 1;;
    --auto-reboot) AUTO_REBOOT="true"; shift 1;;
    --keep-ssh-22) KEEP_SSH_22="true"; shift 1;;
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
[[ "$KEEP_SSH_22" == "true" ]] && echo "[*] Will keep port 22 open for safe cutover"

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
  auditd audispd-plugins lynis whois openssh-server gnupg

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
KEY_PATH="$USER_HOME/.ssh/id_ed25519"
if [[ -n "$PUBKEY" ]]; then
  echo "[*] Installing provided public key for $NEW_USER"
  if ! grep -qxF "$PUBKEY" "$USER_HOME/.ssh/authorized_keys"; then
    echo "$PUBKEY" >> "$USER_HOME/.ssh/authorized_keys"
  else
    echo "[*] Provided public key already present in authorized_keys."
  fi
elif [[ "$GENERATE_KEY" == "true" ]]; then
  if [[ -f "$KEY_PATH" ]]; then
    echo "[*] Key already exists at $KEY_PATH (skipping generation)."
  else
    echo "[*] Generating ed25519 keypair for $NEW_USER (no passphrase)..."
    sudo -u "$NEW_USER" ssh-keygen -t ed25519 -N "" -f "$KEY_PATH"
    # Add pubkey to authorized_keys if not present
    if ! grep -qxF "$(cat "${KEY_PATH}.pub")" "$USER_HOME/.ssh/authorized_keys"; then
      cat "${KEY_PATH}.pub" >> "$USER_HOME/.ssh/authorized_keys"
    fi
    chmod 600 "$KEY_PATH" "${KEY_PATH}.pub"
    chown "$NEW_USER:$NEW_USER" "$KEY_PATH" "${KEY_PATH}.pub"
  fi
else
  echo "[*] No public key provided and --generate-key not set. Add a key before disabling password auth."
fi

########################
# UFW firewall (pre-SSH) #
########################
echo "[*] Configuring UFW (preparing SSH cutover)..."
# Ensure IPv6 is enabled
if grep -q '^IPV6=' /etc/default/ufw; then
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
else
  echo 'IPV6=yes' >> /etc/default/ufw
fi

# Initialize UFW (idempotent)
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH on new port (from given sources if provided)
if [[ -n "$ALLOW_SSH_FROM" ]]; then
  IFS=',' read -r -a sources <<<"$ALLOW_SSH_FROM"
  for src in "${sources[@]}"; do
    ufw allow from "$src" to any port "$SSH_PORT" proto tcp || true
  done
else
  ufw allow "$SSH_PORT"/tcp || true
fi

# Optionally keep port 22 open for cutover safety
if [[ "$KEEP_SSH_22" == "true" ]]; then
  ufw allow 22/tcp || true
fi

# Open HTTP/HTTPS on general role
if [[ "$ROLE" == "general" ]]; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
fi

# Rate-limit SSH
ufw limit "$SSH_PORT"/tcp || true

ufw --force enable
ufw status verbose || true

########################
# SSH hardening        #
########################
echo "[*] Hardening SSH configuration..."
SSHD="/etc/ssh/sshd_config"
[[ ! -f "${SSHD}.bak" ]] && cp "$SSHD" "${SSHD}.bak"

# Base secure settings (port first)
sed -i -E "s/^#?Port .*/Port $SSH_PORT/" "$SSHD"
sed -i -E "s/^#?PermitRootLogin .*/PermitRootLogin no/" "$SSHD"
sed -i -E "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" "$SSHD"
sed -i -E "s/^#?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" "$SSHD"
sed -i -E "s/^#?X11Forwarding .*/X11Forwarding no/" "$SSHD"
sed -i -E "s/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/" "$SSHD"
grep -qE "^ClientAliveInterval" "$SSHD" || echo "ClientAliveInterval 300" >> "$SSHD"
grep -qE "^ClientAliveCountMax" "$SSHD" || echo "ClientAliveCountMax 2" >> "$SSHD"
grep -qE "^UseDNS" "$SSHD" || echo "UseDNS no" >> "$SSHD"
grep -qE "^AuthenticationMethods" "$SSHD" || echo "AuthenticationMethods publickey" >> "$SSHD"

# Legal banner (non-informative)
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

# Disable password auth ONLY if keys are present
if [[ -s "$USER_HOME/.ssh/authorized_keys" ]]; then
  sed -i -E "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" "$SSHD"
  echo "[*] PasswordAuthentication disabled (authorized_keys not empty)."
else
  echo "[!] No keys present; leaving PasswordAuthentication enabled to avoid lockout."
  sed -i -E "s/^#?PasswordAuthentication .*/PasswordAuthentication yes/" "$SSHD"
fi

# Validate sshd config before reload
if ! sshd -t 2>/dev/null; then
  echo "[!] sshd config test failed; restoring backup."
  cp "${SSHD}.bak" "$SSHD"
  exit 1
fi

# Apply SSH changes
systemctl reload ssh || systemctl restart ssh

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

# Ensure pwquality in common-password (best-effort)
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
# Process exec tracking (verbose; consider narrowing for prod)
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
net.ipv4.conf.default.rp_filter=1
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
  echo "[*] Installing CrowdSec engine..."
  apt-get update -y
  apt-get install -y crowdsec || true

  if command -v cscli >/dev/null 2>&1; then
    systemctl enable --now crowdsec || true

    cscli hub update || true

    # Handle tainted collections robustly
    if [[ "$CROWDSEC_FORCE_TAINTED" == "true" ]]; then
      cscli collections install crowdsecurity/linux --force || true
      cscli collections install crowdsecurity/sshd  --force || true
    else
      cscli collections upgrade crowdsecurity/linux || true
      cscli collections install crowdsecurity/linux || true
      cscli collections install crowdsecurity/sshd  || true
    fi

    systemctl reload crowdsec || true

    # --- Firewall bouncer install strategy ---
    want_nft="false"
    command -v nft >/dev/null 2>&1 && want_nft="true"

    install_bouncer_pkg() {
      local ok="false"
      if [[ "$want_nft" == "true" ]]; then
        apt-get install -y crowdsec-firewall-bouncer-nftables && ok="true" || true
      fi
      if [[ "$ok" != "true" ]]; then
        apt-get install -y crowdsec-firewall-bouncer-iptables && ok="true" || true
      fi
      if [[ "$ok" != "true" ]]; then
        apt-get install -y crowdsec-firewall-bouncer && ok="true" || true
      fi
      [[ "$ok" == "true" ]]
    }

    if ! install_bouncer_pkg; then
      if [[ "$CROWDSEC_ALLOW_REPO_ADD" == "true" ]]; then
        echo "[i] Adding official CrowdSec APT repo to obtain firewall bouncer..."
        apt-get install -y curl ca-certificates gnupg || true
        curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash || true
        apt-get update -y
        install_bouncer_pkg || echo "[!] Bouncer packages still unavailable after adding repo."
      else
        echo "[!] Bouncer package(s) not found in current repos and repo-add disabled; continuing without bouncer."
      fi
    fi

    BCFG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    HAVE_API_KEY="false"
    if [[ -f "$BCFG" ]]; then
      if ! grep -qE '^api_key:\s*\S' "$BCFG"; then
        echo "[*] Creating firewall bouncer API key..."
        API_KEY="$(cscli bouncers add firewall-bouncer -o raw 2>/dev/null || true)"
        if [[ -n "${API_KEY:-}" ]]; then
          if grep -q '^api_key:' "$BCFG" 2>/dev/null; then
            sed -i "s/^api_key:.*/api_key: ${API_KEY}/" "$BCFG"
          else
            printf "api_key: %s\n" "$API_KEY" >> "$BCFG"
          fi
          HAVE_API_KEY="true"
        else
          echo "[!] Failed to obtain bouncer API key."
        fi
      else
        HAVE_API_KEY="true"
      fi
    fi

    # Enable bouncer only if unit exists and we have an API key
    if systemctl list-unit-files | grep -q '^crowdsec-firewall-bouncer\.service'; then
      if [[ "$HAVE_API_KEY" == "true" ]]; then
        systemctl enable --now crowdsec-firewall-bouncer || true
      else
        echo "[!] Skipping bouncer enable: missing API key."
      fi
    else
      echo "[!] Bouncer systemd unit not present; skipping enable."
    fi

    echo "[*] CrowdSec status:"
    cscli metrics || true
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
if [[ "$KEEP_SSH_22" == "true" ]]; then
  echo "[i] Port 22 is currently kept open for safety. After verifying access on port $SSH_PORT, you should close port 22:"
  echo "    sudo ufw delete allow 22/tcp"
fi
if [[ -f "$KEY_PATH" && "$GENERATE_KEY" == "true" && "$PRINT_PRIVATE_KEY" == "true" ]]; then
  echo
  echo "==== PRIVATE KEY (copy and store securely) ===="
  cat "$KEY_PATH"
  echo "==== END PRIVATE KEY =========================="
  echo
  echo "[i] The matching public key is at: ${KEY_PATH}.pub"
fi
echo "=============================================================="

cat <<'EONEXT'
Next steps (do these NOW, before logging out):

1) From your workstation, copy the private key (if generated here) into a local file, e.g.:
   - Save it as ~/.ssh/id_ed25519_<user> with permissions 600:
     chmod 600 ~/.ssh/id_ed25519_<user>

   OR, if you didn't generate a key here, ensure your workstation's public key
   is in /home/<user>/.ssh/authorized_keys on the server.

2) Open a NEW terminal and test logging in on the NEW port:
   ssh -i ~/.ssh/id_ed25519_<user> -p <port> <user>@<server-ip>

3) If login works, and you used --keep-ssh-22, close port 22:
   sudo ufw delete allow 22/tcp

4) OPTIONAL: If PasswordAuthentication is still enabled because no keys were found,
   add a key to authorized_keys and then you may disable password auth by setting:
   PasswordAuthentication no
   in /etc/ssh/sshd_config, then:
   sudo sshd -t && sudo systemctl reload ssh

Tips:
- Keep an active root/session open while testing the new port.
- Store your private key securely; do not share it; consider a passphrase on workstation keys.
- For CrowdSec+Fail2ban duplication: it's fine, but you can remove one to simplify ops.
EONEXT
