# Ultimate Ubuntu Hardening Script

This repository provides a **one-script solution** for hardening fresh Ubuntu servers.  
It can be used for **bastion hosts** (jump boxes) and **general servers** (e.g. web, mail).

The script:
- Creates a non-root sudo user
- Sets up SSH key authentication (optionally generates keys)
- Changes the SSH port
- Disables root and password logins
- Configures a restrictive **UFW firewall**
- Installs and configures **Fail2ban**
- Enables **automatic security updates**
- Installs **auditd** for logging
- Runs an initial **Lynis** audit
- (Optional) Installs **CrowdSec** for community-driven intrusion detection & blocking

---

## 📦 Requirements
- Ubuntu 20.04, 22.04, or 24.04
- Root access on a fresh server

---

## 🚀 Usage

### 1. Download the script

    curl -O https://raw.githubusercontent.com/itseMeCode/harden-ubuntu.sh
    chmod +x harden-ubuntu.sh
    
### 2. Run the script

#### Bastion host (small server)

    sudo ./harden-ubuntu.sh \
      --user admin \
      --ssh-port 2222 \
      --generate-key \
      --role bastion \
      --enable-crowdsec

- Creates user `admin`
- Sets SSH to port `2222`
- Generates a new `ed25519` keypair (you’ll copy the private key to your workstation)
- Installs CrowdSec for advanced blocking

#### General server (e.g. mail/web)

    sudo ./harden-ubuntu.sh \
      --user admin \
      --ssh-port 2222 \
      --role general \
      --allow-ssh-from <bastion-ip>

- Creates user `admin`
- Sets SSH to port `2222`
- Only allows SSH **from your bastion’s IP**
- Opens ports 80/443 (HTTP/HTTPS) by default

---

## 🔑 Options

| Option                  | Description                                                                  |
|-------------------------|------------------------------------------------------------------------------|
| `--user <name>`         | Username to create (sudo-enabled)                                            |
| `--ssh-port <port>`     | SSH port to use (default: 2222)                                              |
| `--pubkey "<key>"`      | Public SSH key to install for the new user                                   |
| `--generate-key`        | Generate a new ed25519 keypair on the server                                 |
| `--role bastion`        | Configure as bastion (SSH only)                                              |
| `--role general`        | Configure as general server (SSH + HTTP/HTTPS)                               |
| `--allow-ssh-from <ip>` | Restrict SSH access to given IP/CIDR (recommended for general servers)       |
| `--enable-crowdsec`     | Install CrowdSec for community-driven protection                              |

---

## 🖥️ Client-Side Setup (`~/.ssh/config`)

On your workstation, configure SSH shortcuts for easier access:

    Host bastion
        HostName <bastion-ip>
        User admin
        Port 2222
        IdentityFile ~/.ssh/id_ed25519_bastion
        ServerAliveInterval 60
        ServerAliveCountMax 2

    Host big
        HostName <big-server-ip>
        User admin
        Port 2222
        ProxyJump bastion
        IdentityFile ~/.ssh/id_ed25519_big
        ServerAliveInterval 60
        ServerAliveCountMax 2

Then you can connect with:

    ssh bastion
    ssh big   # automatically jumps through bastion

---

## 🔍 Security Tools Installed

- **UFW**: simple firewall with defaults (deny inbound, allow outbound)
- **Fail2ban**: bans brute force login attempts
- **Unattended Upgrades**: keeps security patches up to date
- **Auditd**: logs critical system events
- **Lynis**: performs security auditing (`lynis audit system`)
- **CrowdSec (optional)**: blocks malicious IPs using shared community intelligence

---

## ⚠️ Notes
- Run on a **fresh server** to avoid conflicts.
- Always back up the generated private keys securely.
- Test your SSH connection on the new port before closing your existing session.
- For production, restrict SSH to bastion-only (`--allow-ssh-from <bastion-ip>`).

---

## 📝 License
MIT License
