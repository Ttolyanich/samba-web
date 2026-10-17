#!/bin/bash
set -e

# Samba Web Agent Installer for Linux Host
# Ensures Python 3 is installed, places the agent files, and starts systemd service.

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root: sudo bash install-agent.sh"
  exit 1
fi

echo "[*] Installing Samba Management Agent on host..."

# Check Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[*] Installing python3..."
    apt-get update && apt-get install -y python3
fi

# Directory structure
INSTALL_DIR="/opt/samba-agent"
mkdir -p "$INSTALL_DIR"
mkdir -p "/run/samba-agent"
chmod 755 "/run/samba-agent"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy agent script
cp "$SCRIPT_DIR/samba_agent.py" "$INSTALL_DIR/samba_agent.py"
chmod +x "$INSTALL_DIR/samba_agent.py"

# Copy systemd service
cp "$SCRIPT_DIR/samba-agent.service" "/etc/systemd/system/samba-agent.service"

# Reload systemd and start service
systemctl daemon-reload
systemctl enable --now samba-agent

echo "[+] Samba Host Agent installed and active!"
systemctl status samba-agent --no-pager
