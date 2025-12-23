#!/bin/bash
# Honeypot Security System - Installation Script
# For Raspberry Pi / Debian / Ubuntu

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║     🍯 HONEYPOT SECURITY SYSTEM - INSTALLER                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (sudo ./install.sh)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "[*] Project directory: $PROJECT_DIR"
echo ""

# Update system
echo "[1/7] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Python and pip
echo "[2/7] Installing Python and dependencies..."
apt-get install -y python3 python3-pip python3-venv

# Install system dependencies
echo "[3/7] Installing system dependencies..."
apt-get install -y \
    libffi-dev \
    libssl-dev \
    build-essential \
    git

# Create virtual environment
echo "[4/7] Creating Python virtual environment..."
cd "$PROJECT_DIR"
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "[5/7] Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Setup configuration
echo "[6/7] Setting up configuration..."
if [ ! -f "$PROJECT_DIR/config/config.yaml" ]; then
    cp "$PROJECT_DIR/config/config.example.yaml" "$PROJECT_DIR/config/config.yaml"
    echo "[*] Created config.yaml from example"
    echo "[!] Please edit config/config.yaml to configure your settings"
fi

# Generate SSH host key
echo "[7/7] Generating SSH host key..."
mkdir -p "$PROJECT_DIR/data"
if [ ! -f "$PROJECT_DIR/data/ssh_host_key" ]; then
    ssh-keygen -t rsa -b 2048 -f "$PROJECT_DIR/data/ssh_host_key" -N ""
    echo "[*] SSH host key generated"
fi

# Create logs directory
mkdir -p "$PROJECT_DIR/logs"

# Set permissions
chown -R $SUDO_USER:$SUDO_USER "$PROJECT_DIR"
chmod +x "$PROJECT_DIR/main.py"
chmod +x "$PROJECT_DIR/scripts/"*.sh

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║     ✅ INSTALLATION COMPLETE                                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: nano config/config.yaml"
echo "  2. Add Discord webhook URL for alerts"
echo "  3. (Optional) Download GeoIP database from MaxMind"
echo "  4. Start the system: sudo python3 main.py"
echo ""
echo "For systemd service, run: sudo ./scripts/setup_service.sh"
echo ""
