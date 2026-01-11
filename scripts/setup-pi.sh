#!/bin/bash
# ==============================================================================
# Honeypot Security System - Raspberry Pi 3 Setup Script
# Debian 13 (Trixie) / Raspberry Pi OS 64-bit ARM64
# ==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Honeypot Security System Setup${NC}"
echo -e "${GREEN}  Raspberry Pi 3 - ARM64${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running on ARM64
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" ]]; then
    echo -e "${YELLOW}Warning: This script is optimized for ARM64 (aarch64)${NC}"
    echo -e "${YELLOW}Detected architecture: $ARCH${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Warning: Running as root is not recommended${NC}"
    echo -e "${YELLOW}Consider running as a regular user with sudo${NC}"
fi

# Update system
echo -e "${GREEN}[1/5] Updating system packages...${NC}"
sudo apt-get update
sudo apt-get upgrade -y

# Install Docker if not present
echo -e "${GREEN}[2/5] Installing Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker $USER
    echo -e "${YELLOW}Note: Log out and back in for docker group changes${NC}"
else
    echo "Docker already installed"
fi

# Install Docker Compose plugin
echo -e "${GREEN}[3/5] Installing Docker Compose...${NC}"
if ! docker compose version &> /dev/null; then
    sudo apt-get install -y docker-compose-plugin
else
    echo "Docker Compose already installed"
fi

# Create directories
echo -e "${GREEN}[4/5] Setting up directories...${NC}"
mkdir -p data logs
chmod 755 data logs

# Copy config if not exists
if [[ ! -f config/config.yaml ]]; then
    cp config/config.example.yaml config/config.yaml
    echo -e "${YELLOW}Created config/config.yaml - please edit with your settings${NC}"
fi

# Build and start
echo -e "${GREEN}[5/5] Building Docker image...${NC}"
echo -e "${YELLOW}This may take 10-15 minutes on Raspberry Pi 3${NC}"

docker compose -f docker-compose.arm64.yml build --no-cache

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "To start the honeypot:"
echo -e "  ${YELLOW}docker compose -f docker-compose.arm64.yml up -d${NC}"
echo ""
echo -e "To view logs:"
echo -e "  ${YELLOW}docker compose -f docker-compose.arm64.yml logs -f${NC}"
echo ""
echo -e "To stop:"
echo -e "  ${YELLOW}docker compose -f docker-compose.arm64.yml down${NC}"
echo ""
echo -e "Access Dashboard: ${GREEN}http://$(hostname -I | awk '{print $1}'):5000${NC}"
echo -e "Web Honeypot:     ${GREEN}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo -e "SSH Honeypot:     ${GREEN}ssh -p 2222 $(hostname -I | awk '{print $1}')${NC}"
echo ""
