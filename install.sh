#!/usr/bin/env bash
# ============================================================
# WiFi Security Auditor — Installation Script for Kali Linux
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║    WiFi Security Auditor — Instalare Kali Linux  ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

if ! command -v apt-get &>/dev/null; then
    echo -e "${RED}Eroare: Scriptul este proiectat pentru Debian/Ubuntu/Kali.${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/3] Actualizare pachete...${NC}"
sudo apt-get update -qq

echo -e "${YELLOW}[2/3] Instalare unelte...${NC}"
sudo apt-get install -y -qq wireless-tools iw network-manager net-tools python3 python3-pip nmap 2>/dev/null || true

echo -e "${YELLOW}[3/3] Setare permisiuni...${NC}"
chmod +x wifi_auditor.py

echo -e "${GREEN}"
echo "✓ Instalare completă!"
echo "Utilizare:"
echo "  sudo python3 wifi_auditor.py"
echo "  sudo python3 wifi_auditor.py --quick"
echo "  sudo python3 wifi_auditor.py --report"
echo "  sudo python3 wifi_auditor.py --json"
echo -e "${NC}"

if grep -qi microsoft /proc/version 2>/dev/null; then
    echo -e "${YELLOW}NOTE WSL detectat:${NC}"
    echo "  nmcli dev wifi list"
fi
