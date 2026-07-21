#!/bin/bash
# Build + scrub ERS-W (Windows Reverse Shell)
# Usage: bash build.sh
# Requires: rustup target add x86_64-pc-windows-gnu && sudo apt install gcc-mingw-w64-x86-64
set -e

echo "[*] Building ERS-W (Windows)..."
cargo build --release --target x86_64-pc-windows-gnu

echo "[*] Scrubbing binary..."
python3 scrub.py

BIN="target/x86_64-pc-windows-gnu/release/win_rev_shell_wss.exe"
cp "$BIN" ./ers-w.exe
echo "[+] Binary ready: ./ers-w.exe ($(du -h ./ers-w.exe | cut -f1))"
echo "[+] Transfer to Windows target and run"
