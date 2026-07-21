#!/bin/bash
# ERS Cleanup — kills all listener, implant, and related processes
# Usage: bash cleanup.sh

echo "[*] Killing listeners..."
pkill -9 -f 'listener.py' 2>/dev/null
pkill -9 -f 'python3 listener' 2>/dev/null

echo "[*] Killing implants..."
pkill -9 -f './implant' 2>/dev/null
pkill -9 -f 'rev_shell_wss' 2>/dev/null

echo "[*] Freeing ports..."
fuser -k 4443/tcp 2>/dev/null
fuser -k 443/tcp 2>/dev/null

echo "[*] Cleaning /dev/shm artifacts..."
rm -f /dev/shm/.dbus-* /dev/shm/.pulse-shm-* 2>/dev/null

echo "[*] Cleaning masqueraded processes..."
pkill -9 -f 'gsd-color' 2>/dev/null
pkill -9 -f 'tracker-miner' 2>/dev/null
pkill -9 -f 'evolution-calendar' 2>/dev/null

echo "[+] Done — all ERS processes killed"
