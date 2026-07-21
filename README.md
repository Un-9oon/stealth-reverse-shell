# Stealth Reverse Shell Toolkit

A fully evasive WSS reverse shell framework for **Linux** and **Windows**, written in Rust. Designed for authorized red team engagements, penetration testing, and security research in controlled lab environments.

> **⚠️ DISCLAIMER:** This toolkit is intended for authorized security testing, CTF challenges, and educational purposes only. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and punishable under applicable cybercrime laws.

---

## Tools

| Tool | Platform | Stealth Rating | Description |
|------|----------|----------------|-------------|
| [**ERS**](./ERS/) | Linux | 20/20 | WSS reverse shell with Tor, split-process IPC, BoringSSL Chrome JA3 fingerprint |
| [**ERS-W**](./ERS-W/) | Windows | 24/24 | WSS reverse shell with sandbox detection, anti-debug, registry persistence |

---

## Highlights

### ERS (Linux)
- **9 Defense Evasion techniques** — XOR obfuscation, fileless execution, process masquerading, sleep mask encryption, sandbox/VM detection, anti-core-dump
- **Split-process architecture** — network handler + command executor via anonymous Unix socketpair IPC
- **Tor onion routing** — auto-install, auto-start hidden service, zero IP attribution
- **Chrome 120 JA3 fingerprint** — BoringSSL configured to match Chrome's TLS fingerprint exactly
- **12 in-process builtins** — zero `fork`/`exec` for common recon commands
- **LOLBin routing** — commands routed through `systemd-run` / `script` / `nsenter`

### ERS-W (Windows)
- **8 Defense Evasion techniques** — XOR obfuscation, 494 post-build binary patches, sandbox detection, anti-debug, self-deletion
- **WSS over TLS** with rustls (pure Rust TLS) + Chrome 120 User-Agent
- **18 built-in commands** including `persist`, `pe` (privilege escalation scan), registry/network operations
- **Registry Run Key persistence** — copies to `%APPDATA%\WindowsUpdateSvc.exe`

---

## Quick Start

### ERS (Linux — Tor mode)
```bash
cd ERS
sudo bash setup.sh
# Automatically: installs deps → creates Tor hidden service → builds + scrubs binary → starts listener
```

### ERS-W (Windows — cross-compile from Linux)
```bash
cd ERS-W
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
bash build.sh
python3 listener.py 443
```

---

## Companion Project

| Repository | Description |
|---|---|
| [**stealth-privesc**](https://github.com/Un-9oon/stealth-privesc) | Stealth Privilege Escalation Scanner — Linux (SPES) + Windows (SPES-W) |

---

## MITRE ATT&CK Coverage

27+ techniques across Defense Evasion, Execution, Command & Control, Persistence, and Discovery tactics. See individual tool READMEs for full mappings.

---

## Lab Environment

Built and tested in:
- **Attacker:** Kali Linux (host)
- **Victim:** Ubuntu VM / Windows VM (VirtualBox)
- **Network:** NAT + host-only adapter

## License

For educational and authorized security research purposes only.
