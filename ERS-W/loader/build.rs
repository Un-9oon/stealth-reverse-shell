fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        // Compile .rc resource file for version info + manifest
        let rc_path = std::path::Path::new("res/app.rc");
        if rc_path.exists() {
            // Use windres (from mingw) to compile .rc → .res
            let out_dir = std::env::var("OUT_DIR").unwrap();
            let res_path = format!("{}/app.res", out_dir);
            let status = std::process::Command::new("x86_64-w64-mingw32-windres")
                .args(&["res/app.rc", "-O", "coff", "-o", &res_path])
                .status();
            if let Ok(s) = status {
                if s.success() {
                    println!("cargo:rustc-link-arg={}", res_path);
                }
            }
        }
    }
}
