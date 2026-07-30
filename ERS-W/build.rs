fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let res_path = std::path::Path::new("res/app.res");
        if res_path.exists() {
            println!("cargo:rustc-link-arg={}", res_path.display());
        }
    }
}
