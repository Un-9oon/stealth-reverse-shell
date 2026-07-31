fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winresource::WindowsResource::new();
        res.set("FileDescription", "Windows Update Agent");
        res.set("ProductName", "Microsoft Windows");
        res.set("CompanyName", "Microsoft Corporation");
        res.set("LegalCopyright", "\u{00a9} Microsoft Corporation. All rights reserved.");
        res.set("FileVersion", "10.0.26100.1");
        res.set("ProductVersion", "10.0.26100.1");
        res.set("OriginalFilename", "WUAgent.exe");
        res.set("InternalName", "WUAgent");
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Version resource failed: {e}");
        }
    }
}
