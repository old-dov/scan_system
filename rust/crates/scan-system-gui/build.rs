fn main() {
    let icon = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../pictures/scan_system.ico")
        .canonicalize()
        .expect("Scan System Windows icon exists");
    println!("cargo:rerun-if-changed={}", icon.display());
    if cfg!(target_os = "windows") {
        winres::WindowsResource::new()
            .set_icon(icon.to_str().expect("Windows icon path is UTF-8"))
            .compile()
            .expect("could not embed the Scan System Windows icon");
    }
}
