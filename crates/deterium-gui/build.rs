//! Gives `Deterium.exe` its icon and version information (what Explorer, the
//! desktop and the taskbar show for the file). The icon is `assets/deterium.ico`,
//! rendered from the logo code by `cargo run -p deterium-gui --example make_icons`.
//!
//! If Windows' resource compiler isn't available the build still succeeds; the
//! program just has the default icon.

fn main() {
    println!("cargo:rerun-if-changed=assets/deterium.ico");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.2.0".into());

    let mut resources = winresource::WindowsResource::new();
    resources
        .set_icon("assets/deterium.ico")
        .set("ProductName", "Deterium VPN")
        .set("FileDescription", "Deterium VPN - self-hosted VPN client")
        .set("InternalName", "Deterium")
        .set("OriginalFilename", "Deterium.exe")
        .set("CompanyName", "Deterium contributors")
        .set("LegalCopyright", "Deterium contributors")
        .set("ProductVersion", &version)
        .set("FileVersion", &version);
    if let Err(error) = resources.compile() {
        println!("cargo:warning=couldn't embed the icon and version info: {error}");
    }
}
