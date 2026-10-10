//! Embeds the official OpenVPN Windows binaries into the program, when they
//! have been fetched with `tools/fetch-openvpn.ps1`. Without them the build
//! still succeeds, and the app falls back to an OpenVPN installed on the PC.

use std::path::Path;
use std::{env, fs};

/// Relative to `assets/openvpn/`. Keep in sync with tools/fetch-openvpn.ps1.
const FILES: &[&str] = &[
    "bin/openvpn.exe",
    "bin/libcrypto-3-x64.dll",
    "bin/libssl-3-x64.dll",
    "bin/libpkcs11-helper-1.dll",
    "bin/vcruntime140.dll",
    "ssl/modules/legacy.dll",
    "license.txt",
];

fn main() {
    println!("cargo:rerun-if-changed=assets/openvpn");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(bundled_openvpn)");

    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("bundled_files.rs");
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let dir = Path::new(&manifest).join("assets").join("openvpn");
    let windows = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let x64 = env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|a| a == "x86_64");
    let complete = FILES.iter().all(|f| dir.join(f).is_file());

    if !(windows && x64 && complete) {
        if windows && x64 {
            println!(
                "cargo:warning=OpenVPN is not bundled (run tools/fetch-openvpn.ps1 first); \
                 the app will need OpenVPN installed separately."
            );
        }
        fs::write(
            &out,
            "pub const FILES: &[(&str, &[u8])] = &[];\npub const VERSION: &str = \"\";\n",
        )
        .unwrap();
        return;
    }

    println!("cargo:rustc-cfg=bundled_openvpn");
    let version = fs::read_to_string(dir.join("VERSION")).unwrap_or_default();
    let mut code = String::from("pub const FILES: &[(&str, &[u8])] = &[\n");
    for file in FILES {
        let path = dir.join(file);
        code.push_str(&format!(
            "    ({file:?}, include_bytes!({:?})),\n",
            path.to_string_lossy()
        ));
    }
    code.push_str("];\n");
    code.push_str(&format!(
        "pub const VERSION: &str = {:?};\n",
        version.trim()
    ));
    fs::write(&out, code).unwrap();
}
