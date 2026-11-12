//! Embeds WinDivert (DLL + signed driver) when it has been downloaded (scripts/get-windivert.ps1), so the exe
//! carries everything it needs. `PROXIDIZE_WINDIVERT_DIR` overrides where to look.

use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(windivert_embedded)");
    println!("cargo::rerun-if-env-changed=PROXIDIZE_WINDIVERT_DIR");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dir = std::env::var("PROXIDIZE_WINDIVERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("../../third_party/WinDivert/x64"));
    let dll = dir.join("WinDivert.dll");
    let sys = dir.join("WinDivert64.sys");
    println!("cargo::rerun-if-changed={}", dll.display());
    println!("cargo::rerun-if-changed={}", sys.display());
    let windows = std::env::var("CARGO_CFG_TARGET_OS").map(|os| os == "windows").unwrap_or(false);
    if windows && dll.is_file() && sys.is_file() {
        println!("cargo::rustc-cfg=windivert_embedded");
        println!("cargo::rustc-env=PROXIDIZE_WINDIVERT_DLL={}", dll.canonicalize().unwrap().display());
        println!("cargo::rustc-env=PROXIDIZE_WINDIVERT_SYS={}", sys.canonicalize().unwrap().display());
    } else if windows {
        println!("cargo::warning=WinDivert not found in {}: the exe will look for WinDivert.dll next to itself. Run scripts/get-windivert.ps1 to embed it.", dir.display());
    }
}
