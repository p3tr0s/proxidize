//! Windows resources: the administrator manifest, the icon and version information.

fn main() {
    let target_windows = std::env::var("CARGO_CFG_TARGET_OS").map(|os| os == "windows").unwrap_or(false);
    // Resources need the Windows SDK's rc.exe; cross-checks from other hosts skip them.
    #[cfg(windows)]
    if target_windows {
        resources();
    }
    let _ = target_windows;
}

#[cfg(windows)]
fn resources() {
    {
        let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let ico = out.join("proxidize.ico");
        std::fs::write(&ico, icon()).expect("write icon");
        let manifest = out.join("proxidize.manifest");
        std::fs::write(&manifest, MANIFEST).expect("write manifest");
        let version = std::env::var("CARGO_PKG_VERSION").unwrap();
        let numeric: Vec<u64> = version.split(['.', '-']).take(3).map(|p| p.parse().unwrap_or(0)).collect();
        let packed = (numeric[0] << 48) | (numeric[1] << 32) | (numeric[2] << 16);
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico.to_str().unwrap())
            .set_manifest_file(manifest.to_str().unwrap())
            .set("ProductName", "Proxidize")
            .set("FileDescription", "Proxidize: per-program proxy redirection")
            .set("CompanyName", "Petros Aposporis")
            .set("LegalCopyright", "MIT License")
            .set("OriginalFilename", "proxidize.exe")
            .set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed)
            .set_version_info(winresource::VersionInfo::FILEVERSION, packed);
        res.compile().expect("Windows resources");
    }
}

#[cfg(windows)]
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Proxidize" version="1.0.0.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
</assembly>
"#;

/// A multi-size .ico (32-bit BMP images): the green link light on the dark rack.
#[cfg(windows)]
fn icon() -> Vec<u8> {
    let sizes = [16u32, 24, 32, 48, 64, 256];
    let images: Vec<Vec<u8>> = sizes.iter().map(|&s| bmp(s)).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (s, img) in sizes.iter().zip(&images) {
        let dim = if *s >= 256 { 0 } else { *s as u8 };
        out.extend_from_slice(&[dim, dim, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images {
        out.extend_from_slice(&img);
    }
    out
}

#[cfg(windows)]
fn bmp(size: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(size as i32).to_le_bytes());
    out.extend_from_slice(&((size * 2) as i32).to_le_bytes()); // XOR + AND masks
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 24]);
    let f = |v: f32| (v * size as f32) as u32;
    for y in (0..size).rev() {
        for x in 0..size {
            let rack = x >= f(0.06) && x < f(0.94) && y >= f(0.06) && y < f(0.94);
            let light = x >= f(0.34) && x < f(0.66) && y >= f(0.34) && y < f(0.66);
            let px: [u8; 4] = if light {
                [0x8A, 0xC3, 0x4C, 255]
            } else if rack {
                [0x1B, 0x19, 0x19, 255]
            } else {
                [0, 0, 0, 0]
            };
            out.extend_from_slice(&px);
        }
    }
    let row = size.div_ceil(32) * 4;
    out.extend(std::iter::repeat_n(0u8, (row * size) as usize));
    out
}
