//! Running programs, for the rule editor's picker: (file name, full path), one entry per path.

pub fn running() -> Vec<(String, String)> {
    let mut list = list();
    list.sort_by_key(|(name, path)| (name.to_lowercase(), path.to_lowercase()));
    list.dedup_by(|a, b| a.1.eq_ignore_ascii_case(&b.1));
    list
}

#[cfg(windows)]
fn list() -> Vec<(String, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    let mut out = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snapshot, &mut entry);
        while ok != 0 {
            if entry.th32ProcessID > 4 {
                if let Some(path) = proxidize_win::win::process_path(entry.th32ProcessID) {
                    let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
                    out.push((name, path));
                }
            }
            ok = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    out
}

#[cfg(not(windows))]
fn list() -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc") {
        for entry in dir.flatten() {
            if let Ok(path) = std::fs::read_link(entry.path().join("exe")) {
                let path = path.display().to_string();
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                out.push((name, path));
            }
        }
    }
    out
}
