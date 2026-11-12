//! Installing an update: the verified exe replaces the running one (Windows lets a running exe be renamed), a new
//! instance starts and waits for this one to exit, then removes the old file.

use std::path::{Path, PathBuf};
use std::time::Duration;

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Puts `exe` in place of the running program, keeping the old one as `<exe>.old` until the next start.
pub fn install(exe: &[u8]) -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|e| format!("Couldn't find the running program: {e}"))?;
    let staged = sibling(&current, ".new");
    let old = sibling(&current, ".old");
    std::fs::write(&staged, exe).map_err(|e| format!("Couldn't save the update next to {}: {e}", current.display()))?;
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(&current, &old) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!("Couldn't replace {}: {e}", current.display()));
    }
    if let Err(e) = std::fs::rename(&staged, &current) {
        let _ = std::fs::rename(&old, &current); // put the running version back
        let _ = std::fs::remove_file(&staged);
        return Err(format!("Couldn't replace {}: {e}", current.display()));
    }
    Ok(current)
}

/// Starts the installed version. It waits for this process to exit before taking over.
pub fn restart(exe: &Path, start_redirecting: bool) -> Result<(), String> {
    let mut args = vec!["--after-update".to_string(), std::process::id().to_string()];
    if start_redirecting {
        args.push("--start".into());
    }
    match std::process::Command::new(exe).args(&args).spawn() {
        Ok(_) => Ok(()),
        #[cfg(windows)]
        Err(e) if e.raw_os_error() == Some(740) => run_elevated(exe, &args.join(" ")), // ERROR_ELEVATION_REQUIRED
        Err(e) => Err(format!("Couldn't start the new version: {e}")),
    }
}

#[cfg(windows)]
fn run_elevated(exe: &Path, args: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (verb, file, params) = (wide("runas".as_ref()), wide(exe.as_os_str()), wide(args.as_ref()));
    let result = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), params.as_ptr(), std::ptr::null(), SW_SHOWNORMAL)
    };
    if result as usize > 32 {
        Ok(())
    } else {
        Err("Couldn't start the new version (elevation was refused).".into())
    }
}

/// In the new instance: waits (up to `timeout`) for the previous one to exit.
#[cfg(windows)]
pub fn wait_for_exit(pid: u32, timeout: Duration) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return; // already gone
    }
    unsafe {
        WaitForSingleObject(handle, timeout.as_millis().min(u32::MAX as u128) as u32);
        CloseHandle(handle);
    }
}

#[cfg(not(windows))]
pub fn wait_for_exit(_pid: u32, timeout: Duration) {
    std::thread::sleep(timeout.min(Duration::from_millis(500)));
}

/// Removes what the last update left behind. Retries briefly: the old process may take a moment to release its file.
pub fn clean_up() {
    let Ok(current) = std::env::current_exe() else { return };
    let _ = std::fs::remove_file(sibling(&current, ".new"));
    let old = sibling(&current, ".old");
    for _ in 0..20 {
        if !old.exists() || std::fs::remove_file(&old).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_names() {
        assert_eq!(sibling(Path::new(r"F:\Tools\proxidize.exe"), ".old"), PathBuf::from(r"F:\Tools\proxidize.exe.old"));
    }
}
