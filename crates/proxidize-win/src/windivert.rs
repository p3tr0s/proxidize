//! WinDivert, loaded at runtime. The DLL and the signed driver are embedded in the exe (see build.rs) and
//! extracted to `%ProgramData%\Proxidize\bin\WinDivert-<hash>`. That folder is locked down to SYSTEM and
//! Administrators before anything is loaded from it and every file is compared byte for byte with the embedded
//! copy, so a non-admin user can't plant a DLL that this elevated process would load.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH};

use crate::divert::{Address, Divert, DivertError, DivertOpener, Layer};

type OpenFn = unsafe extern "system" fn(*const u8, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> BOOL;
type SendFn = unsafe extern "system" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> BOOL;
type ShutdownFn = unsafe extern "system" fn(HANDLE, u32) -> BOOL;
type CloseFn = unsafe extern "system" fn(HANDLE) -> BOOL;
type SetParamFn = unsafe extern "system" fn(HANDLE, u32, u64) -> BOOL;
type ChecksumsFn = unsafe extern "system" fn(*mut c_void, u32, *mut Address, u64) -> BOOL;

struct Api {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    set_param: SetParamFn,
    checksums: ChecksumsFn,
}

static API: OnceLock<Result<Api, DivertError>> = OnceLock::new();

fn api() -> Result<&'static Api, DivertError> {
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn load() -> Result<Api, DivertError> {
    let dll = locate().map_err(|e| DivertError { code: 126, context: e })?;
    let path = wide(&dll.to_string_lossy());
    // LOAD_WITH_ALTERED_SEARCH_PATH: the DLL's own folder is searched for its dependencies, not the cwd.
    let module = unsafe { LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
    if module.is_null() {
        return Err(DivertError { code: unsafe { GetLastError() }, context: format!("loading {}", dll.display()) });
    }
    macro_rules! sym {
        ($name:literal, $ty:ty) => {{
            let f = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
            match f {
                Some(f) => unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f) },
                None => return Err(DivertError { code: 127, context: format!("{} missing from WinDivert.dll", $name) }),
            }
        }};
    }
    Ok(Api {
        open: sym!("WinDivertOpen", OpenFn),
        recv: sym!("WinDivertRecv", RecvFn),
        send: sym!("WinDivertSend", SendFn),
        shutdown: sym!("WinDivertShutdown", ShutdownFn),
        close: sym!("WinDivertClose", CloseFn),
        set_param: sym!("WinDivertSetParam", SetParamFn),
        checksums: sym!("WinDivertHelperCalcChecksums", ChecksumsFn),
    })
}

#[cfg(windivert_embedded)]
const EMBEDDED: Option<(&[u8], &[u8])> =
    Some((include_bytes!(env!("PROXIDIZE_WINDIVERT_DLL")), include_bytes!(env!("PROXIDIZE_WINDIVERT_SYS"))));

#[cfg(not(windivert_embedded))]
const EMBEDDED: Option<(&[u8], &[u8])> = None;

/// True when this build carries WinDivert inside the exe.
pub fn is_embedded() -> bool {
    EMBEDDED.is_some()
}

/// The WinDivert.dll to load: the embedded copy (extracted and verified), else one next to the exe.
fn locate() -> Result<PathBuf, String> {
    match EMBEDDED {
        Some((dll, sys)) => extract(dll, sys),
        None => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let dll = exe.with_file_name("WinDivert.dll");
            if dll.is_file() && exe.with_file_name("WinDivert64.sys").is_file() {
                Ok(dll)
            } else {
                Err("WinDivert.dll / WinDivert64.sys are not embedded in this build and not next to the exe".into())
            }
        }
    }
}

fn fnv1a(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for part in parts {
        for b in *part {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

fn extract(dll: &[u8], sys: &[u8]) -> Result<PathBuf, String> {
    let base = proxidize_core::config::ConfigStore::data_directory().join("bin");
    let dir = base.join(format!("WinDivert-{:016x}", fnv1a(&[dll, sys])));
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    lock_down(&base)?;
    lock_down(&dir)?;
    for (name, bytes) in [("WinDivert.dll", dll), ("WinDivert64.sys", sys)] {
        let path = dir.join(name);
        if path.exists() {
            lock_down(&path)?;
        }
        let same = std::fs::read(&path).map(|existing| existing == bytes).unwrap_or(false);
        if !same {
            let _ = std::fs::remove_file(&path);
            std::fs::write(&path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))?;
            lock_down(&path)?;
            let written = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            if written != bytes {
                return Err(format!("{} does not match the embedded copy", path.display()));
            }
        }
    }
    Ok(dir.join("WinDivert.dll"))
}

/// Owner Administrators; SYSTEM and Administrators full control, Users read and execute; no inherited entries.
fn lock_down(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    let sddl = wide("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
            == 0
        {
            return Err(format!("security descriptor: error {}", GetLastError()));
        }
        let mut owner = std::ptr::null_mut();
        let mut owner_defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut present = 0;
        let mut dacl_defaulted = 0;
        GetSecurityDescriptorOwner(sd, &mut owner, &mut owner_defaulted);
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut dacl_defaulted);
        let name = wide(&path.to_string_lossy());
        let status = SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        );
        LocalFree(sd as _);
        if status != 0 {
            return Err(format!("securing {}: error {status}", path.display()));
        }
    }
    Ok(())
}

pub struct WinDivertHandle {
    api: &'static Api,
    handle: usize,
    in_flight: AtomicUsize,
    closing: AtomicBool,
}

impl WinDivertHandle {
    fn raw(&self) -> HANDLE {
        self.handle as HANDLE
    }
}

impl Divert for WinDivertHandle {
    fn recv(&self, buffer: &mut [u8], address: &mut Address) -> Result<usize, u32> {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let result = if self.closing.load(Ordering::Acquire) {
            Err(6)
        } else {
            let mut len = 0u32;
            let ptr = if buffer.is_empty() { std::ptr::null_mut() } else { buffer.as_mut_ptr() as *mut c_void };
            let ok = unsafe { (self.api.recv)(self.raw(), ptr, buffer.len() as u32, &mut len, address) };
            if ok != 0 {
                Ok(len as usize)
            } else {
                Err(unsafe { GetLastError() })
            }
        };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        result
    }

    fn send(&self, packet: &[u8], address: &Address) -> bool {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let ok = !self.closing.load(Ordering::Acquire)
            && unsafe {
                (self.api.send)(self.raw(), packet.as_ptr() as *const c_void, packet.len() as u32, std::ptr::null_mut(), address)
                    != 0
            };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        ok
    }

    fn reinject(&self, packet: &mut [u8], address: &mut Address) -> bool {
        unsafe { (self.api.checksums)(packet.as_mut_ptr() as *mut c_void, packet.len() as u32, address, 0) };
        self.send(packet, address)
    }

    fn shutdown(&self) {
        unsafe { (self.api.shutdown)(self.raw(), 3) };
    }

    fn set_queue(&self, length: u64, size: u64) {
        unsafe {
            (self.api.set_param)(self.raw(), 0, length); // WINDIVERT_PARAM_QUEUE_LENGTH
            (self.api.set_param)(self.raw(), 2, size); // WINDIVERT_PARAM_QUEUE_SIZE
        }
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Release);
        unsafe { (self.api.shutdown)(self.raw(), 3) };
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.in_flight.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        unsafe { (self.api.close)(self.raw()) };
    }
}

pub struct WinDivertOpener;

impl DivertOpener for WinDivertOpener {
    fn open(&self, filter: &str, layer: Layer, priority: i16, flags: u64) -> Result<Arc<dyn Divert>, DivertError> {
        let api = api()?;
        let mut text = filter.as_bytes().to_vec();
        text.push(0);
        let handle = unsafe { (api.open)(text.as_ptr(), layer as u32, priority, flags) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(DivertError {
                code: unsafe { GetLastError() },
                context: format!("{layer:?} layer, filter \"{filter}\""),
            });
        }
        Ok(Arc::new(WinDivertHandle {
            api,
            handle: handle as usize,
            in_flight: AtomicUsize::new(0),
            closing: AtomicBool::new(false),
        }))
    }
}
