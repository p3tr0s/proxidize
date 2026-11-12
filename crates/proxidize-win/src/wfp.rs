//! The kill switch on the Windows Filtering Platform (fwpuclnt.dll).

use std::sync::Mutex;

use proxidize_core::log::LogHub;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::killswitch::Filters;

const PROVIDER_KEY: GUID = GUID::from_u128(0x8f3c2a10_5d4e_4b7a_9c61_2e7d5a0b9f01);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x8f3c2a10_5d4e_4b7a_9c61_2e7d5a0b9f02);
const BLOCK_WEIGHT: u8 = 8;
const PERMIT_WEIGHT: u8 = 15;
const LAYERS: [GUID; 2] = [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn describe(code: u32) -> String {
    match code {
        0 => "OK".into(),
        5 => "access denied (run as Administrator)".into(),
        2 => "file not found".into(),
        3 => "path not found".into(),
        0x80320009 => "already exists".into(),
        0x8032000A => "in use".into(),
        other => format!("0x{other:08X}"),
    }
}

fn check(status: u32, what: &str) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("WFP: {what} failed ({}).", describe(status)))
    }
}

/// An open filtering engine session, closed on drop.
struct Engine(HANDLE);

impl Engine {
    fn open(dynamic: bool) -> Result<Engine, String> {
        let session = FWPM_SESSION0 {
            flags: if dynamic { FWPM_SESSION_FLAG_DYNAMIC } else { 0 },
            txnWaitTimeoutInMSec: 5000,
            ..Default::default()
        };
        let mut handle: HANDLE = std::ptr::null_mut();
        let status = unsafe { FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut handle) };
        check(status, "open filtering engine")?;
        Ok(Engine(handle))
    }

    fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}

fn ensure_provider_and_sublayer(engine: &Engine) -> Result<(), String> {
    let mut provider_name = wide("Proxidize");
    let mut sublayer_name = wide("Proxidize kill switch");
    let mut provider_key = PROVIDER_KEY;
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 { name: provider_name.as_mut_ptr(), description: std::ptr::null_mut() },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        ..Default::default()
    };
    let status = unsafe { FwpmProviderAdd0(engine.0, &provider, std::ptr::null_mut()) };
    if status != 0 && status != FWP_E_ALREADY_EXISTS as u32 {
        check(status, "add provider")?;
    }
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 { name: sublayer_name.as_mut_ptr(), description: std::ptr::null_mut() },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        weight: 0x0100,
        ..Default::default()
    };
    let status = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, std::ptr::null_mut()) };
    if status != 0 && status != FWP_E_ALREADY_EXISTS as u32 {
        check(status, "add sublayer")?;
    }
    Ok(())
}

fn new_filter(layer: GUID, name: *mut u16, action: u32, weight: u8, provider: Option<*mut GUID>) -> FWPM_FILTER0 {
    let mut filter = FWPM_FILTER0 {
        filterKey: GUID::from_u128(uuid::Uuid::new_v4().as_u128()),
        displayData: FWPM_DISPLAY_DATA0 { name, description: std::ptr::null_mut() },
        flags: if provider.is_some() { FWPM_FILTER_FLAG_PERSISTENT } else { 0 },
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        ..Default::default()
    };
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = weight;
    filter.action.r#type = action;
    if let Some(p) = provider {
        filter.providerKey = p;
    }
    filter
}

/// Deletes every persistent filter registered under our provider. Returns how many.
fn delete_our_filters(engine: &Engine) -> usize {
    let mut provider_key = PROVIDER_KEY;
    let mut keys: Vec<GUID> = Vec::new();
    for layer in LAYERS {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider_key,
            layerKey: layer,
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            actionMask: 0xFFFF_FFFF,
            ..Default::default()
        };
        let mut enum_handle: HANDLE = std::ptr::null_mut();
        if unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut enum_handle) } != 0 {
            continue;
        }
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count = 0u32;
            let status = unsafe { FwpmFilterEnum0(engine.0, enum_handle, 64, &mut entries, &mut count) };
            if status != 0 || count == 0 {
                if !entries.is_null() {
                    unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void) };
                }
                break;
            }
            for i in 0..count as usize {
                let filter = unsafe { &**entries.add(i) };
                if !filter.providerKey.is_null() && guid_eq(unsafe { &*filter.providerKey }, &PROVIDER_KEY) {
                    keys.push(filter.filterKey);
                }
            }
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void) };
        }
        unsafe { FwpmFilterDestroyEnumHandle0(engine.0, enum_handle) };
    }
    for key in &keys {
        unsafe { FwpmFilterDeleteByKey0(engine.0, key) };
    }
    keys.len()
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// Deletes every Proxidize WFP object (recovery: `proxidize.exe --remove-killswitch`).
pub fn remove_everything() -> Result<usize, String> {
    let engine = Engine::open(false)?;
    let removed = delete_our_filters(&engine);
    unsafe {
        FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER_KEY);
        FwpmProviderDeleteByKey0(engine.0, &PROVIDER_KEY);
    }
    Ok(removed)
}

#[derive(Default)]
pub struct WfpFilters {
    /// The dynamic session that carries the running override.
    running: Mutex<Option<usize>>,
}

impl Filters for WfpFilters {
    fn apply_blocks(&self, paths: &[String], log: &LogHub) -> Result<Vec<String>, String> {
        let engine = Engine::open(false)?;
        // Outside the transaction: "already exists" results must not affect it.
        ensure_provider_and_sublayer(&engine)?;
        check(unsafe { FwpmTransactionBegin0(engine.0, 0) }, "begin transaction")?;
        let result = (|| {
            delete_our_filters(&engine);
            let mut applied = Vec::new();
            let mut provider_key = PROVIDER_KEY;
            for path in paths {
                let file = wide(path);
                let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                let status = unsafe { FwpmGetAppIdFromFileName0(file.as_ptr(), &mut app_id) };
                if status != 0 {
                    log.warning(format!(
                        "Kill switch: '{path}' skipped ({}). It is protected once it exists and Proxidize re-syncs.",
                        describe(status)
                    ));
                    continue;
                }
                let mut name = wide(&format!("Proxidize kill switch: {path}"));
                let mut condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    ..Default::default()
                };
                condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                condition.conditionValue.Anonymous.byteBlob = app_id;
                let mut outcome = Ok(());
                for layer in LAYERS {
                    let mut filter =
                        new_filter(layer, name.as_mut_ptr(), FWP_ACTION_BLOCK, BLOCK_WEIGHT, Some(&mut provider_key));
                    filter.numFilterConditions = 1;
                    filter.filterCondition = &mut condition;
                    let mut id = 0u64;
                    outcome = check(
                        unsafe { FwpmFilterAdd0(engine.0, &filter, std::ptr::null_mut(), &mut id) },
                        &format!("add block for {path}"),
                    );
                    if outcome.is_err() {
                        break;
                    }
                }
                unsafe { FwpmFreeMemory0(&mut app_id as *mut _ as *mut *mut core::ffi::c_void) };
                outcome?;
                applied.push(path.clone());
            }
            check(unsafe { FwpmTransactionCommit0(engine.0) }, "commit")?;
            Ok(applied)
        })();
        if result.is_err() {
            unsafe { FwpmTransactionAbort0(engine.0) };
        }
        result
    }

    fn remove_blocks(&self, remove_objects: bool) -> Result<usize, String> {
        let engine = Engine::open(false)?;
        let removed = delete_our_filters(&engine);
        if remove_objects {
            unsafe {
                FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER_KEY);
                FwpmProviderDeleteByKey0(engine.0, &PROVIDER_KEY);
            }
        }
        Ok(removed)
    }

    fn allow_while_running(&self) -> Result<(), String> {
        let mut running = self.running.lock().unwrap();
        if running.is_some() {
            return Ok(());
        }
        // Persistent objects can't be created from a dynamic session: make sure they exist first.
        ensure_provider_and_sublayer(&Engine::open(false)?)?;
        let engine = Engine::open(true)?;
        let mut name = wide("Proxidize running: redirected programs may connect");
        for layer in LAYERS {
            let filter = new_filter(layer, name.as_mut_ptr(), FWP_ACTION_PERMIT, PERMIT_WEIGHT, None);
            let mut id = 0u64;
            check(unsafe { FwpmFilterAdd0(engine.0, &filter, std::ptr::null_mut(), &mut id) }, "add running permit")?;
        }
        *running = Some(engine.into_raw() as usize);
        Ok(())
    }

    fn revoke(&self) {
        if let Some(handle) = self.running.lock().unwrap().take() {
            unsafe { FwpmEngineClose0(handle as HANDLE) }; // dynamic session: its filters go with it
        }
    }

    fn is_allowing(&self) -> bool {
        self.running.lock().unwrap().is_some()
    }
}
