//! Windows integration: connection owner tables, process identity, DPAPI, Start with Windows, the firewall rule
//! for the relay, DNS cache flush and the adapters' DNS servers.

use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use proxidize_core::config::SecretProtector;
use proxidize_core::log::LogHub;
use proxidize_core::net::Ip;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, FILETIME};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetExtendedTcpTable, GetExtendedUdpTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::process::{SystemInfo, TcpRow, UdpRow};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STILL_ACTIVE: u32 = 259;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const MIB_TCP_STATE_LISTEN: u32 = 2;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ------------------------------------------------------------------------------------------------ tables

pub struct WindowsSystem;

/// The port is a DWORD whose first two bytes are the port in network order.
fn port(d: &[u8]) -> u16 {
    u16::from_be_bytes([d[0], d[1]])
}

fn le32(d: &[u8]) -> u32 {
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

fn read_table(tcp: bool, family: u32, mut reader: impl FnMut(&[u8], usize)) {
    let mut size: u32 = 64 * 1024;
    for _ in 0..5 {
        let mut buffer = vec![0u8; size as usize];
        let mut required = size;
        let status = unsafe {
            if tcp {
                GetExtendedTcpTable(buffer.as_mut_ptr() as *mut c_void, &mut required, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(buffer.as_mut_ptr() as *mut c_void, &mut required, 0, family, UDP_TABLE_OWNER_PID, 0)
            }
        };
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = size.max(required) + 16 * 1024;
            continue;
        }
        if status != 0 {
            return;
        }
        let row = match (tcp, family == AF_INET as u32) {
            (true, true) => 24,
            (true, false) => 56,
            (false, true) => 12,
            (false, false) => 28,
        };
        let count = (le32(&buffer) as usize).min((buffer.len() - 4) / row);
        reader(&buffer, count);
        return;
    }
}

impl SystemInfo for WindowsSystem {
    fn tcp_table(&self) -> Vec<TcpRow> {
        let mut rows = Vec::with_capacity(512);
        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (24 bytes)
        read_table(true, AF_INET as u32, |d, n| {
            for i in 0..n {
                let r = &d[4 + i * 24..4 + i * 24 + 24];
                rows.push(TcpRow {
                    local: Ip::from_slice_v4(&r[4..8]),
                    local_port: port(&r[8..]),
                    remote: Ip::from_slice_v4(&r[12..16]),
                    remote_port: port(&r[16..]),
                    pid: le32(&r[20..]),
                    listening: le32(r) == MIB_TCP_STATE_LISTEN,
                });
            }
        });
        // MIB_TCP6ROW_OWNER_PID: localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid (56)
        read_table(true, AF_INET6 as u32, |d, n| {
            for i in 0..n {
                let r = &d[4 + i * 56..4 + i * 56 + 56];
                rows.push(TcpRow {
                    local: Ip::from_slice_v6(&r[0..16]),
                    local_port: port(&r[20..]),
                    remote: Ip::from_slice_v6(&r[24..40]),
                    remote_port: port(&r[44..]),
                    pid: le32(&r[52..]),
                    listening: le32(&r[48..]) == MIB_TCP_STATE_LISTEN,
                });
            }
        });
        rows
    }

    fn udp_table(&self) -> Vec<UdpRow> {
        let mut rows = Vec::with_capacity(256);
        // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid (12 bytes)
        read_table(false, AF_INET as u32, |d, n| {
            for i in 0..n {
                let r = &d[4 + i * 12..4 + i * 12 + 12];
                rows.push(UdpRow { local: Ip::from_slice_v4(&r[0..4]), local_port: port(&r[4..]), pid: le32(&r[8..]) });
            }
        });
        // MIB_UDP6ROW_OWNER_PID: localAddr[16], scope, localPort, pid (28 bytes)
        read_table(false, AF_INET6 as u32, |d, n| {
            for i in 0..n {
                let r = &d[4 + i * 28..4 + i * 28 + 28];
                rows.push(UdpRow { local: Ip::from_slice_v6(&r[0..16]), local_port: port(&r[20..]), pid: le32(&r[24..]) });
            }
        });
        rows
    }

    fn identity(&self, pid: u32) -> Option<(Option<String>, u64)> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let result = (|| {
            let mut exit = 0u32;
            if unsafe { GetExitCodeProcess(handle, &mut exit) } != 0 && exit != STILL_ACTIVE {
                return None;
            }
            let mut times = [FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 }; 4];
            let [c, e, k, u] = &mut times;
            let created = if unsafe { GetProcessTimes(handle, c, e, k, u) } != 0 {
                ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64
            } else {
                0
            };
            let mut buffer = vec![0u16; 1024];
            let mut size = buffer.len() as u32;
            let path = if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) } != 0 {
                Some(String::from_utf16_lossy(&buffer[..size as usize]))
            } else {
                None
            };
            Some((path, created))
        })();
        unsafe { CloseHandle(handle) };
        result
    }
}

/// The image path of a running process (for the program picker).
pub fn process_path(pid: u32) -> Option<String> {
    WindowsSystem.identity(pid).and_then(|(p, _)| p)
}

// ------------------------------------------------------------------------------------------------ DNS

/// Drops the system DNS cache (stale fake answers after the engine stops). Best effort.
pub fn flush_dns_cache() {
    let name = wide("dnsapi.dll");
    unsafe {
        let module = LoadLibraryW(name.as_ptr());
        if module.is_null() {
            return;
        }
        if let Some(f) = GetProcAddress(module, c"DnsFlushResolverCache".as_ptr() as *const u8) {
            let flush: unsafe extern "system" fn() -> i32 = std::mem::transmute(f);
            flush();
        }
    }
}

/// DNS servers of the adapters that are up (loopback excluded).
pub fn adapter_dns_servers() -> Vec<Ip> {
    let mut size: u32 = 32 * 1024;
    for _ in 0..4 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let status = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), first, &mut size) };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status != 0 {
            return Vec::new();
        }
        let mut result = Vec::new();
        let mut adapter = first;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };
            if a.OperStatus == 1 && a.IfType != 24 {
                let mut dns = a.FirstDnsServerAddress;
                while !dns.is_null() {
                    let d = unsafe { &*dns };
                    if let Some(ip) = unsafe { sockaddr_ip(d.Address.lpSockaddr as *const c_void) } {
                        if !result.contains(&ip) {
                            result.push(ip);
                        }
                    }
                    dns = d.Next;
                }
            }
            adapter = a.Next;
        }
        return result;
    }
    Vec::new()
}

unsafe fn sockaddr_ip(p: *const c_void) -> Option<Ip> {
    if p.is_null() {
        return None;
    }
    let family = unsafe { *(p as *const u16) };
    if family == AF_INET {
        let v4 = unsafe { &*(p as *const SOCKADDR_IN) };
        Some(Ip::v4(unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes()))
    } else if family == AF_INET6 {
        let v6 = unsafe { &*(p as *const SOCKADDR_IN6) };
        Some(Ip::v6(unsafe { v6.sin6_addr.u.Byte }))
    } else {
        None
    }
}

// ------------------------------------------------------------------------------------------------ DPAPI

/// Proxy passwords on disk are encrypted with DPAPI for the current Windows user. Same prefix and entropy as
/// ProxyForge, so a ProxyForge config comes over with its passwords.
pub struct Dpapi;

const DPAPI_PREFIX: &str = "dpapi:";
const DPAPI_ENTROPY: &[u8] = b"ProxyForge proxy credentials v1";

fn dpapi(input: &[u8], protect: bool) -> Option<Vec<u8>> {
    let data_in = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_ptr() as *mut u8 };
    let entropy = CRYPT_INTEGER_BLOB { cbData: DPAPI_ENTROPY.len() as u32, pbData: DPAPI_ENTROPY.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &data_in,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &data_in,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };
    if ok == 0 || out.pbData.is_null() {
        return None;
    }
    let result = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe { LocalFree(out.pbData as _) };
    Some(result)
}

impl SecretProtector for Dpapi {
    fn protect(&self, plain: &str) -> String {
        use base64::Engine as _;
        match dpapi(plain.as_bytes(), true) {
            Some(bytes) => format!("{DPAPI_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(bytes)),
            None => plain.to_string(), // never lose a password; the config store warns about plain text
        }
    }

    fn unprotect(&self, value: &str) -> Option<String> {
        use base64::Engine as _;
        let encoded = value.strip_prefix(DPAPI_PREFIX)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
        String::from_utf8(dpapi(&bytes, false)?).ok()
    }
}

// ------------------------------------------------------------------------------------------------ processes

fn run(file: &str, args: &[&str]) -> (i32, String) {
    match Command::new(file).args(args).stdin(Stdio::null()).creation_flags(CREATE_NO_WINDOW).output() {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
        ),
        Err(e) => (-1, e.to_string()),
    }
}

/// An inbound allow rule for this exe on the relay port.
pub fn ensure_firewall_rule(port: u16, log: &LogHub) {
    const RULE: &str = "Proxidize Relay";
    let Ok(exe) = std::env::current_exe() else { return };
    let _ = run("netsh.exe", &["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}")]);
    let (code, _) = run(
        "netsh.exe",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={RULE}"),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
            &format!("program={}", exe.display()),
            "enable=yes",
            "profile=any",
        ],
    );
    if code != 0 {
        log.warning(format!(
            "Could not create the Windows Firewall rule (netsh exit code {code}). Redirected connections may be blocked."
        ));
    }
}

// ------------------------------------------------------------------------------------------------ autostart

pub const TASK_NAME: &str = "Proxidize";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

fn current_user() -> String {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();
    if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    }
}

/// Start at sign-in through a Task Scheduler task: elevated, no UAC prompt, no 72-hour limit.
pub fn sync_autostart(enabled: bool, log: &LogHub) {
    if enabled {
        let Ok(exe) = std::env::current_exe() else { return };
        let exe = exe.display().to_string();
        let dir = std::path::Path::new(&exe).parent().map(|p| p.display().to_string()).unwrap_or_default();
        let user = xml_escape(&current_user());
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts Proxidize minimized at sign-in.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{}</Command><Arguments>--minimized</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions>
</Task>"#,
            xml_escape(&exe),
            xml_escape(&dir)
        );
        let path = std::env::temp_dir().join(format!("proxidize-task-{}.xml", uuid::Uuid::new_v4().simple()));
        let bytes: Vec<u8> = [0xFF, 0xFE].into_iter().chain(xml.encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
        if let Err(e) = std::fs::write(&path, bytes) {
            log.warning(format!("Start with Windows: {e}"));
            return;
        }
        let (code, output) = run("schtasks.exe", &["/Create", "/TN", TASK_NAME, "/XML", &path.display().to_string(), "/F"]);
        let _ = std::fs::remove_file(&path);
        if code == 0 {
            log.info("Start with Windows: scheduled task created.");
        } else {
            log.warning(format!("Start with Windows: creating the scheduled task failed ({code}): {}", output.trim()));
        }
    } else if autostart_exists() {
        let (code, output) = run("schtasks.exe", &["/Delete", "/TN", TASK_NAME, "/F"]);
        if code == 0 {
            log.info("Start with Windows: scheduled task removed.");
        } else {
            log.warning(format!("Start with Windows: removing the scheduled task failed ({code}): {}", output.trim()));
        }
    }
}

pub fn autostart_exists() -> bool {
    run("schtasks.exe", &["/Query", "/TN", TASK_NAME]).0 == 0
}

/// True when the process runs elevated.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}
