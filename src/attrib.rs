//! Which process owns a connection: Windows IP Helper tables + name lookup.
//!
//! The TCP/UDP owner tables are polled fast (the sightings thread runs
//! every 150 ms) and cached by (proto, local port) — ports are the
//! practical join key between a captured packet and a process. IPv6 rows
//! are matched the same way. Processes that were resolved successfully
//! at least once are remembered in a census (10 min), so even after a
//! short-lived process exits, its still-lingering connection rows can be
//! answered with the name that was caught while it was alive.

use crate::model::Proto;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    /// The path was inferred (service table / well-known system
    /// location), not read from the process itself.
    pub path_estimate: bool,
    /// Process creation time (Windows FILETIME as u64), when it could be
    /// read. Two different processes can reuse one PID over time; the
    /// creation time is what tells them apart in the census below.
    pub created: Option<u64>,
}

/// True for the placeholder produced when a process could not be
/// resolved at all (it had usually already exited).
fn is_unresolved(p: &ProcInfo) -> bool {
    p.path.is_empty() && p.name.starts_with("pid ")
}

/// One live connection row from the OS tables (used by table mode, where
/// no packet capture is available: endpoints and owner, no byte counts).
#[derive(Debug, Clone)]
pub struct ConnRow {
    pub proto: Proto,
    pub local_ip: std::net::IpAddr,
    pub local_port: u16,
    pub remote_ip: std::net::IpAddr,
    pub remote_port: u16,
    pub proc: ProcInfo,
}

pub trait Resolver {
    /// Refresh the internal tables (cheap enough to call every few seconds).
    fn refresh(&mut self);
    fn lookup(
        &self,
        proto: Proto,
        local_port: u16,
        remote_ip: std::net::IpAddr,
        remote_port: u16,
    ) -> Option<ProcInfo>;
}

#[derive(Default)]
pub struct TableResolver {
    /// Current snapshot: (IP protocol 6=TCP / 17=UDP, local port) -> process.
    by_port: HashMap<(u8, u16), ProcInfo>,
    /// Every exact (proto, local port, remote ip, remote port) tuple seen
    /// in recent refreshes, with when it was last seen. This is what lets
    /// short-lived connections be attributed AFTER they close: the table
    /// only needs to have caught them once while they were alive.
    history: HashMap<(u8, u16, std::net::IpAddr, u16), (ProcInfo, std::time::SystemTime)>,
    /// Most recent owner per (proto, local port), for flows whose exact
    /// tuple was never recorded (e.g. UDP endpoints without a remote).
    port_history: HashMap<(u8, u16), (ProcInfo, std::time::SystemTime)>,
    proc_cache: HashMap<u32, (ProcInfo, std::time::SystemTime)>,
    /// Census of processes resolved successfully at least once, by PID.
    /// Short-lived processes are usually gone by the time their (still
    /// lingering, e.g. TIME_WAIT) connection rows are examined; if any
    /// earlier poll caught the process alive, its name is remembered
    /// here for a while and can still answer for the dead PID. Entries
    /// carry the process creation time so a recycled PID belonging to a
    /// different process is never answered with the old name.
    census: HashMap<u32, (ProcInfo, std::time::SystemTime)>,
    /// Windows only: PID -> binary path from the service control manager.
    /// Many service processes refuse OpenProcess (protected), but their
    /// binary path is public configuration data in the SCM.
    service_paths: HashMap<u32, String>,
    service_paths_at: Option<std::time::SystemTime>,
}

impl TableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    fn proc(&mut self, pid: u32) -> ProcInfo {
        if let Some((p, at)) = self.proc_cache.get(&pid) {
            // Failed resolutions ("pid N" with no path) are retried after
            // a while instead of being cached forever: the process may
            // simply not have been queryable at that moment.
            let failed = is_unresolved(p);
            if !failed
                || at.elapsed().map(|d| d.as_secs() < 10).unwrap_or(false)
            {
                let p = p.clone();
                if !failed {
                    // Keep the census entry fresh while the process is
                    // being seen, so it stays answerable right after the
                    // process exits.
                    self.note_census(&p);
                }
                return p;
            }
        }
        let mut info = query_process(pid);
        if info.path.is_empty() {
            // Protected processes often reveal their binary path only
            // through the service table.
            #[cfg(windows)]
            {
                self.ensure_service_paths();
                if let Some(p) = self.service_paths.get(&pid) {
                    info.path = p.clone();
                }
            }
        }
        if is_unresolved(&info) {
            // The process itself is gone — but an earlier poll may have
            // caught it alive. Answer from the census if it is fresh and
            // belongs to this same process instance.
            if let Some(known) = self.census_info(pid, &info) {
                info = known;
            }
        } else {
            self.note_census(&info);
        }
        self.proc_cache
            .insert(pid, (info.clone(), std::time::SystemTime::now()));
        info
    }

    /// Remember a successfully resolved process in the census.
    fn note_census(&mut self, info: &ProcInfo) {
        if is_unresolved(info) || info.pid == 0 {
            return;
        }
        if let Some((old, _)) = self.census.get(&info.pid) {
            match (old.created, info.created) {
                // Same PID, different creation time: the PID was
                // recycled — the new process replaces the old entry.
                (Some(a), Some(b)) if a != b => {}
                // Same process: keep the more complete record (the one
                // that has a path) rather than downgrading it.
                _ if old.path.is_empty() || !info.path.is_empty() => {}
                _ => return,
            }
        }
        self.census
            .insert(info.pid, (info.clone(), std::time::SystemTime::now()));
    }

    /// The census answer for a PID whose live query just failed, if the
    /// entry is fresh (< 10 min, matching the history retention) and not
    /// contradicted by a creation time. A creation time can only be
    /// present on `failed` in synthetic cases — a dead process yields
    /// none — so in practice freshness decides.
    fn census_info(&self, pid: u32, failed: &ProcInfo) -> Option<ProcInfo> {
        let (known, at) = self.census.get(&pid)?;
        if at.elapsed().map(|d| d.as_secs() >= 600).unwrap_or(true) {
            return None;
        }
        if let (Some(a), Some(b)) = (known.created, failed.created) {
            if a != b {
                return None;
            }
        }
        Some(known.clone())
    }

    /// (Re)build the SCM pid->path map at most every 30 s (Windows).
    #[cfg(windows)]
    fn ensure_service_paths(&mut self) {
        let stale = self
            .service_paths_at
            .map(|t| t.elapsed().map(|d| d.as_secs() > 30).unwrap_or(true))
            .unwrap_or(true);
        if stale {
            self.service_paths = unsafe { win_tables::service_paths() };
            self.service_paths_at = Some(std::time::SystemTime::now());
        }
    }

    /// Start a refresh cycle: the live port map is rebuilt, history is
    /// kept (and pruned to the last 10 minutes / 20k entries).
    pub fn begin_refresh(&mut self) {
        self.by_port.clear();
        let now = std::time::SystemTime::now();
        self.history.retain(|_, (_, at)| {
            now.duration_since(*at).map(|d| d.as_secs() < 600).unwrap_or(true)
        });
        self.port_history.retain(|_, (_, at)| {
            now.duration_since(*at).map(|d| d.as_secs() < 600).unwrap_or(true)
        });
        self.census.retain(|_, (_, at)| {
            now.duration_since(*at).map(|d| d.as_secs() < 600).unwrap_or(true)
        });
        if self.history.len() > 20_000 {
            self.history.clear();
        }
        if self.census.len() > 20_000 {
            self.census.clear();
        }
    }

    /// Record one full connection row (with remote endpoint).
    pub fn ingest_row(
        &mut self,
        proto: Proto,
        local_port: u16,
        remote_ip: std::net::IpAddr,
        remote_port: u16,
        proc: ProcInfo,
    ) {
        let tag = match proto {
            Proto::Tcp => 6u8,
            Proto::Udp => 17u8,
            _ => return,
        };
        let now = std::time::SystemTime::now();
        self.by_port.insert((tag, local_port), proc.clone());
        self.port_history.insert((tag, local_port), (proc.clone(), now));
        if remote_port != 0 {
            self.history
                .insert((tag, local_port, remote_ip, remote_port), (proc, now));
        }
    }

    /// Record a port-only ownership (UDP tables have no remote endpoint).
    pub fn ingest_port(&mut self, proto: Proto, local_port: u16, proc: ProcInfo) {
        let tag = match proto {
            Proto::Tcp => 6u8,
            Proto::Udp => 17u8,
            _ => return,
        };
        let now = std::time::SystemTime::now();
        self.by_port.insert((tag, local_port), proc.clone());
        self.port_history.insert((tag, local_port), (proc, now));
    }
}

impl TableResolver {
    /// Snapshot of current TCP connections (IPv4) with owners, for table
    /// mode. UDP has no remote endpoint in the owner table, so UDP rows
    /// are reported through `by_port` lookups only.
    pub fn connections(&mut self) -> Vec<ConnRow> {
        #[cfg(windows)]
        unsafe {
            win_tables::connections(self)
        }
        #[cfg(target_os = "linux")]
        {
            linux_tables::connections(self)
        }
        #[cfg(target_os = "macos")]
        {
            mac_tables::connections(self)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Vec::new()
        }
    }
}

impl Resolver for TableResolver {
    fn refresh(&mut self) {
        self.begin_refresh();
        #[cfg(windows)]
        unsafe {
            win_tables::fill(self);
        }
        #[cfg(target_os = "linux")]
        linux_tables::fill(self);
        #[cfg(target_os = "macos")]
        mac_tables::fill(self);
    }

    fn lookup(
        &self,
        proto: Proto,
        local_port: u16,
        remote_ip: std::net::IpAddr,
        remote_port: u16,
    ) -> Option<ProcInfo> {
        let tag = match proto {
            Proto::Tcp => 6u8,
            Proto::Udp => 17u8,
            _ => return None, // the OS owner tables only cover TCP/UDP
        };
        // 1) exact tuple from history (works after the connection closed)
        if let Some((p, _)) = self.history.get(&(tag, local_port, remote_ip, remote_port)) {
            return Some(p.clone());
        }
        // 2) current owner of the local port
        if let Some(p) = self.by_port.get(&(tag, local_port)) {
            return Some(p.clone());
        }
        // 3) most recent owner of the local port
        if let Some((p, _)) = self.port_history.get(&(tag, local_port)) {
            return Some(p.clone());
        }
        None
    }
}

#[cfg(windows)]
fn query_process(pid: u32) -> ProcInfo {
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_VM_READ,
    };
    // Kernel pseudo-processes have stable names; querying them fails.
    if pid == 0 {
        return ProcInfo { pid, name: "System Idle Process".into(), path: String::new(), path_estimate: false, created: None };
    }
    if pid == 4 {
        return ProcInfo { pid, name: "System".into(), path: String::new(), path_estimate: false, created: None };
    }
    unsafe {
        let mut path = String::new();
        let mut created: Option<u64> = None;
        // 1) Limited-information query (works for most processes).
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if !h.is_null() {
            // Creation time identifies this process instance even if the
            // PID is later recycled (used by the resolver's census).
            let mut c: windows_sys::Win32::Foundation::FILETIME = std::mem::zeroed();
            let mut x: windows_sys::Win32::Foundation::FILETIME = std::mem::zeroed();
            let mut k: windows_sys::Win32::Foundation::FILETIME = std::mem::zeroed();
            let mut u: windows_sys::Win32::Foundation::FILETIME = std::mem::zeroed();
            if GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) != 0 {
                created = Some(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64);
            }
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            if QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0 {
                path = String::from_utf16_lossy(&buf[..len as usize]);
            }
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
        // 2) PSAPI module path with broader rights.
        if path.is_empty() {
            let h2 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if !h2.is_null() {
                let mut buf = vec![0u16; 1024];
                let n = windows_sys::Win32::System::ProcessStatus::GetModuleFileNameExW(
                    h2,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                );
                if n > 0 {
                    path = String::from_utf16_lossy(&buf[..n as usize]);
                }
                windows_sys::Win32::Foundation::CloseHandle(h2);
            }
        }
        if !path.is_empty() {
            let name = path.rsplit(['\\', '/']).next().unwrap_or("?").to_string();
            return ProcInfo { pid, name, path, path_estimate: false, created };
        }
        // 3) Toolhelp snapshot: at least the image name (svchost.exe …),
        // which succeeds for many protected/service processes.
        if let Some(name) = snapshot_name(pid) {
            // Core OS binaries live at a fixed System32 location; fill it
            // in as an ESTIMATE (flagged as such) rather than leaving the
            // path blank. Only names whose genuine instances are
            // protected system processes are listed.
            const SYSTEM32_KNOWN: &[&str] = &[
                "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
                "conhost.exe", "fontdrvhost.exe", "dllhost.exe",
                "wudfhost.exe", "runtimebroker.exe", "searchindexer.exe",
                "spoolsv.exe", "audiodg.exe", "dashost.exe", "sihost.exe",
                "taskhostw.exe", "ctfmon.exe", "searchprotocolhost.exe",
                "searchfilterhost.exe", "wmiprvse.exe", "lsaiso.exe",
            ];
            if SYSTEM32_KNOWN.iter().any(|k| k.eq_ignore_ascii_case(&name)) {
                let root = std::env::var("SystemRoot")
                    .unwrap_or_else(|_| "C:\\Windows".to_string());
                let path = format!("{root}\\System32\\{}", name.to_lowercase());
                return ProcInfo { pid, name, path, path_estimate: true, created };
            }
            return ProcInfo { pid, name, path: String::new(), path_estimate: false, created };
        }
        ProcInfo { pid, name: format!("pid {pid}"), path: String::new(), path_estimate: false, created: None }
    }
}

/// Image name for a PID from a Toolhelp process snapshot.
#[cfg(windows)]
unsafe fn snapshot_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap.is_null() {
        return None;
    }
    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut found = None;
    if Process32FirstW(snap, &mut entry) != 0 {
        loop {
            if entry.th32ProcessID == pid {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                found = Some(String::from_utf16_lossy(&entry.szExeFile[..end]));
                break;
            }
            if Process32NextW(snap, &mut entry) == 0 {
                break;
            }
        }
    }
    CloseHandle(snap);
    found
}

#[cfg(target_os = "linux")]
fn query_process(pid: u32) -> ProcInfo {
    let mut path = String::new();
    if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        path = p.to_string_lossy().trim_end_matches(" (deleted)").to_string();
    }
    let name = if path.is_empty() {
        // Fall back to the command name in /proc/<pid>/stat.
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                let a = s.find('(')?;
                let b = s.rfind(')')?;
                Some(s[a + 1..b].to_string())
            })
            .unwrap_or_else(|| format!("pid {pid}"))
    } else {
        path.rsplit('/').next().unwrap_or("?").to_string()
    };
    ProcInfo { pid, name, path, path_estimate: false, created: None }
}

#[cfg(target_os = "macos")]
fn query_process(pid: u32) -> ProcInfo {
    // libproc's proc_pidpath: a single stable FFI call, no headers needed.
    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
    }
    let mut path = String::new();
    unsafe {
        let mut buf = vec![0u8; 4096];
        let n = proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut _, buf.len() as u32);
        if n > 0 {
            path = String::from_utf8_lossy(&buf[..n as usize]).to_string();
        }
    }
    let name = if path.is_empty() {
        format!("pid {pid}")
    } else {
        path.rsplit('/').next().unwrap_or("?").to_string()
    };
    ProcInfo { pid, name, path, path_estimate: false, created: None }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn query_process(pid: u32) -> ProcInfo {
    ProcInfo { pid, name: format!("pid {pid}"), path: String::new(), path_estimate: false, created: None }
}

#[cfg(windows)]
mod win_tables {
    use super::*;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    pub struct TcpRowRaw {
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        pid: u32,
    }

    fn port_of(raw: u32) -> u16 {
        u16::from_be((raw & 0xffff) as u16)
    }

    /// All TCP rows (IPv4 + IPv6) with owners.
    pub unsafe fn enum_tcp() -> Vec<TcpRowRaw> {
        let mut out = Vec::new();
        // ---- IPv4 ----
        let mut size: u32 = 0;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(buf.as_mut_ptr() as *mut c_void, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
                let rs = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                for i in 0..count {
                    let off = 4 + i * rs;
                    if off + rs > buf.len() { break; }
                    let row = *(buf.as_ptr().add(off) as *const MIB_TCPROW_OWNER_PID);
                    if row.dwOwningPid == 0 { continue; }
                    out.push(TcpRowRaw {
                        // Address fields hold octets in address order in
                        // memory (the v1 to_be_bytes display bug came from
                        // reading them the other way round).
                        local_ip: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_le_bytes())),
                        local_port: port_of(row.dwLocalPort),
                        remote_ip: IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_le_bytes())),
                        remote_port: port_of(row.dwRemotePort),
                        pid: row.dwOwningPid,
                    });
                }
            }
        }
        // ---- IPv6 ----
        let mut size: u32 = 0;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(buf.as_mut_ptr() as *mut c_void, &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
                let rs = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
                for i in 0..count {
                    let off = 4 + i * rs;
                    if off + rs > buf.len() { break; }
                    let row = *(buf.as_ptr().add(off) as *const MIB_TCP6ROW_OWNER_PID);
                    if row.dwOwningPid == 0 { continue; }
                    out.push(TcpRowRaw {
                        local_ip: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                        local_port: port_of(row.dwLocalPort),
                        remote_ip: IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                        remote_port: port_of(row.dwRemotePort),
                        pid: row.dwOwningPid,
                    });
                }
            }
        }
        out
    }

    /// (local port, pid) pairs from the UDP owner tables, both families.
    pub unsafe fn enum_udp_ports() -> Vec<(u16, u32)> {
        let mut out = Vec::new();
        for family in [AF_INET as u32, AF_INET6 as u32] {
            let mut size: u32 = 0;
            GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, family, UDP_TABLE_OWNER_PID, 0);
            if size == 0 { continue; }
            let mut buf = vec![0u8; size as usize];
            if GetExtendedUdpTable(buf.as_mut_ptr() as *mut c_void, &mut size, 0, family, UDP_TABLE_OWNER_PID, 0) != 0 {
                continue;
            }
            let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            if family == AF_INET as u32 {
                let rs = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                for i in 0..count {
                    let off = 4 + i * rs;
                    if off + rs > buf.len() { break; }
                    let row = *(buf.as_ptr().add(off) as *const MIB_UDPROW_OWNER_PID);
                    if row.dwOwningPid != 0 {
                        out.push((port_of(row.dwLocalPort), row.dwOwningPid));
                    }
                }
            } else {
                let rs = std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();
                for i in 0..count {
                    let off = 4 + i * rs;
                    if off + rs > buf.len() { break; }
                    let row = *(buf.as_ptr().add(off) as *const MIB_UDP6ROW_OWNER_PID);
                    if row.dwOwningPid != 0 {
                        out.push((port_of(row.dwLocalPort), row.dwOwningPid));
                    }
                }
            }
        }
        out
    }

    pub unsafe fn fill(r: &mut TableResolver) {
        for row in enum_tcp() {
            let info = r.proc(row.pid);
            r.ingest_row(Proto::Tcp, row.local_port, row.remote_ip, row.remote_port, info);
        }
        for (port, pid) in enum_udp_ports() {
            let info = r.proc(pid);
            r.ingest_port(Proto::Udp, port, info);
        }
    }

    pub unsafe fn connections(r: &mut TableResolver) -> Vec<ConnRow> {
        enum_tcp()
            .into_iter()
            .filter(|x| x.remote_port != 0)
            .map(|x| ConnRow {
                proto: Proto::Tcp,
                local_ip: x.local_ip,
                local_port: x.local_port,
                remote_ip: x.remote_ip,
                remote_port: x.remote_port,
                proc: r.proc(x.pid),
            })
            .collect()
    }

    /// PID -> binary path for every Windows service, from the SCM.
    /// Protected service processes (Defender, indexing, spooler…)
    /// refuse OpenProcess, but their configured binary path is public.
    pub unsafe fn service_paths() -> HashMap<u32, String> {
        use windows_sys::Win32::System::Services::{
            CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
            QueryServiceConfigW, ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW,
            SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG,
            SERVICE_STATE_ALL, SERVICE_WIN32,
        };
        let mut map = HashMap::new();
        let mgr = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if mgr.is_null() {
            return map;
        }
        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let mut resume: u32 = 0;
        EnumServicesStatusExW(
            mgr,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            std::ptr::null_mut(),
            0,
            &mut needed,
            &mut count,
            &mut resume,
            std::ptr::null(),
        );
        if needed > 0 {
            let mut buf = vec![0u8; needed as usize];
            let ok = EnumServicesStatusExW(
                mgr,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf.as_mut_ptr(),
                needed,
                &mut needed,
                &mut count,
                &mut resume,
                std::ptr::null(),
            );
            if ok != 0 {
                let rs = std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
                for i in 0..count as usize {
                    let off = i * rs;
                    if off + rs > buf.len() {
                        break;
                    }
                    let entry = &*(buf.as_ptr().add(off) as *const ENUM_SERVICE_STATUS_PROCESSW);
                    let pid = entry.ServiceStatusProcess.dwProcessId;
                    if pid == 0 || entry.lpServiceName.is_null() {
                        continue;
                    }
                    let svc = OpenServiceW(mgr, entry.lpServiceName, SERVICE_QUERY_CONFIG);
                    if svc.is_null() {
                        continue;
                    }
                    let mut need2: u32 = 0;
                    QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut need2);
                    if need2 > 0 {
                        let mut buf2 = vec![0u8; need2 as usize];
                        if QueryServiceConfigW(
                            svc,
                            buf2.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
                            need2,
                            &mut need2,
                        ) != 0
                        {
                            let cfg = &*(buf2.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                            if !cfg.lpBinaryPathName.is_null() {
                                let mut len = 0usize;
                                while *cfg.lpBinaryPathName.add(len) != 0 {
                                    len += 1;
                                }
                                let raw = String::from_utf16_lossy(
                                    std::slice::from_raw_parts(cfg.lpBinaryPathName, len),
                                );
                                if let Some(p) = normalize_service_path(&raw) {
                                    map.insert(pid, p);
                                }
                            }
                        }
                    }
                    CloseServiceHandle(svc);
                }
            }
        }
        CloseServiceHandle(mgr);
        map
    }

    /// "C:\Windows\system32\svchost.exe -k netsvcs" -> the exe path,
    /// with %SystemRoot% etc. expanded and \SystemRoot\ resolved.
    fn normalize_service_path(raw: &str) -> Option<String> {
        let s = raw.trim();
        let core = if let Some(rest) = s.strip_prefix('"') {
            rest.split('"').next()?.to_string()
        } else {
            let lower = s.to_lowercase();
            let pos = lower.find(".exe")?;
            s[..pos + 4].to_string()
        };
        let mut out = core;
        for var in ["SystemRoot", "windir", "ProgramFiles", "ProgramData", "SystemDrive"] {
            if let Ok(val) = std::env::var(var) {
                out = out.replace(&format!("%{var}%"), &val);
            }
        }
        // NT-style prefixes used in service ImagePath values:
        // "\SystemRoot\system32\..." and "\??\C:\...".
        let lower = out.to_lowercase();
        for prefix in ["\\systemroot\\", "\\\\systemroot\\"] {
            if lower.starts_with(prefix) {
                let root =
                    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
                let rest = &out[prefix.len()..];
                out = format!("{root}\\{rest}");
                break;
            }
        }
        if let Some(rest) = out.strip_prefix("\\??\\") {
            out = rest.to_string();
        }
        if out.to_lowercase().ends_with(".exe") {
            Some(out)
        } else {
            None
        }
    }
}


/// Linux: /proc/net/{tcp,tcp6,udp,udp6} socket tables joined to PIDs by
/// scanning /proc/<pid>/fd for socket inodes.
#[cfg(target_os = "linux")]
mod linux_tables {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub struct RawRow {
        proto: Proto,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        pid: u32,
    }

    fn hex_ip(s: &str, v6: bool) -> Option<IpAddr> {
        if v6 {
            if s.len() != 32 {
                return None;
            }
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let v = u32::from_str_radix(&s[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        } else {
            let v = u32::from_str_radix(s, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(v.to_le_bytes())))
        }
    }

    fn endpoint(s: &str, v6: bool) -> Option<(IpAddr, u16)> {
        let (ip, port) = s.rsplit_once(':')?;
        Some((hex_ip(ip, v6)?, u16::from_str_radix(port, 16).ok()?))
    }

    fn inode_map() -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        let Ok(procs) = std::fs::read_dir("/proc") else {
            return map;
        };
        for entry in procs.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    let t = target.to_string_lossy();
                    if let Some(inode) = t
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        map.insert(inode, pid);
                    }
                }
            }
        }
        map
    }

    fn rows() -> Vec<RawRow> {
        let inodes = inode_map();
        let mut out = Vec::new();
        for (file, proto, v6) in [
            ("tcp", Proto::Tcp, false),
            ("tcp6", Proto::Tcp, true),
            ("udp", Proto::Udp, false),
            ("udp6", Proto::Udp, true),
        ] {
            let Ok(text) = std::fs::read_to_string(format!("/proc/net/{file}")) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 {
                    continue;
                }
                let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
                    (endpoint(f[1], v6), endpoint(f[2], v6))
                else {
                    continue;
                };
                let Ok(inode) = f[9].parse::<u64>() else {
                    continue;
                };
                let Some(&pid) = inodes.get(&inode) else {
                    continue;
                };
                out.push(RawRow {
                    proto,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    pid,
                });
            }
        }
        out
    }

    pub fn fill(r: &mut TableResolver) {
        for row in rows() {
            let info = r.proc(row.pid);
            r.ingest_row(row.proto, row.local_port, row.remote_ip, row.remote_port, info);
        }
    }

    pub fn connections(r: &mut TableResolver) -> Vec<ConnRow> {
        rows()
            .into_iter()
            .filter(|x| x.remote_port != 0)
            .map(|x| ConnRow {
                proto: x.proto,
                local_ip: x.local_ip,
                local_port: x.local_port,
                remote_ip: x.remote_ip,
                remote_port: x.remote_port,
                proc: r.proc(x.pid),
            })
            .collect()
    }
}


/// macOS: `lsof` field output joined with proc_pidpath for exe paths.
/// (macOS has no /proc; lsof ships with the OS.)
#[cfg(target_os = "macos")]
mod mac_tables {
    use super::*;
    use std::net::IpAddr;

    pub struct RawRow {
        proto: Proto,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        pid: u32,
    }

    fn endpoint(s: &str) -> Option<(IpAddr, u16)> {
        if let Some(rest) = s.strip_prefix('[') {
            let (ip, port) = rest.split_once("]:")?;
            Some((ip.parse().ok()?, port.parse().ok()?))
        } else {
            let (ip, port) = s.rsplit_once(':')?;
            let ip = if ip == "*" {
                "0.0.0.0".parse().unwrap()
            } else {
                ip.parse().ok()?
            };
            Some((ip, port.parse().ok()?))
        }
    }

    fn rows() -> Vec<RawRow> {
        let Ok(out) = std::process::Command::new("lsof")
            .args(["-nP", "-F", "pPcn", "-iTCP", "-iUDP"])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut rows = Vec::new();
        let mut pid: Option<u32> = None;
        let mut proto: Option<Proto> = None;
        for line in text.lines() {
            let (tag, val) = line.split_at(1.min(line.len()));
            match tag {
                "p" => {
                    pid = val.parse().ok();
                    proto = None;
                }
                "P" => {
                    proto = match val {
                        "TCP" => Some(Proto::Tcp),
                        "UDP" => Some(Proto::Udp),
                        _ => None,
                    };
                }
                "n" => {
                    let (Some(p), Some(pr)) = (pid, proto) else {
                        continue;
                    };
                    let (local, remote) = match val.split_once("->") {
                        Some((l, r)) => (l, Some(r)),
                        None => (val, None),
                    };
                    let Some((local_ip, local_port)) = endpoint(local) else {
                        continue;
                    };
                    let (remote_ip, remote_port) = remote
                        .and_then(endpoint)
                        .unwrap_or((local_ip, 0));
                    rows.push(RawRow {
                        proto: pr,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        pid: p,
                    });
                }
                _ => {}
            }
        }
        rows
    }

    pub fn fill(r: &mut TableResolver) {
        for row in rows() {
            let info = r.proc(row.pid);
            r.ingest_row(row.proto, row.local_port, row.remote_ip, row.remote_port, info);
        }
    }

    pub fn connections(r: &mut TableResolver) -> Vec<ConnRow> {
        rows()
            .into_iter()
            .filter(|x| x.remote_port != 0)
            .map(|x| ConnRow {
                proto: x.proto,
                local_ip: x.local_ip,
                local_port: x.local_port,
                remote_ip: x.remote_ip,
                remote_port: x.remote_port,
                proc: r.proc(x.pid),
            })
            .collect()
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn named(pid: u32, name: &str, created: Option<u64>) -> ProcInfo {
        ProcInfo {
            pid,
            name: name.to_string(),
            path: format!("C:\\Apps\\{name}"),
            path_estimate: false,
            created,
        }
    }

    fn failed(pid: u32) -> ProcInfo {
        ProcInfo {
            pid,
            name: format!("pid {pid}"),
            path: String::new(),
            path_estimate: false,
            created: None,
        }
    }

    #[test]
    fn census_answers_for_a_dead_pid_it_saw_alive() {
        let mut r = TableResolver::new();
        r.note_census(&named(4242, "helper.exe", Some(111)));
        let got = r.census_info(4242, &failed(4242)).expect("census hit");
        assert_eq!(got.name, "helper.exe");
        assert_eq!(got.path, "C:\\Apps\\helper.exe");
    }

    #[test]
    fn census_miss_for_unknown_pid() {
        let r = TableResolver::new();
        assert!(r.census_info(9999, &failed(9999)).is_none());
    }

    #[test]
    fn census_entry_is_replaced_when_pid_is_recycled() {
        let mut r = TableResolver::new();
        r.note_census(&named(4242, "old.exe", Some(111)));
        r.note_census(&named(4242, "new.exe", Some(222)));
        let got = r.census_info(4242, &failed(4242)).expect("census hit");
        assert_eq!(got.name, "new.exe");
        // A stale query result carrying the OLD creation time must not be
        // answered with the new process's name.
        let mut stale = failed(4242);
        stale.created = Some(111);
        assert!(r.census_info(4242, &stale).is_none());
    }

    #[test]
    fn unresolved_results_are_never_remembered() {
        let mut r = TableResolver::new();
        r.note_census(&failed(4242));
        assert!(r.census_info(4242, &failed(4242)).is_none());
    }
}
