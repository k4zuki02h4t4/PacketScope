//! ETW process-start feed (Windows only).
//!
//! Connection-table polling has a floor: however fast it runs, a
//! process that starts, connects and exits inside one interval (SSH
//! askpass helpers are the classic example — they live for tens of
//! milliseconds) is only ever seen as a bare PID on its lingering
//! TIME_WAIT rows. The kernel process provider instead reports every
//! process start as it happens, with the image name, regardless of how
//! short the process lives. This module runs the NT Kernel Logger
//! session with EVENT_TRACE_FLAG_PROCESS and forwards starts to the
//! engine, which keeps them in a [`ProcFeed`] and can still answer
//! "what was PID N called?" after the process is long gone.
//!
//! If the session cannot be started (not elevated, or another tool is
//! mid-trace), the feed simply stays empty and attribution falls back
//! to polling + the resolver census, exactly as before.

use std::time::{Duration, SystemTime};

/// One process-start observation.
#[derive(Debug, Clone)]
pub struct ProcStart {
    pub pid: u32,
    pub parent_pid: u32,
    /// Image file name only (e.g. `askpass.exe`) — the kernel event
    /// carries no full path. A live process still gets its path from
    /// the resolver; this name is what survives the process's death.
    pub name: String,
    pub started: SystemTime,
}

/// How long a start record stays usable for attribution.
const FEED_WINDOW_SECS: u64 = 900;
/// Tolerance for event-vs-capture clock disagreement. Kept tight: a
/// process must start before it can connect, so a start later than
/// the connection itself can only be a recycled PID's new owner.
const FEED_SLACK_SECS: u64 = 1;
const FEED_CAP: usize = 60_000;

/// Time-windowed store of process starts. Answers "what was PID P
/// called around time T?", picking the process *instance* that was
/// alive then — PIDs get recycled, so the start time is the join key.
#[derive(Debug, Default)]
pub struct ProcFeed {
    starts: Vec<ProcStart>,
}

impl ProcFeed {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, p: ProcStart) {
        let now = p.started;
        self.starts.push(p);
        // Retain generously (twice the query window): name_for applies
        // the exact window for the queried moment, and a record must
        // not be evicted just because a newer process started since.
        self.starts.retain(|s| {
            now.duration_since(s.started)
                .map(|d| d.as_secs() <= FEED_WINDOW_SECS * 2)
                .unwrap_or(true)
        });
        if self.starts.len() > FEED_CAP {
            let excess = self.starts.len() - FEED_CAP;
            self.starts.drain(..excess);
        }
    }

    /// The latest start of `pid` no later than `at` (plus a small
    /// slack), provided it began within the feed window before `at`.
    pub fn name_for(&self, pid: u32, at: SystemTime) -> Option<ProcStart> {
        self.starts
            .iter()
            .filter(|s| s.pid == pid)
            .filter(|s| {
                // started <= at + slack
                s.started.duration_since(at).map(|d| d.as_secs() <= FEED_SLACK_SECS).unwrap_or(true)
            })
            .filter(|s| {
                // at - started <= window
                at.duration_since(s.started)
                    .map(|d| d.as_secs() <= FEED_WINDOW_SECS)
                    .unwrap_or(true)
            })
            .max_by_key(|s| s.started)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }
}

/// Start the ETW feed thread (Windows). No-op elsewhere, and silently
/// gives up on Windows when the kernel logger session is unavailable.
pub fn spawn(tx: std::sync::mpsc::SyncSender<crate::engine::EngineEvent>) {
    #[cfg(windows)]
    imp::spawn(tx);
    #[cfg(not(windows))]
    let _ = tx;
}

/// Stop a kernel-logger session started by [`spawn`]. Called from
/// main() after the UI exits; consume-only sessions (started by
/// someone else) are left alone.
pub fn shutdown() {
    #[cfg(windows)]
    imp::shutdown();
}

#[cfg(windows)]
mod imp {
    use super::ProcStart;
    use crate::engine::EngineEvent;
    use std::ffi::c_void;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::SyncSender;
    use std::time::{Duration, SystemTime};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW,
        CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
        EVENT_TRACE_CONTROL_STOP,
        EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
        EVENT_TRACE_SYSTEM_LOGGER_MODE, PROCESSTRACE_HANDLE,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        WNODE_FLAG_TRACED_GUID,
    };

    const SESSION_NAME: &str = "NT Kernel Logger";
    /// SystemTraceControlGuid — required as the session guid for the
    /// NT Kernel Logger.
    const SYSTEM_TRACE_CONTROL_GUID: GUID = GUID::from_u128(0x68fdd900_4a3e_11d1_84f4_0000f80464e3);
    /// Microsoft-Windows-Kernel-Process (manifest provider).
    const KERNEL_PROCESS_GUID: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
    /// Classic "Process" MOF class guid, as delivered by the kernel
    /// logger session.
    const CLASSIC_PROCESS_GUID: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);

    // ------------------------------------------------------------ diag log
    // The ETW path is exercised only on a real Windows machine, so it
    // leaves a breadcrumb file: %LOCALAPPDATA%\PacketScope\etw.log,
    // truncated at each launch. Session start codes, the first events
    // seen, and parse outcomes are recorded (budget-capped).

    static LOG_CB: AtomicUsize = AtomicUsize::new(0);
    static LOG_SEND: AtomicUsize = AtomicUsize::new(0);
    static LOG_FAIL: AtomicUsize = AtomicUsize::new(0);
    /// Set by shutdown(): the consumer loop must not run its
    /// stop-and-recreate recovery once the app is on its way out —
    /// a ProcessTrace 4201 racing the shutdown stop could otherwise
    /// resurrect the session during teardown (audit 2026-11-08).
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    fn log_path() -> std::path::PathBuf {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("PacketScope");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("etw.log")
    }

    /// True when the log path itself is a symlink / reparse point.
    /// This process runs elevated; appending to (or truncating) a
    /// planted link would redirect the write outside the data
    /// directory (audit 2026-11-08).
    fn log_path_is_link(p: &std::path::Path) -> bool {
        let Ok(md) = std::fs::symlink_metadata(p) else {
            return false;
        };
        let mut link = md.file_type().is_symlink();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            link = link || (md.file_attributes() & 0x0000_0400 != 0);
        }
        link
    }

    fn dlog(msg: &str) {
        let path = log_path();
        if log_path_is_link(&path) {
            let _ = std::fs::remove_file(&path);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{msg}");
        }
    }

    fn dlog_reset() {
        let path = log_path();
        if log_path_is_link(&path) {
            let _ = std::fs::remove_file(&path);
        }
        let _ = std::fs::write(
            &path,
            format!("PacketScope v{} ETW diagnostics\n", env!("CARGO_PKG_VERSION")),
        );
    }

    fn budget(counter: &AtomicUsize, max: usize) -> bool {
        counter.fetch_add(1, Ordering::Relaxed) < max
    }

    fn fmt_guid(g: &GUID) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            g.data1, g.data2, g.data3, g.data4[0], g.data4[1], g.data4[2],
            g.data4[3], g.data4[4], g.data4[5], g.data4[6], g.data4[7]
        )
    }

    fn guid_eq(a: &GUID, b: &GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    struct Session {
        handle: CONTROLTRACE_HANDLE,
        ours: bool,
    }

    static SESSION: std::sync::Mutex<Option<Session>> = std::sync::Mutex::new(None);

    pub fn spawn(tx: SyncSender<EngineEvent>) {
        std::thread::spawn(move || run(tx));
    }

    pub fn shutdown() {
        STOP_REQUESTED.store(true, Ordering::Relaxed);
        let session = SESSION.lock().ok().and_then(|mut g| g.take());
        if let Some(s) = session {
            if s.ours {
                unsafe {
                    let name_w: Vec<u16> =
                        SESSION_NAME.encode_utf16().chain(std::iter::once(0)).collect();
                    let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
                    let mut buf = props_buffer(total);
                    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
                    (*props).Wnode.BufferSize = total as u32;
                    (*props).LoggerNameOffset =
                        std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                    let tail = (buf.as_mut_ptr() as *mut u8)
                        .add(std::mem::size_of::<EVENT_TRACE_PROPERTIES>())
                        as *mut u16;
                    std::ptr::copy_nonoverlapping(name_w.as_ptr(), tail, name_w.len());
                    let rc = ControlTraceW(s.handle, name_w.as_ptr(), props, EVENT_TRACE_CONTROL_STOP);
                    dlog(&format!("shutdown: ControlTrace STOP rc={rc}"));
                }
            }
        }
    }

    /// Backing store for an EVENT_TRACE_PROPERTIES blob, allocated
    /// with the alignment the struct requires. A plain Vec<u8> only
    /// guarantees 1-byte alignment, so casting its pointer to the
    /// struct type was formally undefined behavior even though the
    /// allocator has always returned well-aligned blocks in practice
    /// (audit 2026-11-08). A Vec<u64> guarantees 8-byte alignment.
    fn props_buffer(total: usize) -> Vec<u64> {
        vec![0u64; total.div_ceil(8)]
    }

    /// LogFileMode of the session currently owning the kernel logger
    /// name, when it can be queried.
    unsafe fn session_logfile_mode(name_w: &[u16]) -> Option<u32> {
        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut buf = props_buffer(total);
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = total as u32;
        let rc = ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name_w.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        );
        if rc == ERROR_SUCCESS {
            Some((*props).LogFileMode)
        } else {
            None
        }
    }

    /// Whether the named session is one we may stop: it must be a
    /// real-time session that exists but cannot be consumed — the
    /// signature of a zombie left by an earlier crashed run of this
    /// app (which only ever starts real-time sessions). A session in
    /// another mode belongs to a foreign tool (e.g. a file-mode
    /// trace) and is left alone (audit 2026-11-08).
    unsafe fn session_is_stoppable_zombie(name_w: &[u16]) -> bool {
        match session_logfile_mode(name_w) {
            Some(mode) => mode & EVENT_TRACE_REAL_TIME_MODE != 0,
            None => false,
        }
    }

    /// Stop whatever session currently owns the kernel logger name.
    /// Used to clear a zombie session (e.g. left behind by a crashed
    /// run) that reports ALREADY_EXISTS but cannot be consumed.
    unsafe fn stop_by_name(name_w: &[u16]) {
        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut buf = props_buffer(total);
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = total as u32;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let tail = (buf.as_mut_ptr() as *mut u8)
            .add(std::mem::size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16;
        std::ptr::copy_nonoverlapping(name_w.as_ptr(), tail, name_w.len());
        let rc = ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name_w.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
        dlog(&format!("ControlTrace STOP by name rc={rc}"));
        if let Ok(mut g) = SESSION.lock() {
            *g = None;
        }
    }

    unsafe fn start_session(name_w: &[u16], mode: u32) -> (u32, CONTROLTRACE_HANDLE) {
        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut buf = props_buffer(total);
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;
        (*props).Wnode.ClientContext = 1;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).BufferSize = 64; // KB per buffer
        (*props).MinimumBuffers = 8;
        (*props).MaximumBuffers = 64;
        (*props).LogFileMode = mode;
        (*props).EnableFlags = EVENT_TRACE_FLAG_PROCESS;
        (*props).FlushTimer = 1;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let tail = (buf.as_mut_ptr() as *mut u8)
            .add(std::mem::size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16;
        std::ptr::copy_nonoverlapping(name_w.as_ptr(), tail, name_w.len());
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let rc = StartTraceW(&mut handle, name_w.as_ptr(), props);
        (rc, handle)
    }

    fn run(tx: SyncSender<EngineEvent>) {
        dlog_reset();
        unsafe {
            let name_w: Vec<u16> =
                SESSION_NAME.encode_utf16().chain(std::iter::once(0)).collect();
            // ERROR_WMI_INSTANCE_NOT_FOUND: the named session cannot
            // be consumed — the signature of a zombie session (e.g.
            // v1.2.0's, whose stop call was malformed) or of one
            // started in an incompatible mode.
            const ERR_INSTANCE_NOT_FOUND: u32 = 4201;
            let modes: [(&str, u32); 2] = [
                ("realtime", EVENT_TRACE_REAL_TIME_MODE),
                (
                    "realtime+system_logger",
                    EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE,
                ),
            ];
            let mut mode_idx = 0usize;
            let mut cleaned = false;
            for attempt in 0..6 {
                let (label, mode) = modes[mode_idx];
                let (rc, handle) = start_session(&name_w, mode);
                dlog(&format!("attempt {attempt}: StartTrace mode={label} rc={rc}"));
                let ours = if rc == ERROR_SUCCESS {
                    if let Ok(mut g) = SESSION.lock() {
                        *g = Some(Session { handle, ours: true });
                    }
                    true
                } else if rc == ERROR_ALREADY_EXISTS {
                    // Another owner (a live foreign trace, or a zombie
                    // left by an earlier run). Try to consume it.
                    false
                } else if mode_idx + 1 < modes.len() {
                    mode_idx += 1;
                    continue;
                } else {
                    dlog("StartTrace failed in all modes; ETW feed disabled");
                    return;
                };

                // --- consumer ---
                let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
                logfile.LoggerName = name_w.as_ptr() as *mut u16;
                logfile.Anonymous1.ProcessTraceMode =
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                logfile.Anonymous2.EventRecordCallback = Some(record_cb);
                logfile.Context = Box::into_raw(Box::new(tx.clone())) as *mut c_void;

                let trace: PROCESSTRACE_HANDLE = OpenTraceW(&mut logfile);
                dlog(&format!("attempt {attempt}: OpenTrace handle={:#x}", trace.Value));
                if trace.Value == 0 || trace.Value == u64::MAX {
                    let _ = Box::from_raw(logfile.Context as *mut SyncSender<EngineEvent>);
                    if !cleaned
                        && !STOP_REQUESTED.load(Ordering::Relaxed)
                        && session_is_stoppable_zombie(&name_w)
                    {
                        // Unusable real-time session squatting on
                        // the name (a zombie left by an earlier run
                        // of this app): clear it and retry. A session
                        // in any other mode belongs to a foreign tool
                        // and is left alone.
                        stop_by_name(&name_w);
                        cleaned = true;
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    dlog("existing session cannot be consumed and is not a stoppable zombie; ETW feed disabled");
                    return;
                }
                // Blocks until the session is stopped (shutdown() at
                // app exit) or the trace is closed.
                let handles = [trace];
                let prc = ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
                dlog(&format!("attempt {attempt}: ProcessTrace returned rc={prc}"));
                CloseTrace(trace);
                let _ = Box::from_raw(logfile.Context as *mut SyncSender<EngineEvent>);
                if prc == ERR_INSTANCE_NOT_FOUND
                    && !cleaned
                    && !STOP_REQUESTED.load(Ordering::Relaxed)
                    && session_is_stoppable_zombie(&name_w)
                {
                    // The session exists on paper but cannot be
                    // consumed (zombie / incompatible mode) — and it
                    // is a real-time session, i.e. one of ours. Stop
                    // it by name and retry, switching mode when we
                    // owned the broken one ourselves.
                    stop_by_name(&name_w);
                    cleaned = true;
                    if ours && mode_idx + 1 < modes.len() {
                        mode_idx += 1;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
                break;
            }
        }
    }

    unsafe extern "system" fn record_cb(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        let rec = &*record;
        let header = &rec.EventHeader;
        let provider = header.ProviderId;
        let opcode = header.EventDescriptor.Opcode;
        let is_process = guid_eq(&provider, &KERNEL_PROCESS_GUID)
            || guid_eq(&provider, &CLASSIC_PROCESS_GUID);
        if budget(&LOG_CB, 40) {
            dlog(&format!(
                "cb provider={} opcode={} id={} process_provider={}",
                fmt_guid(&provider),
                opcode,
                header.EventDescriptor.Id,
                is_process
            ));
        }
        if !is_process {
            return;
        }
        // 1 = start, 3 = DC start (processes already running when the
        // session began — equally useful for naming).
        if opcode != 1 && opcode != 3 {
            return;
        }
        match parse_process_start(rec) {
            Ok(start) => {
                if budget(&LOG_SEND, 100) {
                    dlog(&format!(
                        "start pid={} parent={} name={}",
                        start.pid, start.parent_pid, start.name
                    ));
                }
                let tx = &*(rec.UserContext as *const SyncSender<EngineEvent>);
                // Never block the ETW callback: if the engine's queue
                // is full, dropping one start record is acceptable.
                let _ = tx.try_send(EngineEvent::ProcStart(start));
            }
            Err(why) => {
                if budget(&LOG_FAIL, 40) {
                    dlog(&format!("parse failed: {why}"));
                }
            }
        }
    }

    /// Extract (ProcessId, ParentId, ImageFileName) from an event via
    /// TDH, which understands both the classic MOF and the manifest
    /// form of the process events across Windows versions. Errors are
    /// described for the diagnostics log.
    unsafe fn parse_process_start(rec: &EVENT_RECORD) -> Result<ProcStart, String> {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
            EVENT_PROPERTY_INFO, PROPERTY_DATA_DESCRIPTOR, TRACE_EVENT_INFO,
        };
        let mut info_size: u32 = 0;
        let rc = TdhGetEventInformation(rec, 0, std::ptr::null(), std::ptr::null_mut(), &mut info_size);
        if rc != 122 || info_size == 0 {
            return Err(format!("TdhGetEventInformation(size) rc={rc} size={info_size}"));
        }
        let mut info_buf = vec![0u8; info_size as usize];
        let info = info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
        let rc2 = TdhGetEventInformation(rec, 0, std::ptr::null(), info, &mut info_size);
        if rc2 != 0 {
            return Err(format!("TdhGetEventInformation rc={rc2}"));
        }
        let info_ref = &*info;
        let base = info_buf.as_ptr() as usize;
        let count = info_ref.TopLevelPropertyCount as usize;
        let props = (base + std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray))
            as *const EVENT_PROPERTY_INFO;

        let mut pid: Option<u32> = None;
        let mut parent: u32 = 0;
        let mut name: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        for i in 0..count {
            let pinfo = &*props.add(i);
            if pinfo.NameOffset == 0 {
                continue;
            }
            let name_ptr = (base + pinfo.NameOffset as usize) as *const u16;
            let pname = wide_to_string(name_ptr);
            seen.push(pname.clone());
            let want = matches!(pname.as_str(), "ProcessId" | "ParentId" | "ImageFileName");
            if !want {
                continue;
            }
            let desc = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: name_ptr as u64,
                ArrayIndex: u32::MAX,
                Reserved: 0,
            };
            let mut vsize: u32 = 0;
            if TdhGetPropertySize(rec, 0, std::ptr::null(), 1, &desc, &mut vsize) != 0
                || vsize == 0
            {
                continue;
            }
            let mut vbuf = vec![0u8; vsize as usize];
            if TdhGetProperty(rec, 0, std::ptr::null(), 1, &desc, vsize, vbuf.as_mut_ptr()) != 0 {
                continue;
            }
            match pname.as_str() {
                "ProcessId" if vbuf.len() >= 4 => {
                    pid = Some(u32::from_le_bytes(vbuf[0..4].try_into().unwrap()));
                }
                "ParentId" if vbuf.len() >= 4 => {
                    parent = u32::from_le_bytes(vbuf[0..4].try_into().unwrap());
                }
                "ImageFileName" => {
                    name = Some(decode_string(&vbuf));
                }
                _ => {}
            }
        }
        match (pid, name) {
            (Some(pid), Some(name)) if pid != 0 && !name.is_empty() => Ok(ProcStart {
                pid,
                parent_pid: parent,
                name,
                started: filetime_to_system_time(rec.EventHeader.TimeStamp),
            }),
            (p, n) => Err(format!(
                "missing fields pid={p:?} name_present={} props=[{}]",
                n.is_some(),
                seen.join(",")
            )),
        }
    }

    unsafe fn wide_to_string(ptr: *const u16) -> String {
        let mut len = 0usize;
        while *ptr.add(len) != 0 && len < 512 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }

    /// ImageFileName arrives as an ANSI string in the classic form and
    /// may be UTF-16 in the manifest form. Detect and decode.
    fn decode_string(buf: &[u8]) -> String {
        if buf.len() >= 4 && buf[1] == 0 && buf[3] == 0 {
            let units: Vec<u16> = buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            return String::from_utf16_lossy(&units);
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }

    fn filetime_to_system_time(ft: i64) -> SystemTime {
        const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
        // Clamp to ~200 years past the Unix epoch: the value comes
        // from the kernel, but an absurd one must not overflow the
        // nanos multiplication or the SystemTime addition and panic
        // (audit 2026-11-08).
        const MAX_TICKS: u64 = 63_072_000_000_000_000; // 200 y in 100 ns units
        if ft > EPOCH_DIFF_100NS {
            let ticks = ((ft - EPOCH_DIFF_100NS) as u64).min(MAX_TICKS);
            SystemTime::UNIX_EPOCH + Duration::from_nanos(ticks * 100)
        } else {
            SystemTime::now()
        }
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn start(pid: u32, name: &str, secs_after_epoch: u64) -> ProcStart {
        ProcStart {
            pid,
            parent_pid: 0,
            name: name.to_string(),
            started: SystemTime::UNIX_EPOCH + Duration::from_secs(secs_after_epoch),
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn feed_names_a_process_seen_at_its_connection_time() {
        let mut feed = ProcFeed::new();
        feed.push(start(100, "askpass.exe", 1_000));
        let got = feed.name_for(100, at(1_005)).expect("hit");
        assert_eq!(got.name, "askpass.exe");
    }

    #[test]
    fn recycled_pid_picks_the_instance_alive_then() {
        let mut feed = ProcFeed::new();
        feed.push(start(100, "old.exe", 1_000));
        feed.push(start(100, "new.exe", 2_000));
        // A connection at t=1500 belongs to old.exe's instance.
        assert_eq!(feed.name_for(100, at(1_500)).unwrap().name, "old.exe");
        // One at t=2500 belongs to new.exe's instance.
        assert_eq!(feed.name_for(100, at(2_500)).unwrap().name, "new.exe");
    }

    #[test]
    fn no_answer_before_the_process_started_or_after_the_window() {
        let mut feed = ProcFeed::new();
        feed.push(start(100, "app.exe", 2_000));
        assert!(feed.name_for(100, at(1_000)).is_none());
        assert!(feed.name_for(100, at(2_000 + FEED_WINDOW_SECS + 10)).is_none());
        assert!(feed.name_for(999, at(2_100)).is_none());
    }
}
