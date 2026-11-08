//! Flow aggregation and alert rules. The capture thread feeds parsed
//! packets in; the UI polls snapshots out.

use crate::attrib::{Resolver, TableResolver};
use crate::model::*;
use crate::parse::{classify, classify_decrypted, is_client_hello, parse_frame, tls_server_version};
use crate::tls::{KeyLog, TcpStream};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::mpsc::Receiver;
use std::time::{Duration, SystemTime};

pub struct Engine {
    flows: HashMap<FlowKey, Flow>,
    order: VecDeque<FlowKey>,
    pub alerts: VecDeque<Alert>,
    pub capture_status: String,
    resolver: TableResolver,
    /// ETW process-start records (Windows): names processes that the
    /// connection tables only ever saw as a bare, already-dead PID.
    proc_feed: crate::etw::ProcFeed,
    /// Learned image-name -> exe path associations from processes the
    /// resolver could see alive. ETW events carry no path, so a
    /// short-lived process named by the feed borrows the path of its
    /// (usually long-lived) same-name siblings — as an estimate.
    path_book: PathBook,
    /// PID -> exe path for processes seen in sightings, used to find
    /// a feed-named process's parent folder.
    pid_paths: HashMap<u32, String>,
    /// For flows named by the ETW feed: the parent PID from the start
    /// record, so the parent's folder can be probed for the exe.
    feed_parents: HashMap<FlowKey, u32>,
    /// Flows whose parent folder was already probed (probe once).
    probe_tried: HashSet<FlowKey>,
    settings: Settings,
    local_ips: HashSet<IpAddr>,
    seen_processes: HashSet<String>,
    seen_destinations: HashSet<(String, String)>, // (process, host-or-ip)
    upload_windows: HashMap<String, VecDeque<(SystemTime, u64)>>, // per process
    /// Reassembled streams for TLS flows (kept engine-side: snapshots stay
    /// light) plus the sizes/keys state at the last decryption attempt.
    tls_streams: HashMap<FlowKey, (TcpStream, TcpStream, (usize, usize, usize))>,
    keylog: KeyLog,
    last_keylog_check: SystemTime,
    last_resolve: SystemTime,
    max_flows: usize,
}

pub enum EngineEvent {
    /// A captured frame plus its pcap datalink type.
    Frame(Vec<u8>, i32),
    /// Table mode (no packet capture): live connection rows from the OS.
    Sightings(Vec<crate::attrib::ConnRow>),
    /// Human-readable capture state for the UI header.
    CaptureStatus(String),
    /// A process started (ETW feed; Windows only).
    ProcStart(crate::etw::ProcStart),
    Tick,
}

impl Engine {
    pub fn new(settings: Settings) -> Self {
        Engine {
            flows: HashMap::new(),
            order: VecDeque::new(),
            alerts: VecDeque::new(),
            capture_status: if cfg!(feature = "npcap") {
                "キャプチャ初期化中…".to_string()
            } else {
                "接続表モード（このビルドには Npcap キャプチャが含まれていません）".to_string()
            },
            resolver: TableResolver::new(),
            proc_feed: crate::etw::ProcFeed::new(),
            path_book: PathBook::default(),
            pid_paths: HashMap::new(),
            feed_parents: HashMap::new(),
            probe_tried: HashSet::new(),
            settings,
            local_ips: detect_local_ips(),
            seen_processes: HashSet::new(),
            seen_destinations: HashSet::new(),
            upload_windows: HashMap::new(),
            tls_streams: HashMap::new(),
            keylog: KeyLog::new(),
            last_keylog_check: SystemTime::UNIX_EPOCH,
            last_resolve: SystemTime::UNIX_EPOCH,
            max_flows: 5000,
        }
    }

    pub fn set_settings(&mut self, s: Settings) {
        self.settings = s;
    }

    pub fn run(&mut self, rx: Receiver<EngineEvent>) {
        for ev in rx {
            match ev {
                EngineEvent::Frame(f, lt) => self.on_frame(&f, lt),
                EngineEvent::Sightings(rows) => self.on_sightings(rows),
                EngineEvent::CaptureStatus(s) => self.capture_status = s,
                EngineEvent::ProcStart(p) => self.proc_feed.push(p),
                EngineEvent::Tick => self.on_tick(),
            }
        }
    }

    /// Table mode: merge OS connection rows into flows. Byte counts stay
    /// zero (the tables do not provide them); endpoints, owners and timing
    /// are real, which is what leak detection primarily needs.
    fn on_sightings(&mut self, rows: Vec<crate::attrib::ConnRow>) {
        let now = SystemTime::now();
        for row in rows {
            // Learn name->path and pid->path from every process the
            // tables could resolve while alive; both are used to give
            // feed-named (name-only) processes a path later.
            if !row.proc.path.is_empty() {
                self.path_book.learn(&row.proc.name, &row.proc.path);
                if self.pid_paths.len() > 8192 {
                    self.pid_paths.clear();
                }
                self.pid_paths.insert(row.proc.pid, row.proc.path.clone());
            }
            let key = FlowKey {
                proto: row.proto,
                local_ip: row.local_ip,
                local_port: row.local_port,
                remote_ip: row.remote_ip,
                remote_port: row.remote_port,
            };
            let is_new = !self.flows.contains_key(&key);
            if is_new && self.flows.len() >= self.max_flows {
                if let Some(old) = self.order.pop_front() {
                    self.flows.remove(&old);
                }
            }
            let flow = self
                .flows
                .entry(key.clone())
                .or_insert_with(|| Flow::new(key.clone(), now));
            flow.sightings += 1;
            flow.last_seen = now;
            flow.pid = Some(row.proc.pid);
            // Never downgrade a resolved name back to the "pid N"
            // placeholder: the two resolvers (sightings thread and the
            // engine's own) learn at different moments.
            let incoming_unresolved =
                row.proc.path.is_empty() && row.proc.name.starts_with("pid ");
            let current_unresolved = flow.process_path.is_empty()
                && (flow.process_name.is_empty()
                    || flow.process_name.starts_with("pid "));
            if !incoming_unresolved || current_unresolved {
                flow.process_name = row.proc.name.clone();
                flow.process_path = row.proc.path.clone();
                flow.path_estimate = row.proc.path_estimate;
            }
            // ETW feed: even when the table resolver only has the bare
            // PID (short-lived process, already gone), the process-start
            // record usually knows the name.
            if flow.process_path.is_empty() && flow.process_name.starts_with("pid ") {
                if let Some(s) = self.proc_feed.name_for(row.proc.pid, now) {
                    flow.process_name = s.name;
                    if s.parent_pid != 0 {
                        self.feed_parents.insert(key.clone(), s.parent_pid);
                    }
                }
            }
            if is_new {
                self.order.push_back(key.clone());
                if !self.settings.is_excluded(&row.proc.name, &row.proc.path) {
                    let host = row.remote_ip.to_string();
                    self.alert_checks(&row.proc.name.clone(), &host, true, 0, now);
                }
            }
        }
    }

    fn on_tick(&mut self) {
        self.try_keylog_decrypt();
        if self.last_resolve.elapsed().unwrap_or_default() > Duration::from_millis(300) {
            self.resolver.refresh();
            self.last_resolve = SystemTime::now();
            // Late attribution: flows whose owner is now known, plus
            // flows stuck with the "pid N" placeholder whose owner the
            // resolver can name by now (fast polling + the process
            // census catch short-lived processes much more often).
            let updates: Vec<(FlowKey, crate::attrib::ProcInfo)> = self
                .flows
                .iter()
                .filter(|(_, f)| {
                    f.pid.is_none()
                        || (f.process_path.is_empty()
                            && f.process_name.starts_with("pid "))
                })
                .filter_map(|(k, _)| {
                    self.resolver
                        .lookup(k.proto, k.local_port, k.remote_ip, k.remote_port)
                        .map(|p| (k.clone(), p))
                })
                .collect();
            for (k, p) in updates {
                if let Some(f) = self.flows.get_mut(&k) {
                    // A flow that already knows its PID must never be
                    // re-attributed to a different process (its local
                    // port may have been reused since).
                    if f.pid.is_some() && f.pid != Some(p.pid) {
                        continue;
                    }
                    f.pid = Some(p.pid);
                    f.process_name = p.name;
                    f.path_estimate = p.path_estimate;
                    f.process_path = p.path;
                }
            }
            // ETW feed upgrade: flows that know their PID but are still
            // wearing the "pid N" placeholder may belong to a process
            // that started — and died — between table polls. The start
            // record names it; match on the flow's first-seen time so a
            // recycled PID resolves to the right instance.
            let feed_updates: Vec<(FlowKey, String, u32)> = self
                .flows
                .iter()
                .filter(|(_, f)| {
                    f.pid.is_some()
                        && f.process_path.is_empty()
                        && f.process_name.starts_with("pid ")
                })
                .filter_map(|(k, f)| {
                    self.proc_feed
                        .name_for(f.pid.unwrap_or(0), f.first_seen)
                        .map(|s| (k.clone(), s.name, s.parent_pid))
                })
                .collect();
            for (k, name, parent_pid) in feed_updates {
                if parent_pid != 0 {
                    self.feed_parents.insert(k.clone(), parent_pid);
                }
                if let Some(f) = self.flows.get_mut(&k) {
                    f.process_name = name;
                }
            }
            // Path completion for named-but-pathless flows (the ETW
            // feed yields names without paths): first probe the parent
            // process's folder and common subfolders for the exe —
            // helpers usually live next to their parent app — then
            // fall back to the path learned from same-name processes
            // that were seen alive. Both are inferences and are
            // flagged as estimates.
            // Each entry: (flow, name, path, parent_folder_was_probed)
            let path_updates: Vec<(FlowKey, String, String, bool)> = self
                .flows
                .iter()
                .filter(|(_, f)| {
                    !f.process_name.is_empty()
                        && !f.process_name.starts_with("pid ")
                        && f.process_path.is_empty()
                })
                .filter_map(|(k, f)| {
                    let name = f.process_name.clone();
                    let mut probed = false;
                    if !self.probe_tried.contains(k) {
                        if let Some(ppid) = self.feed_parents.get(k) {
                            if let Some(ppath) = self.pid_paths.get(ppid) {
                                if let Some(dir) =
                                    std::path::Path::new(ppath).parent()
                                {
                                    probed = true;
                                    for cand in [
                                        dir.join(&name),
                                        dir.join("resources").join(&name),
                                        dir.join("bin").join(&name),
                                    ] {
                                        if cand.is_file() {
                                            return Some((
                                                k.clone(),
                                                name,
                                                cand.to_string_lossy().into_owned(),
                                                true,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    self.path_book
                        .best(&name)
                        .map(|p| (k.clone(), name, p, probed))
                })
                .collect();
            for (k, _, _, probed) in &path_updates {
                if *probed {
                    self.probe_tried.insert(k.clone());
                }
            }
            // Flows that could not be completed this round but whose
            // parent folder was probed are also done probing.
            let missed_probes: Vec<FlowKey> = self
                .flows
                .iter()
                .filter(|(_, f)| f.process_path.is_empty())
                .filter(|(k, _)| {
                    !self.probe_tried.contains(k)
                        && self
                            .feed_parents
                            .get(k)
                            .map(|ppid| self.pid_paths.contains_key(ppid))
                            .unwrap_or(false)
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in missed_probes {
                self.probe_tried.insert(k);
            }
            for (k, name, p, _) in path_updates {
                // Teach the book: siblings of this process (same name,
                // equally pathless) can reuse a probed/learned path.
                self.path_book.learn(&name, &p);
                if let Some(f) = self.flows.get_mut(&k) {
                    if f.process_path.is_empty() {
                        f.process_path = p;
                        f.path_estimate = true;
                    }
                }
            }
        }
        self.check_upload_bursts();
    }

    fn on_frame(&mut self, frame: &[u8], linktype: i32) {
        let Some(p) = parse_frame(frame, linktype) else { return };
        let now = SystemTime::now();
        let upload = self.local_ips.contains(&p.src_ip);
        let (local_ip, local_port, remote_ip, remote_port) = if upload {
            (p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        } else {
            (p.dst_ip, p.dst_port, p.src_ip, p.src_port)
        };
        let key = FlowKey { proto: p.proto, local_ip, local_port, remote_ip, remote_port };
        let len = frame.len() as u64;

        let is_new = !self.flows.contains_key(&key);
        if is_new && self.flows.len() >= self.max_flows {
            if let Some(old) = self.order.pop_front() {
                self.flows.remove(&old);
                self.tls_streams.remove(&old);
            }
        }
        let flow = self.flows.entry(key.clone()).or_insert_with(|| {
            Flow::new(key.clone(), now)
        });
        flow.last_seen = now;
        if upload {
            flow.bytes_up += len;
            flow.packets_up += 1;
            if flow.raw_up.is_empty() && !p.payload.is_empty() {
                flow.raw_up = p.payload[..p.payload.len().min(2048)].to_vec();
            }
            if matches!(flow.content_up, Content::Unknown) {
                flow.content_up = classify(&p.payload, p.src_port, p.dst_port, p.proto);
            }
        } else {
            flow.bytes_down += len;
            flow.packets_down += 1;
            if flow.raw_down.is_empty() && !p.payload.is_empty() {
                flow.raw_down = p.payload[..p.payload.len().min(2048)].to_vec();
            }
            if matches!(flow.content_down, Content::Unknown) {
                flow.content_down = classify(&p.payload, p.src_port, p.dst_port, p.proto);
            }
        }
        // Keep the reassembled streams of TLS flows for key-log decryption.
        if p.proto == Proto::Tcp {
            let has_stream = self.tls_streams.contains_key(&key);
            if has_stream {
                if let Some((up_s, down_s, _)) = self.tls_streams.get_mut(&key) {
                    if upload {
                        up_s.push(p.seq.unwrap_or(0), &p.payload);
                    } else {
                        down_s.push(p.seq.unwrap_or(0), &p.payload);
                    }
                }
            } else if upload && is_client_hello(&p.payload) && self.tls_streams.len() < 2000 {
                let mut up_s = TcpStream::new();
                up_s.push(p.seq.unwrap_or(0), &p.payload);
                self.tls_streams.insert(key.clone(), (up_s, TcpStream::new(), (0, 0, 0)));
            }
        }
        // TLS version from the ServerHello when one passes by.
        if let Some(v) = tls_server_version(&p.payload) {
            flow.tls_version = Some(v);
        } else if flow.tls_version.is_none() && is_client_hello(&p.payload) {
            flow.tls_version = Some("TLS".to_string());
        }
        // host name hints
        match (&flow.content_up, &flow.content_down) {
            (Content::TlsHello { server_name: Some(s) }, _) |
            (_, Content::TlsHello { server_name: Some(s) }) => {
                if flow.remote_host.is_none() {
                    flow.remote_host = Some(s.clone());
                }
            }
            (Content::Dns { names }, _) | (_, Content::Dns { names }) => {
                if flow.remote_host.is_none() {
                    flow.remote_host = names.first().cloned();
                }
            }
            _ => {}
        }
        if flow.pid.is_none() {
            if let Some(proc) = self.resolver.lookup(key.proto, key.local_port, key.remote_ip, key.remote_port) {
                flow.pid = Some(proc.pid);
                flow.process_name = proc.name.clone();
                flow.process_path = proc.path.clone();
                flow.path_estimate = proc.path_estimate;
            }
        }
        let (pname, ppath) = (flow.process_name.clone(), flow.process_path.clone());
        let host_label = flow
            .remote_host
            .clone()
            .unwrap_or_else(|| remote_ip.to_string());
        if is_new {
            self.order.push_back(key.clone());
        }
        drop(flow);
        if !pname.is_empty() && !self.settings.is_excluded(&pname, &ppath) {
            self.alert_checks(&pname, &host_label, upload, len, now);
        }
    }

    /// Refresh the key log and decrypt any TLS flow whose streams or the
    /// available secrets changed since the last attempt.
    fn try_keylog_decrypt(&mut self) {
        if self.last_keylog_check.elapsed().unwrap_or_default() > Duration::from_secs(2) {
            self.last_keylog_check = SystemTime::now();
            self.keylog.refresh(&keylog_path(&self.settings));
        }
        if self.keylog.entries() == 0 {
            return;
        }
        let entries = self.keylog.entries();
        let keys: Vec<FlowKey> = self.tls_streams.keys().cloned().collect();
        for k in keys {
            let already = self.flows.get(&k).map(|f| f.tls_decrypted).unwrap_or(false);
            if already {
                continue;
            }
            let Some((up_s, down_s, seen)) = self.tls_streams.get_mut(&k) else {
                continue;
            };
            let state = (up_s.len(), down_s.len(), entries);
            if *seen == state || up_s.len() == 0 || down_s.len() == 0 {
                continue;
            }
            *seen = state;
            let up = up_s.bytes().to_vec();
            let down = down_s.bytes().to_vec();
            let Some(dec) = crate::tls::try_decrypt(&up, &down, &self.keylog) else {
                continue;
            };
            if let Some(flow) = self.flows.get_mut(&k) {
                flow.tls_decrypted = true;
                if !dec.up.is_empty() {
                    flow.content_up = classify_decrypted(&dec.up);
                    flow.plain_up = dec.up;
                }
                if !dec.down.is_empty() {
                    flow.content_down = classify_decrypted(&dec.down);
                    flow.plain_down = dec.down;
                }
            }
        }
    }

    fn alert_checks(&mut self, process: &str, host: &str, upload: bool, len: u64, now: SystemTime) {
        if self.settings.alert_on_new_process && !self.seen_processes.contains(process) {
            self.seen_processes.insert(process.to_string());
            self.push_alert(Alert {
                at: now,
                kind: AlertKind::NewProcess,
                process_name: process.to_string(),
                detail: format!("{process} が初めて通信しました（宛先: {host}）"),
            });
        }
        if self.settings.alert_on_new_destination {
            let k = (process.to_string(), host.to_string());
            if !self.seen_destinations.contains(&k) {
                self.seen_destinations.insert(k);
                if self.seen_processes.len() > 1 {
                    self.push_alert(Alert {
                        at: now,
                        kind: AlertKind::NewDestination,
                        process_name: process.to_string(),
                        detail: format!("{process} が新しい宛先 {host} に接続しました"),
                    });
                }
            }
        }
        if upload {
            let w = self.upload_windows.entry(process.to_string()).or_default();
            w.push_back((now, len));
            while let Some((t, _)) = w.front() {
                if now.duration_since(*t).unwrap_or_default() > Duration::from_secs(60) {
                    w.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    fn check_upload_bursts(&mut self) {
        let threshold = self.settings.upload_burst_bytes_per_min;
        if threshold == 0 {
            return;
        }
        let mut fired = Vec::new();
        for (proc_name, w) in self.upload_windows.iter_mut() {
            let total: u64 = w.iter().map(|(_, n)| *n).sum();
            if total >= threshold {
                fired.push((proc_name.clone(), total));
                w.clear();
            }
        }
        for (proc_name, total) in fired {
            self.push_alert(Alert {
                at: SystemTime::now(),
                kind: AlertKind::UploadBurst,
                process_name: proc_name.clone(),
                detail: format!(
                    "{proc_name} が直近1分で約 {} MB をアップロードしました",
                    total / (1024 * 1024)
                ),
            });
        }
    }

    fn push_alert(&mut self, a: Alert) {
        self.alerts.push_back(a);
        while self.alerts.len() > 500 {
            self.alerts.pop_front();
        }
    }

    pub fn snapshot(&self) -> (Vec<Flow>, Vec<Alert>, String) {
        let mut flows: Vec<Flow> = self.flows.values().cloned().collect();
        flows.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        (
            flows,
            self.alerts.iter().cloned().collect(),
            self.capture_status.clone(),
        )
    }
}

/// Where the browser key log lives: settings override, else
/// `sslkeylog.log` in the same data directory as settings.txt.
pub fn keylog_path(settings: &Settings) -> std::path::PathBuf {
    if let Some(p) = &settings.keylog_path {
        if !p.trim().is_empty() {
            return std::path::PathBuf::from(p.trim());
        }
    }
    data_dir().join("sslkeylog.log")
}

fn data_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join("PacketScope")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
        home.join("Library").join("Application Support").join("PacketScope")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".config"))
                    .unwrap_or_default()
            });
        base.join("PacketScope")
    }
    #[cfg(not(any(windows, unix)))]
    {
        std::path::PathBuf::from("PacketScope")
    }
}

fn detect_local_ips() -> HashSet<IpAddr> {
    let mut s = HashSet::new();
    s.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    s.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    // The classic no-traffic trick: a UDP "connect" only picks the route,
    // revealing this machine's primary address on that family.
    for target in ["8.8.8.8:80", "[2001:4860:4860::8888]:80"] {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    s.insert(local.ip());
                }
            }
        }
    }
    s
}

/// Start the pipeline. Returns the snapshot receiver the UI drains:
/// (flows, alerts) roughly twice a second.
pub fn spawn(
    settings: Settings,
) -> std::sync::mpsc::Receiver<(Vec<Flow>, Vec<Alert>, String)> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<EngineEvent>(8192);
    let (snap_tx, snap_rx) = std::sync::mpsc::channel();
    {
        let tx_tick = tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            if tx_tick.send(EngineEvent::Tick).is_err() {
                break;
            }
        });
    }
    #[cfg(feature = "npcap")]
    {
        let tx_cap = tx.clone();
        std::thread::spawn(move || crate::capture::run_pcap(tx_cap));
    }
    // ETW process-start feed (Windows): names processes too
    // short-lived for the connection tables. Silently absent when the
    // kernel logger session can't be started.
    crate::etw::spawn(tx.clone());
    {
        // Connection-table sightings always run: they are the fallback
        // when Npcap is missing (the app then still shows which app is
        // talking where), and they speed up process attribution when
        // capture is active. The poll is fast (150 ms) on purpose:
        // short-lived processes — the ones that used to end up as
        // anonymous "pid N" rows — must be caught while they are still
        // alive, because once they exit only their PID remains.
        let tx_tab = tx.clone();
        std::thread::spawn(move || {
            let mut resolver = TableResolver::new();
            loop {
                let rows = resolver.connections();
                if tx_tab.send(EngineEvent::Sightings(rows)).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        });
    }
    std::thread::spawn(move || {
        let mut engine = Engine::new(settings);
        let mut last_snap = SystemTime::now();
        for ev in rx {
            match ev {
                EngineEvent::Frame(f, lt) => engine.on_frame(&f, lt),
                EngineEvent::Sightings(rows) => engine.on_sightings(rows),
                EngineEvent::CaptureStatus(s) => engine.capture_status = s,
                EngineEvent::ProcStart(p) => engine.proc_feed.push(p),
                EngineEvent::Tick => {
                    engine.on_tick();
                    if last_snap.elapsed().unwrap_or_default() > Duration::from_millis(500) {
                        last_snap = SystemTime::now();
                        if snap_tx.send(engine.snapshot()).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    snap_rx
}

/// Learned image-name -> exe path associations. The same program can
/// legitimately live at several paths (System32 vs SysWOW64), so the
/// most frequently observed path wins.
#[derive(Default)]
struct PathBook {
    map: HashMap<String, HashMap<String, u32>>,
}

impl PathBook {
    fn learn(&mut self, name: &str, path: &str) {
        if name.is_empty() || path.is_empty() {
            return;
        }
        *self
            .map
            .entry(name.to_lowercase())
            .or_default()
            .entry(path.to_string())
            .or_insert(0) += 1;
    }

    fn best(&self, name: &str) -> Option<String> {
        self.map
            .get(&name.to_lowercase())
            .and_then(|m| m.iter().max_by_key(|(_, c)| **c).map(|(p, _)| p.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::PathBook;

    #[test]
    fn path_book_picks_majority_and_ignores_case() {
        let mut b = PathBook::default();
        b.learn("cmd.exe", "C:\\Windows\\System32\\cmd.exe");
        b.learn("CMD.EXE", "C:\\Windows\\System32\\cmd.exe");
        b.learn("cmd.exe", "C:\\Windows\\SysWOW64\\cmd.exe");
        assert_eq!(
            b.best("Cmd.Exe").as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        assert_eq!(b.best("missing.exe"), None);
        b.learn("", "C:\\x.exe");
        b.learn("a.exe", "");
        assert_eq!(b.best("a.exe"), None);
    }
}
