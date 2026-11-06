//! Flow aggregation and alert rules. The capture thread feeds parsed
//! packets in; the UI polls snapshots out.

use crate::attrib::{Resolver, TableResolver};
use crate::model::*;
use crate::parse::{classify, is_client_hello, parse_frame, tls_server_version};
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
    settings: Settings,
    local_ips: HashSet<IpAddr>,
    seen_processes: HashSet<String>,
    seen_destinations: HashSet<(String, String)>, // (process, host-or-ip)
    upload_windows: HashMap<String, VecDeque<(SystemTime, u64)>>, // per process
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
            settings,
            local_ips: detect_local_ips(),
            seen_processes: HashSet::new(),
            seen_destinations: HashSet::new(),
            upload_windows: HashMap::new(),
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
            flow.process_name = row.proc.name.clone();
            flow.process_path = row.proc.path.clone();
            flow.path_estimate = row.proc.path_estimate;
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
        if self.last_resolve.elapsed().unwrap_or_default() > Duration::from_secs(1) {
            self.resolver.refresh();
            self.last_resolve = SystemTime::now();
            // late attribution for flows whose owner is now known
            let updates: Vec<(FlowKey, crate::attrib::ProcInfo)> = self
                .flows
                .iter()
                .filter(|(_, f)| f.pid.is_none())
                .filter_map(|(k, _)| {
                    self.resolver
                        .lookup(k.proto, k.local_port, k.remote_ip, k.remote_port)
                        .map(|p| (k.clone(), p))
                })
                .collect();
            for (k, p) in updates {
                if let Some(f) = self.flows.get_mut(&k) {
                    f.pid = Some(p.pid);
                    f.process_name = p.name;
                    f.path_estimate = p.path_estimate;
                    f.process_path = p.path;
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
    {
        // Connection-table sightings always run: they are the fallback
        // when Npcap is missing (the app then still shows which app is
        // talking where), and they speed up process attribution when
        // capture is active.
        let tx_tab = tx.clone();
        std::thread::spawn(move || {
            let mut resolver = TableResolver::new();
            loop {
                let rows = resolver.connections();
                if tx_tab.send(EngineEvent::Sightings(rows)).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
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
