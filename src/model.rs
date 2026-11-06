//! Shared data types: flows, decoded content, alerts, settings.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    /// Any other IP protocol number (1 ICMP, 2 IGMP, 47 GRE, 50 ESP, 58 ICMPv6…).
    IpOther(u8),
    /// Non-IP EtherType (0x0806 ARP, …); ports are 0 for these flows.
    Ether(u16),
}

impl Proto {
    pub fn name(&self) -> String {
        match self {
            Proto::Tcp => "TCP".to_string(),
            Proto::Udp => "UDP".to_string(),
            Proto::IpOther(1) => "ICMP".to_string(),
            Proto::IpOther(2) => "IGMP".to_string(),
            Proto::IpOther(47) => "GRE".to_string(),
            Proto::IpOther(50) => "ESP".to_string(),
            Proto::IpOther(51) => "AH".to_string(),
            Proto::IpOther(58) => "ICMPv6".to_string(),
            Proto::IpOther(n) => format!("IP proto {n}"),
            Proto::Ether(0x0806) => "ARP".to_string(),
            Proto::Ether(t) => format!("EtherType 0x{t:04x}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Upload,
    Download,
}

/// One transport flow (5-tuple), aggregated from packets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: Proto,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

/// What the payload turned out to be, as far as it can be known from outside.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// Nothing decoded yet.
    Unknown,
    /// TLS/QUIC etc.: content is encrypted; only metadata is visible.
    Encrypted { kind: &'static str },
    /// DNS query or response (plaintext by design).
    Dns { names: Vec<String> },
    /// TLS ClientHello: the server name the app asked for.
    TlsHello { server_name: Option<String> },
    /// Plaintext HTTP: request or response line + a body preview.
    Http { headline: String, preview: String },
    /// Other plaintext protocol: printable preview of the first bytes.
    Plain { preview: String },
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub pid: Option<u32>,
    pub process_name: String,
    pub process_path: String,
    /// process_path was inferred (service table / known system location).
    pub path_estimate: bool,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub packets_up: u64,
    pub packets_down: u64,
    pub remote_host: Option<String>,
    pub content_up: Content,
    pub content_down: Content,
    /// First payload bytes per direction (for the Raw bytes view).
    pub raw_up: Vec<u8>,
    pub raw_down: Vec<u8>,
    /// Negotiated TLS version when a ServerHello was seen ("TLS 1.3"…).
    pub tls_version: Option<String>,
    /// Set once the user has seen this flow in the UI.
    pub acknowledged: bool,
    /// How often the OS connection table reported this flow (table mode /
    /// fallback sightings; no byte counts are known for those).
    pub sightings: u64,
}

impl Flow {
    pub fn new(key: FlowKey, now: SystemTime) -> Self {
        Flow {
            key,
            pid: None,
            process_name: String::new(),
            process_path: String::new(),
            path_estimate: false,
            first_seen: now,
            last_seen: now,
            bytes_up: 0,
            bytes_down: 0,
            packets_up: 0,
            packets_down: 0,
            remote_host: None,
            content_up: Content::Unknown,
            content_down: Content::Unknown,
            raw_up: Vec::new(),
            raw_down: Vec::new(),
            tls_version: None,
            acknowledged: false,
            sightings: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertKind {
    /// A process that has never been seen communicating before.
    NewProcess,
    /// An already-known process contacted a destination it never used before.
    NewDestination,
    /// Upload volume from one process crossed the threshold in the window.
    UploadBurst,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub at: SystemTime,
    pub kind: AlertKind,
    pub process_name: String,
    pub detail: String,
}

/// User settings, persisted as a small text file next to the executable data.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Process image names (e.g. "chrome.exe") or full paths to ignore.
    pub excluded: HashSet<String>,
    /// Upload-burst alert threshold, bytes per minute per process.
    pub upload_burst_bytes_per_min: u64,
    pub alert_on_new_process: bool,
    pub alert_on_new_destination: bool,
    /// UI theme: PacketScope ships dark-first like the design mockups.
    pub theme_dark: bool,
}

impl Settings {
    pub fn is_excluded(&self, process_name: &str, process_path: &str) -> bool {
        self.excluded.iter().any(|e| {
            e.eq_ignore_ascii_case(process_name) || e.eq_ignore_ascii_case(process_path)
        })
    }
}
