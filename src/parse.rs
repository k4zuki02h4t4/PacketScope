//! Packet dissection: from raw link-layer bytes to endpoints + payload hints.
//!
//! Only the first payload bytes of a flow are inspected (enough for a DNS
//! name, a TLS SNI or an HTTP request line); this is a monitor, not a
//! stream reassembler.

use crate::model::{Content, Proto};
use etherparse::{LaxPacketHeaders, TransportHeader};
use std::net::IpAddr;

pub struct Parsed {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: Proto,
    pub payload: Vec<u8>,
}

/// Parse one captured frame. `linktype` is the pcap datalink type:
/// 1 = Ethernet, 0 = BSD loopback (DLT_NULL, used by Npcap's loopback
/// adapter), 12/101 = raw IP. Every frame that carries IP or ARP is
/// returned; TCP/UDP get ports, other protocols are reported as
/// `Proto::IpOther(number)` / `Proto::Ether(type)` with port 0 so the UI
/// can still show direction, peer and size.
pub fn parse_frame(frame: &[u8], linktype: i32) -> Option<Parsed> {
    match linktype {
        0 => {
            // DLT_NULL: 4-byte address-family header, then a raw IP packet.
            if frame.len() <= 4 {
                return None;
            }
            return parse_ip(&frame[4..]);
        }
        12 | 101 => return parse_ip(frame),
        _ => {}
    }
    parse_ethernet(frame)
}

/// Parse a raw IP packet (no link layer).
fn parse_ip(packet: &[u8]) -> Option<Parsed> {
    let headers = LaxPacketHeaders::from_ip(packet).ok()?;
    finish(headers)
}

fn parse_ethernet(frame: &[u8]) -> Option<Parsed> {
    if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x06 {
        // ARP (Ethernet/IPv4): sender/target protocol addresses at fixed
        // offsets; operation 1 = request, 2 = reply.
        let src_b: [u8; 4] = frame[28..32].try_into().unwrap();
        let dst_b: [u8; 4] = frame[38..42].try_into().unwrap();
        let src_ip = IpAddr::V4(src_b.into());
        let dst_ip = IpAddr::V4(dst_b.into());
        return Some(Parsed {
            src_ip,
            src_port: 0,
            dst_ip,
            dst_port: 0,
            proto: Proto::Ether(0x0806),
            payload: frame[14..].to_vec(),
        });
    }
    let headers = LaxPacketHeaders::from_ethernet(frame).ok()?;
    finish(headers)
}

fn finish(headers: LaxPacketHeaders<'_>) -> Option<Parsed> {
    let net = headers.net?;
    let (src_ip, dst_ip, ip_proto) = match &net {
        etherparse::NetHeaders::Ipv4(h, _) => (
            IpAddr::V4(h.source.into()),
            IpAddr::V4(h.destination.into()),
            h.protocol.0,
        ),
        etherparse::NetHeaders::Ipv6(h, _) => (
            IpAddr::V6(h.source.into()),
            IpAddr::V6(h.destination.into()),
            h.next_header.0,
        ),
    };
    let (proto, src_port, dst_port) = match headers.transport {
        Some(TransportHeader::Tcp(h)) => (Proto::Tcp, h.source_port, h.destination_port),
        Some(TransportHeader::Udp(h)) => (Proto::Udp, h.source_port, h.destination_port),
        _ => (Proto::IpOther(ip_proto), 0, 0),
    };
    Some(Parsed {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto,
        payload: headers.payload.slice().to_vec(),
    })
}

/// Classify a payload. `sport`/`dport` help recognise DNS and HTTP.
pub fn classify(payload: &[u8], sport: u16, dport: u16, proto: Proto) -> Content {
    if payload.is_empty() {
        return Content::Unknown;
    }
    match proto {
        Proto::IpOther(50) => return Content::Encrypted { kind: "ESP (IPsec)" },
        Proto::IpOther(1) | Proto::IpOther(58) => {
            // ICMP / ICMPv6: type byte first.
            let label = match (proto, payload[0]) {
                (Proto::IpOther(1), 0) => "ICMP echo reply（応答）",
                (Proto::IpOther(1), 8) => "ICMP echo request（ping）",
                (Proto::IpOther(1), 3) => "ICMP destination unreachable",
                (Proto::IpOther(1), 11) => "ICMP time exceeded",
                (Proto::IpOther(58), 128) => "ICMPv6 echo request（ping）",
                (Proto::IpOther(58), 129) => "ICMPv6 echo reply（応答）",
                (Proto::IpOther(58), 133) => "ICMPv6 router solicitation",
                (Proto::IpOther(58), 134) => "ICMPv6 router advertisement",
                (Proto::IpOther(58), 135) => "ICMPv6 neighbor solicitation",
                (Proto::IpOther(58), 136) => "ICMPv6 neighbor advertisement",
                _ => "ICMP",
            };
            return Content::Plain { preview: label.to_string() };
        }
        Proto::Ether(0x0806) => {
            if payload.len() >= 8 {
                let oper = u16::from_be_bytes([payload[6], payload[7]]);
                let label = match oper {
                    1 => "ARP request（誰がこの IP を持っているか）",
                    2 => "ARP reply（IP と MAC の対応の通知）",
                    _ => "ARP",
                };
                return Content::Plain { preview: label.to_string() };
            }
            return Content::Unknown;
        }
        Proto::IpOther(_) | Proto::Ether(_) => {
            return Content::Plain { preview: preview_text(payload) };
        }
        Proto::Tcp | Proto::Udp => {}
    }
    if sport == 53 || dport == 53 {
        if let Some(names) = dns_names(payload) {
            return Content::Dns { names };
        }
    }
    if payload[0] == 0x16 && payload.len() > 5 && payload[5] == 0x01 {
        return Content::TlsHello { server_name: tls_sni(payload) };
    }
    if proto == Proto::Udp && payload.len() >= 12 && payload[0] & 0xC0 == 0xC0 {
        // QUIC long header: encrypted, version in bytes 1..5.
        return Content::Encrypted { kind: "QUIC" };
    }
    if let Some(http) = http_headline(payload) {
        return http;
    }
    if looks_like_tls(payload) {
        return Content::Encrypted { kind: "TLS" };
    }
    let printable = payload.iter().filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\n' || **b == b'\r' || **b == b'\t').count();
    if !payload.is_empty() && printable * 100 / payload.len() >= 85 {
        return Content::Plain { preview: preview_text(payload) };
    }
    Content::Unknown
}

fn looks_like_tls(p: &[u8]) -> bool {
    p.len() >= 3 && matches!(p[0], 0x14 | 0x16 | 0x17) && p[1] == 0x03
}

/// First line of an HTTP request/response + start of body, if this is HTTP.
fn http_headline(p: &[u8]) -> Option<Content> {
    let text = std::str::from_utf8(&p[..p.len().min(8192)]).ok()?;
    let first = text.lines().next()?.trim().to_string();
    let is_req = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "]
        .iter()
        .any(|m| first.starts_with(m));
    let is_resp = first.starts_with("HTTP/");
    if !is_req && !is_resp {
        return None;
    }
    let mut host = String::new();
    for line in text.lines().skip(1).take(40) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                host = v.trim().to_string();
            }
        }
    }
    let headline = if host.is_empty() { first } else { format!("{first}  (Host: {host})") };
    let body_at = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let preview = if body_at > 0 && body_at < text.len() {
        text[body_at..].chars().take(4096).collect()
    } else {
        String::new()
    };
    Some(Content::Http { headline, preview })
}

/// DNS question names from a standard DNS message (no compression in QNAME
/// of the question section, which is what we read).
fn dns_names(p: &[u8]) -> Option<Vec<String>> {
    if p.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    if qd == 0 || qd > 8 {
        return None;
    }
    let mut off = 12;
    let mut names = Vec::new();
    for _ in 0..qd {
        let mut labels = Vec::new();
        loop {
            if off >= p.len() {
                return None;
            }
            let len = p[off] as usize;
            off += 1;
            if len == 0 {
                break;
            }
            if len > 63 || off + len > p.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&p[off..off + len]).into_owned());
            off += len;
        }
        names.push(labels.join("."));
        off += 4; // QTYPE + QCLASS
    }
    Some(names)
}

/// Minimal TLS ClientHello SNI extraction (RFC 6066 server_name extension).
fn tls_sni(p: &[u8]) -> Option<String> {
    // Record: type(1) ver(2) len(2) | handshake: type(1) len(3) ver(2) random(32)
    if p.len() < 43 {
        return None;
    }
    let mut off = 5 + 4 + 2 + 32;
    // session id
    if off >= p.len() {
        return None;
    }
    let sid_len = p[off] as usize;
    off += 1 + sid_len;
    // cipher suites
    if off + 2 > p.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
    off += 2 + cs_len;
    // compression methods
    if off >= p.len() {
        return None;
    }
    let cm_len = p[off] as usize;
    off += 1 + cm_len;
    // extensions
    if off + 2 > p.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
    off += 2;
    let ext_end = (off + ext_total).min(p.len());
    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([p[off], p[off + 1]]);
        let elen = u16::from_be_bytes([p[off + 2], p[off + 3]]) as usize;
        off += 4;
        if off + elen > p.len() {
            return None;
        }
        if etype == 0 {
            // server_name: list len(2), type(1), name len(2), name
            let e = &p[off..off + elen];
            if e.len() > 5 && e[2] == 0 {
                let nl = u16::from_be_bytes([e[3], e[4]]) as usize;
                if 5 + nl <= e.len() {
                    return String::from_utf8(e[5..5 + nl].to_vec()).ok();
                }
            }
            return None;
        }
        off += elen;
    }
    None
}

/// Printable preview of a payload, truncated, control bytes shown as '·'.
pub fn preview_text(p: &[u8]) -> String {
    p.iter()
        .take(4096)
        .map(|&b| {
            if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '·'
            }
        })
        .collect()
}

/// Negotiated TLS version from a ServerHello payload, if this is one.
/// Returns e.g. "TLS 1.3" (from the supported_versions extension) or the
/// legacy version mapping. None for anything that is not a ServerHello.
pub fn tls_server_version(p: &[u8]) -> Option<String> {
    // Record: type(1) ver(2) len(2) | handshake: type(1) len(3) ver(2) …
    if p.len() < 44 || p[0] != 0x16 || p[5] != 0x02 {
        return None;
    }
    let legacy = u16::from_be_bytes([p[9], p[10]]);
    // Skip: record hdr 5 + hs hdr 4 + version 2 + random 32 = offset 43.
    let sid_len = p[43] as usize;
    let mut off = 44 + sid_len;
    if p.len() < off + 4 {
        return match legacy {
            0x0303 => Some("TLS 1.2".into()),
            0x0302 => Some("TLS 1.1".into()),
            0x0301 => Some("TLS 1.0".into()),
            _ => None,
        };
    }
    // cipher(2) + compression(1) + extensions len(2)
    off += 3;
    if p.len() < off + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
    off += 2;
    let end = (off + ext_total).min(p.len());
    while off + 4 <= end {
        let etype = u16::from_be_bytes([p[off], p[off + 1]]);
        let elen = u16::from_be_bytes([p[off + 2], p[off + 3]]) as usize;
        if etype == 0x002b && elen >= 2 && off + 6 <= p.len() {
            let v = u16::from_be_bytes([p[off + 4], p[off + 5]]);
            return Some(match v {
                0x0304 => "TLS 1.3".to_string(),
                0x0303 => "TLS 1.2".to_string(),
                _ => return None,
            });
        }
        off += 4 + elen;
    }
    match legacy {
        0x0303 => Some("TLS 1.2".into()),
        0x0302 => Some("TLS 1.1".into()),
        0x0301 => Some("TLS 1.0".into()),
        _ => None,
    }
}

/// True when the payload starts a TLS ClientHello.
pub fn is_client_hello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[5] == 0x01
}
