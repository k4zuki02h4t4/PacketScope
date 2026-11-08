//! TLS decryption with browser key-log secrets (SSLKEYLOGFILE).
//!
//! Browsers (Chrome / Brave / Firefox and other Chromium or NSS based apps)
//! can write their TLS session secrets to a file named by the SSLKEYLOGFILE
//! environment variable. Given those secrets and the captured ciphertext,
//! the plaintext of *that browser's* sessions can be recovered — the same
//! mechanism Wireshark uses. Apps that do not write a key log (anything on
//! SChannel, malware, …) stay opaque; only metadata is visible for them.
//!
//! Supported: TLS 1.3 and TLS 1.2 with AEAD cipher suites (AES-GCM,
//! ChaCha20-Poly1305). CBC suites, QUIC and session resumption without a
//! fresh ClientHello in the capture are not decrypted.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

// ---------------------------------------------------------------- key log

#[derive(Default, Clone, Copy)]
pub struct Tls13Secrets {
    pub client_hs: Option<[u8; 48]>,
    pub server_hs: Option<[u8; 48]>,
    pub client_app: Option<[u8; 48]>,
    pub server_app: Option<[u8; 48]>,
    pub hs_len: usize,
    pub app_len: usize,
}

#[derive(Default)]
pub struct KeyLog {
    /// TLS 1.2: client_random -> master_secret (48 bytes).
    tls12: HashMap<[u8; 32], [u8; 48]>,
    /// TLS 1.3: client_random -> traffic secrets (secret bytes + length).
    tls13: HashMap<[u8; 32], Tls13Secrets>,
    /// Insertion order of the keys, for FIFO eviction at the entry cap.
    fifo: std::collections::VecDeque<[u8; 32]>,
    /// Client randoms inserted since the last `take_fresh` call, so
    /// the engine can retry decryption only for the streams whose
    /// keys actually arrived (audit 2026-11-08).
    fresh: Vec<[u8; 32]>,
    offset: u64,
    partial: String,
}

/// Retained key-log entries are capped: the file is attacker-influenceable
/// in the sense that any same-user process can append to it, and an
/// unbounded map in an always-on monitor is a memory lever (audit
/// 2026-11-08). Real browsers produce one entry set per session; a few
/// thousand retained sessions is far beyond a normal day's browsing.
const MAX_KEYLOG_ENTRIES: usize = 8192;
/// Most bytes consumed from the key log in one refresh. Legit growth
/// between refreshes is a handful of ~200-byte lines; a bigger jump
/// means the file is not (only) a key log, so it is skipped wholesale.
const MAX_REFRESH_BYTES: u64 = 32 * 1024 * 1024;
/// A key-log line is ~200 bytes. A trailing partial line longer than
/// this is not a line at all (e.g. a newline-less blob) and is dropped
/// instead of being buffered forever.
const MAX_PARTIAL_LINE: usize = 8192;

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn arr32(v: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

impl KeyLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> usize {
        self.tls12.len() + self.tls13.len()
    }

    /// Incrementally read new complete lines from the key-log file.
    ///
    /// Hardened after the 2026-11-08 audit: only the bytes appended
    /// since the last refresh are read (the old code re-read the whole
    /// file every ~2 s), the amount per refresh is capped, and a
    /// network (UNC) path is never followed — the key log is a local
    /// file by definition, and opening a UNC path from an elevated
    /// process would hand the server an SMB authentication attempt.
    pub fn refresh(&mut self, path: &Path) {
        let shown = path.to_string_lossy();
        if shown.starts_with("\\\\") && !shown.starts_with("\\\\?") && !shown.starts_with("\\\\.") {
            return; // UNC path: not a local key log.
        }
        let Ok(meta) = std::fs::metadata(path) else { return };
        if !meta.is_file() {
            return;
        }
        if meta.len() < self.offset {
            self.offset = 0; // rotated / truncated: start over
            self.partial.clear();
        }
        if meta.len() == self.offset {
            return;
        }
        if meta.len() - self.offset > MAX_REFRESH_BYTES {
            // Implausible growth for a key log: skip the blob entirely.
            self.offset = meta.len();
            self.partial.clear();
            return;
        }
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(path) else { return };
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut new = Vec::new();
        if f.read_to_end(&mut new).is_err() {
            return;
        }
        self.offset += new.len() as u64;
        let text = format!("{}{}", self.partial, String::from_utf8_lossy(&new));
        let mut lines: Vec<&str> = text.split('\n').collect();
        self.partial = lines.pop().unwrap_or("").to_string();
        if self.partial.len() > MAX_PARTIAL_LINE {
            self.partial.clear();
        }
        for line in lines {
            self.parse_line(line.trim());
        }
    }

    /// Client randoms inserted since the last call; empties the set.
    pub fn take_fresh(&mut self) -> Vec<[u8; 32]> {
        std::mem::take(&mut self.fresh)
    }

    /// Record a freshly inserted key for FIFO eviction and enforce
    /// the entry cap. Call only when the key was not already present.
    fn note_insert(&mut self, rand: [u8; 32]) {
        self.fresh.push(rand);
        self.fifo.push_back(rand);
        while self.entries() > MAX_KEYLOG_ENTRIES {
            let Some(old) = self.fifo.pop_front() else { break };
            self.tls12.remove(&old);
            self.tls13.remove(&old);
        }
    }

    fn parse_line(&mut self, line: &str) {
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        let mut it = line.split_whitespace();
        let (Some(label), Some(rand_hex), Some(secret_hex)) = (it.next(), it.next(), it.next())
        else {
            return;
        };
        let (Some(rand), Some(secret)) = (hex_bytes(rand_hex), hex_bytes(secret_hex)) else {
            return;
        };
        let Some(rand) = arr32(&rand) else { return };
        match label {
            "CLIENT_RANDOM" => {
                if secret.len() == 48 {
                    let fresh = !self.tls12.contains_key(&rand);
                    let mut ms = [0u8; 48];
                    ms.copy_from_slice(&secret);
                    self.tls12.insert(rand, ms);
                    if fresh {
                        self.note_insert(rand);
                    }
                }
            }
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" | "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                if secret.len() == 32 || secret.len() == 48 {
                    let fresh = !self.tls13.contains_key(&rand);
                    let e = self.tls13.entry(rand).or_default();
                    let mut buf = [0u8; 48];
                    buf[..secret.len()].copy_from_slice(&secret);
                    if label.starts_with("CLIENT") {
                        e.client_hs = Some(buf);
                    } else {
                        e.server_hs = Some(buf);
                    }
                    e.hs_len = secret.len();
                    if fresh {
                        self.note_insert(rand);
                    }
                }
            }
            "CLIENT_TRAFFIC_SECRET_0" | "SERVER_TRAFFIC_SECRET_0" => {
                if secret.len() == 32 || secret.len() == 48 {
                    let fresh = !self.tls13.contains_key(&rand);
                    let e = self.tls13.entry(rand).or_default();
                    let mut buf = [0u8; 48];
                    buf[..secret.len()].copy_from_slice(&secret);
                    if label.starts_with("CLIENT") {
                        e.client_app = Some(buf);
                    } else {
                        e.server_app = Some(buf);
                    }
                    e.app_len = secret.len();
                    if fresh {
                        self.note_insert(rand);
                    }
                }
            }
            _ => {}
        }
    }

    /// Whether any secret (TLS 1.2 or 1.3) is held for this random —
    /// presence only, for diagnostics (v1.3.2).
    pub fn has_any(&self, client_random: &[u8; 32]) -> bool {
        self.tls13.contains_key(client_random) || self.tls12.contains_key(client_random)
    }

    fn tls13_for(&self, client_random: &[u8; 32]) -> Option<Tls13Secrets> {
        self.tls13.get(client_random).copied()
    }

    fn master_for(&self, client_random: &[u8; 32]) -> Option<[u8; 48]> {
        self.tls12.get(client_random).copied()
    }

    /// Every retained TLS 1.3 secret set, most recently inserted
    /// first — the candidate list for trial decryption (v1.3.5).
    fn tls13_candidates(&self) -> Vec<Tls13Secrets> {
        self.fifo
            .iter()
            .rev()
            .filter_map(|r| self.tls13.get(r).copied())
            .collect()
    }
}

/// How a successful decryption found its secrets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MatchKind {
    /// The key log held secrets under the stream's own client random.
    Direct,
    /// The stream's client random was not in the key log — ECH was
    /// accepted, so the browser logged the *inner* hello's random —
    /// but a retained secret set opened the records. AEAD tag
    /// verification makes a false hit cryptographically negligible,
    /// and the winning set is then bound to this stream's random so
    /// later retries take the direct path.
    Trial,
}

// ------------------------------------------------------- stream reassembly

/// One direction of a TCP stream, reassembled from captured segments.
/// The buffer starts at the first captured segment; if the capture began
/// mid-stream the bytes simply will not parse as a handshake.
pub struct TcpStream {
    base: Option<u32>,
    buf: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    pub capped: bool,
}

const STREAM_CAP: usize = 1 << 20; // 1 MiB per direction is plenty for a preview
/// Parked (out-of-order) segments are capped by count as well as by
/// bytes: each parked segment costs a Vec + a BTreeMap node on top of
/// its payload, and a peer controls how many tiny segments it sends.
/// Past this many fragments the stream is given up on (audit
/// 2026-11-08).
const MAX_PENDING_SEGS: usize = 8192;
/// Per-parked-segment overhead charged against STREAM_CAP so the byte
/// cap bites before segment bookkeeping dominates memory.
const SEG_OVERHEAD: usize = 64;

fn seq_diff(a: u32, b: u32) -> i64 {
    a.wrapping_sub(b) as i32 as i64
}

impl TcpStream {
    pub fn new() -> Self {
        TcpStream { base: None, buf: Vec::new(), pending: BTreeMap::new(), pending_bytes: 0, capped: false }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn push(&mut self, seq: u32, data: &[u8]) {
        if data.is_empty() || self.capped {
            return;
        }
        if self.base.is_none() {
            self.base = Some(seq);
        }
        self.insert(seq, data.to_vec());
        if self.buf.len() + self.pending_bytes > STREAM_CAP {
            self.capped = true;
        }
    }

    fn insert(&mut self, seq: u32, data: Vec<u8>) {
        let base = self.base.unwrap();
        let mut seg = (seq, data);
        // Iterative form of what used to be a recursive drain: a peer
        // could park thousands of 1-byte segments behind a 1-byte gap
        // and, by filling the gap, make the drain recurse once per
        // parked segment until the stack overflowed and took the
        // (elevated) monitoring process down — a remote blind spot,
        // the worst failure for this app (audit 2026-11-08). The loop
        // walks the same chain without growing the stack.
        loop {
            let (seq, mut data) = seg;
            let mut off = seq_diff(seq, base);
            if off < 0 {
                let cut = (-off) as usize;
                if cut >= data.len() {
                    return;
                }
                data.drain(..cut);
                off = 0;
            }
            let off = off as usize;
            let cur = self.buf.len();
            if off > cur {
                // Gap: park the segment until the missing bytes arrive.
                if self.pending.len() >= MAX_PENDING_SEGS {
                    self.capped = true;
                    self.pending.clear();
                    self.pending_bytes = 0;
                    return;
                }
                if !self.pending.contains_key(&seq) {
                    self.pending_bytes += data.len() + SEG_OVERHEAD;
                    self.pending.insert(seq, data);
                }
                return;
            }
            if off + data.len() > cur {
                let skip = cur - off;
                self.buf.extend_from_slice(&data[skip..]);
            }
            // Continue with the parked segment that just became
            // contiguous, if any, within this same call.
            let next = base.wrapping_add(self.buf.len() as u32);
            match self.pending.remove(&next) {
                Some(parked) => {
                    self.pending_bytes -= parked.len() + SEG_OVERHEAD;
                    seg = (next, parked);
                }
                None => return,
            }
        }
    }
}

// ------------------------------------------------------------------ crypto

#[derive(Clone, Copy, PartialEq)]
enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    fn len(&self) -> usize {
        match self {
            HashKind::Sha256 => 32,
            HashKind::Sha384 => 48,
        }
    }
    fn hmac(&self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            HashKind::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    m.update(p);
                }
                m.finalize().into_bytes().to_vec()
            }
            HashKind::Sha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    m.update(p);
                }
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn hkdf_expand(hash: HashKind, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = hash.hmac(prk, &[&input]);
        out.extend_from_slice(&t);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// RFC 8446 HKDF-Expand-Label.
fn expand_label(hash: HashKind, secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty context
    hkdf_expand(hash, secret, &info, len)
}

/// TLS 1.2 PRF (RFC 5246) with the suite's hash.
fn prf12(hash: HashKind, secret: &[u8], label: &str, seed: &[u8], len: usize) -> Vec<u8> {
    let mut label_seed = label.as_bytes().to_vec();
    label_seed.extend_from_slice(seed);
    let mut out = Vec::new();
    let mut a = hash.hmac(secret, &[&label_seed]);
    while out.len() < len {
        let mut parts: Vec<&[u8]> = vec![&a, &label_seed];
        let block = hash.hmac(secret, &parts);
        out.extend_from_slice(&block);
        parts.clear();
        a = hash.hmac(secret, &[&a]);
    }
    out.truncate(len);
    out
}

#[derive(Clone, Copy, PartialEq)]
enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha,
}

impl AeadKind {
    fn key_len(&self) -> usize {
        match self {
            AeadKind::Aes128Gcm => 16,
            AeadKind::Aes256Gcm => 32,
            AeadKind::Chacha => 32,
        }
    }
}

fn aead_open(kind: AeadKind, key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let payload = Payload { msg: ct, aad };
    match kind {
        AeadKind::Aes128Gcm => {
            let c = Aes128Gcm::new_from_slice(key).ok()?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload).ok()
        }
        AeadKind::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key).ok()?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload).ok()
        }
        AeadKind::Chacha => {
            let c = ChaCha20Poly1305::new_from_slice(key).ok()?;
            c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload).ok()
        }
    }
}

fn xor_seq(iv: &[u8], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv[..12]);
    let sb = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= sb[i];
    }
    nonce
}

// ----------------------------------------------------------------- records

struct Record<'a> {
    rtype: u8,
    version: [u8; 2],
    frag: &'a [u8],
}

fn iter_records(stream: &[u8]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 5 <= stream.len() {
        let rtype = stream[off];
        let len = u16::from_be_bytes([stream[off + 3], stream[off + 4]]) as usize;
        if off + 5 + len > stream.len() {
            break;
        }
        out.push(Record {
            rtype,
            version: [stream[off + 1], stream[off + 2]],
            frag: &stream[off + 5..off + 5 + len],
        });
        off += 5 + len;
    }
    out
}

/// The client random of the ClientHello starting a client stream,
/// for callers that need to know which key-log entry a stream wants.
pub fn stream_client_random(up: &[u8]) -> Option<[u8; 32]> {
    client_random(up)
}

/// Client random from a ClientHello at the start of the client stream.
fn client_random(up: &[u8]) -> Option<[u8; 32]> {
    if up.len() < 43 || up[0] != 0x16 || up[5] != 0x01 {
        return None;
    }
    arr32(&up[11..43])
}

struct ServerHello {
    random: [u8; 32],
    cipher: u16,
    tls13: bool,
}

fn server_hello(down: &[u8]) -> Option<ServerHello> {
    if down.len() < 47 || down[0] != 0x16 || down[5] != 0x02 {
        return None;
    }
    let random = arr32(&down[11..43])?;
    let sid_len = down[43] as usize;
    let coff = 44 + sid_len;
    if down.len() < coff + 5 {
        return None;
    }
    let cipher = u16::from_be_bytes([down[coff], down[coff + 1]]);
    // extensions (after cipher 2 + compression 1)
    let mut tls13 = false;
    let eoff = coff + 3;
    if down.len() >= eoff + 2 {
        let total = u16::from_be_bytes([down[eoff], down[eoff + 1]]) as usize;
        let mut off = eoff + 2;
        let end = (off + total).min(down.len());
        while off + 4 <= end {
            let etype = u16::from_be_bytes([down[off], down[off + 1]]);
            let elen = u16::from_be_bytes([down[off + 2], down[off + 3]]) as usize;
            if etype == 0x002b && elen >= 2 && off + 6 <= down.len() {
                let v = u16::from_be_bytes([down[off + 4], down[off + 5]]);
                tls13 = v == 0x0304;
            }
            off += 4 + elen;
        }
    }
    Some(ServerHello { random, cipher, tls13 })
}

fn suite13(cipher: u16) -> Option<(AeadKind, HashKind)> {
    match cipher {
        0x1301 => Some((AeadKind::Aes128Gcm, HashKind::Sha256)),
        0x1302 => Some((AeadKind::Aes256Gcm, HashKind::Sha384)),
        0x1303 => Some((AeadKind::Chacha, HashKind::Sha256)),
        _ => None,
    }
}

fn suite12(cipher: u16) -> Option<(AeadKind, HashKind)> {
    match cipher {
        // ECDHE / DHE / RSA with AES-GCM
        0xC02B | 0xC02F | 0x009C | 0x009E => Some((AeadKind::Aes128Gcm, HashKind::Sha256)),
        0xC02C | 0xC030 | 0x009D | 0x009F => Some((AeadKind::Aes256Gcm, HashKind::Sha384)),
        // ChaCha20-Poly1305 suites
        0xCCA8 | 0xCCA9 | 0xCCAA => Some((AeadKind::Chacha, HashKind::Sha256)),
        _ => None,
    }
}

/// Accumulates decrypted handshake bytes to spot the Finished message,
/// which is where TLS 1.3 switches from handshake to application keys.
struct HsScan {
    buf: Vec<u8>,
    finished: bool,
}

impl HsScan {
    fn new() -> Self {
        HsScan { buf: Vec::new(), finished: false }
    }
    fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        loop {
            if self.buf.len() < 4 {
                return;
            }
            let len = ((self.buf[1] as usize) << 16)
                | ((self.buf[2] as usize) << 8)
                | self.buf[3] as usize;
            if self.buf.len() < 4 + len {
                return;
            }
            if self.buf[0] == 20 {
                self.finished = true;
            }
            self.buf.drain(..4 + len);
        }
    }
}

// --------------------------------------------------------------- decryption

pub struct Decrypted {
    pub up: Vec<u8>,
    pub down: Vec<u8>,
}

/// Strip the TLS 1.3 inner content type (and zero padding) off a decrypted
/// record. Returns (content, inner_type).
fn strip_inner(plain: &[u8]) -> Option<(&[u8], u8)> {
    let mut end = plain.len();
    while end > 0 && plain[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let itype = plain[end - 1];
    Some((&plain[..end - 1], itype))
}

fn decrypt13_direction(
    records: &[Record],
    is_client: bool,
    kind: AeadKind,
    hash: HashKind,
    secrets: &Tls13Secrets,
) -> Vec<u8> {
    let (hs_secret, app_secret, slen) = if is_client {
        (secrets.client_hs, secrets.client_app, secrets.app_len)
    } else {
        (secrets.server_hs, secrets.server_app, secrets.app_len)
    };
    let _ = slen;
    let hs_len = if secrets.hs_len > 0 { secrets.hs_len } else { hash.len() };
    let app_len = if secrets.app_len > 0 { secrets.app_len } else { hash.len() };
    let _ = hs_len;
    let _ = app_len;
    // Precompute (key, iv) per phase.
    let phase_keys = |secret: Option<[u8; 48]>, n: usize| -> Option<(Vec<u8>, Vec<u8>)> {
        let s = secret?;
        let sec = &s[..n];
        Some((
            expand_label(hash, sec, "key", kind.key_len()),
            expand_label(hash, sec, "iv", 12),
        ))
    };
    let hs_keys = phase_keys(hs_secret, hs_len);
    let app_keys = phase_keys(app_secret, app_len);

    let mut out = Vec::new();
    // Phase 0 = plaintext (ClientHello / ServerHello first record),
    // 1 = handshake keys, 2 = application keys.
    let mut phase = 0u8;
    let mut seq: u64 = 0;
    let mut scan = HsScan::new();
    let mut app_success = false;
    let mut fails = 0u32;

    for (idx, rec) in records.iter().enumerate() {
        if rec.rtype == 20 {
            continue; // CCS: dummy plaintext in TLS 1.3, carries no data
        }
        if phase == 0 {
            if idx == 0 && rec.rtype == 22 {
                // ClientHello / ServerHello (plaintext).
                if hs_keys.is_some() {
                    phase = 1;
                } else if app_keys.is_some() {
                    phase = 2;
                } else {
                    break;
                }
                seq = 0;
                continue;
            }
            // Anything else before keys are set: give up on this direction.
            break;
        }
        let (key, iv) = match if phase == 1 { &hs_keys } else { &app_keys } {
            Some((k, v)) => (k.clone(), v.clone()),
            None => break,
        };
        if rec.rtype == 22 && phase == 1 {
            // HelloRetryRequest flight: a second, plaintext ClientHello
            // can appear before the encrypted handshake starts.
            continue;
        }
        if rec.rtype != 23 {
            break;
        }
        let mut aad = vec![0x17, 0x03, 0x03];
        aad.extend_from_slice(&(rec.frag.len() as u16).to_be_bytes());
        let nonce = xor_seq(&iv, seq);
        match aead_open(kind, &key, &nonce, &aad, rec.frag) {
            Some(plain) => {
                seq += 1;
                fails = 0;
                if let Some((content, itype)) = strip_inner(&plain) {
                    if itype == 23 {
                        out.extend_from_slice(content);
                        app_success = true;
                    } else if itype == 22 {
                        scan.feed(content);
                        if phase == 1 && scan.finished && app_keys.is_some() {
                            phase = 2;
                            seq = 0;
                        }
                    }
                }
            }
            None => {
                if phase == 2 && !app_success {
                    // Leftover handshake-phase record we could not read
                    // because the handshake secret is missing: it does not
                    // consume an application sequence number.
                    continue;
                }
                seq += 1;
                fails += 1;
                if fails > 16 {
                    break;
                }
            }
        }
    }
    let _ = app_success;
    out
}

fn decrypt12_direction(
    records: &[Record],
    is_client: bool,
    kind: AeadKind,
    key_block: &[u8],
    reset_seq: bool,
) -> Vec<u8> {
    let klen = kind.key_len();
    let (key, fixed_iv): (Vec<u8>, Vec<u8>) = match kind {
        AeadKind::Chacha => {
            // key block: client key(32), server key(32), client iv(12), server iv(12)
            if is_client {
                (key_block[0..32].to_vec(), key_block[64..76].to_vec())
            } else {
                (key_block[32..64].to_vec(), key_block[76..88].to_vec())
            }
        }
        _ => {
            // key block: client key, server key, client iv(4), server iv(4)
            let iv_off = 2 * klen;
            if is_client {
                (key_block[0..klen].to_vec(), key_block[iv_off..iv_off + 4].to_vec())
            } else {
                (key_block[klen..2 * klen].to_vec(), key_block[iv_off + 4..iv_off + 8].to_vec())
            }
        }
    };
    let mut out = Vec::new();
    let mut encrypted = false;
    let mut seq: u64 = 0; // sequence number for the *next* record overall
    let mut enc_seq: u64 = 0; // sequence within the encrypted epoch
    for rec in records {
        if !encrypted {
            if rec.rtype == 20 {
                encrypted = true;
                enc_seq = if reset_seq { 0 } else { seq + 1 };
            }
            seq += 1;
            continue;
        }
        let use_seq = enc_seq;
        enc_seq += 1;
        seq += 1;
        if rec.rtype != 23 && rec.rtype != 21 && rec.rtype != 22 {
            continue;
        }
        let frag = rec.frag;
        let (nonce, ct, plain_len) = match kind {
            AeadKind::Chacha => {
                if frag.len() < 16 {
                    continue;
                }
                let n = xor_seq(&fixed_iv, use_seq);
                (n, &frag[..], frag.len() - 16)
            }
            _ => {
                // GCM: explicit nonce (8) at the front of the fragment.
                if frag.len() < 8 + 16 {
                    continue;
                }
                let mut n = [0u8; 12];
                n[..4].copy_from_slice(&fixed_iv);
                n[4..].copy_from_slice(&frag[..8]);
                (n, &frag[8..], frag.len() - 8 - 16)
            }
        };
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&use_seq.to_be_bytes());
        aad.push(rec.rtype);
        aad.extend_from_slice(&rec.version);
        aad.extend_from_slice(&(plain_len as u16).to_be_bytes());
        if let Some(plain) = aead_open(kind, &key, &nonce, &aad, ct) {
            if rec.rtype == 23 {
                out.extend_from_slice(&plain);
            }
        }
    }
    out
}

/// Try to decrypt one flow's two reassembled streams. Returns the recovered
/// application bytes per direction when at least one direction yielded data.
pub fn try_decrypt(up: &[u8], down: &[u8], keys: &mut KeyLog) -> Option<Decrypted> {
    try_decrypt_stage(up, down, keys).1
}

/// Like `try_decrypt`, but also reports how far it got, as a short
/// stage tag. The engine records these in decrypt.log: "the key for
/// this flow never arrived" and "the key was there but AEAD yielded
/// nothing" are very different bugs, and from the UI alone they look
/// identical (field report, v1.2.11). Secret values are never part
/// of the report — presence/absence only.
pub fn try_decrypt_stage(
    up: &[u8],
    down: &[u8],
    keys: &mut KeyLog,
) -> (&'static str, Option<Decrypted>) {
    try_decrypt_match(up, down, keys).1
}

/// `try_decrypt_stage` plus, on success, how the secrets were found
/// (`MatchKind`). On a TLS 1.3 random miss, falls back to trial
/// decryption over the retained secret sets (v1.3.5): with ECH
/// accepted, Chromium logs the inner ClientHello's random, so the
/// outer random on the wire is never in the key log — but the logged
/// traffic secrets themselves open the records, because TLS 1.3
/// derives the record keys from the stored traffic secrets directly
/// and never re-consults the random. A candidate wins only when an
/// AEAD tag verifies, so a wrong candidate cannot produce output.
pub fn try_decrypt_match(
    up: &[u8],
    down: &[u8],
    keys: &mut KeyLog,
) -> (Option<MatchKind>, (&'static str, Option<Decrypted>)) {
    let Some(crand) = client_random(up) else {
        return (None, ("no-client-random", None));
    };
    let Some(sh) = server_hello(down) else {
        return (None, ("no-server-hello", None));
    };
    let up_records = iter_records(up);
    let down_records = iter_records(down);
    if up_records.is_empty() || down_records.is_empty() {
        return (None, ("no-complete-records", None));
    }
    if sh.tls13 {
        let Some((kind, hash)) = suite13(sh.cipher) else {
            return (None, ("tls13-unknown-suite", None));
        };
        if let Some(secrets) = keys.tls13_for(&crand) {
            let up_plain = decrypt13_direction(&up_records, true, kind, hash, &secrets);
            let down_plain = decrypt13_direction(&down_records, false, kind, hash, &secrets);
            if up_plain.is_empty() && down_plain.is_empty() {
                // The direct set has the random but opens nothing;
                // trialling other sets cannot fix a wrong-secret
                // case and would only burn time.
                return (None, ("tls13-secret-found-aead-empty", None));
            }
            return (Some(MatchKind::Direct), ("ok", Some(Decrypted { up: up_plain, down: down_plain })));
        }
        // Random miss: trial-decrypt with the retained sets, newest
        // first. The handshake phase decides cheaply — a wrong set
        // fails its first AEAD open in each direction and is dropped;
        // cap the work per attempt (a day's browsing can leave
        // thousands of sets, and this runs per undecrypted stream).
        const MAX_TRIAL: usize = 256;
        let candidates = keys.tls13_candidates();
        for secrets in candidates.iter().take(MAX_TRIAL) {
            let up_plain = decrypt13_direction(&up_records, true, kind, hash, secrets);
            let down_plain = decrypt13_direction(&down_records, false, kind, hash, secrets);
            if up_plain.is_empty() && down_plain.is_empty() {
                continue;
            }
            // Bind the winning set to this stream's random: later
            // retries (and the keyed= diagnostic) take the direct
            // path from here on.
            keys.tls13.insert(crand, *secrets);
            return (
                Some(MatchKind::Trial),
                ("ok-trial", Some(Decrypted { up: up_plain, down: down_plain })),
            );
        }
        return (None, ("tls13-no-secret-for-random", None));
    }
    // TLS 1.2 (or older): CLIENT_RANDOM -> master secret.
    let Some((kind, hash)) = suite12(sh.cipher) else {
        return (None, ("tls12-unknown-suite", None));
    };
    let Some(master) = keys.master_for(&crand) else {
        return (None, ("tls12-no-master-secret", None));
    };
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(&sh.random);
    seed.extend_from_slice(&crand);
    let kb_len = match kind {
        AeadKind::Chacha => 2 * 32 + 2 * 12,
        _ => 2 * kind.key_len() + 2 * 4,
    };
    let key_block = prf12(hash, &master, "key expansion", &seed, kb_len);
    let mut up_plain = decrypt12_direction(&up_records, true, kind, &key_block, true);
    let mut down_plain = decrypt12_direction(&down_records, false, kind, &key_block, true);
    if up_plain.is_empty() && down_plain.is_empty() {
        // Some stacks keep the record sequence counting across the CCS;
        // retry with the continuous numbering before giving up.
        up_plain = decrypt12_direction(&up_records, true, kind, &key_block, false);
        down_plain = decrypt12_direction(&down_records, false, kind, &key_block, false);
    }
    if up_plain.is_empty() && down_plain.is_empty() {
        return (None, ("tls12-aead-empty", None));
    }
    (Some(MatchKind::Direct), ("ok", Some(Decrypted { up: up_plain, down: down_plain })))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- helpers to build a synthetic TLS 1.3 session
    fn record(rtype: u8, frag: &[u8]) -> Vec<u8> {
        let mut v = vec![rtype, 0x03, 0x03];
        v.extend_from_slice(&(frag.len() as u16).to_be_bytes());
        v.extend_from_slice(frag);
        v
    }
    fn handshake_msg(t: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![t, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8];
        v.extend_from_slice(body);
        v
    }
    fn client_hello(random: &[u8; 32]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(random);
        body.extend_from_slice(&[0]); // session id: empty
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites: TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[1, 0]); // compression: null
        body.extend_from_slice(&[0, 0]); // extensions: none
        record(22, &handshake_msg(1, &body))
    }
    fn server_hello(random: &[u8; 32]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(random);
        body.extend_from_slice(&[0]); // session id: empty
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0]); // compression: null
        // extensions block (len 6): supported_versions = TLS 1.3
        body.extend_from_slice(&[0, 6, 0, 43, 0, 2, 0x03, 0x04]);
        record(22, &handshake_msg(2, &body))
    }
    fn seal_record(kind: AeadKind, secret: &[u8; 48], slen: usize, seq: u64, inner: &[u8], itype: u8) -> Vec<u8> {
        let hash = HashKind::Sha256;
        let key = expand_label(hash, &secret[..slen], "key", kind.key_len());
        let iv = expand_label(hash, &secret[..slen], "iv", 12);
        let mut plain = inner.to_vec();
        plain.push(itype);
        let frag_len = plain.len() + 16;
        let mut aad = vec![0x17, 0x03, 0x03];
        aad.extend_from_slice(&(frag_len as u16).to_be_bytes());
        let mut ivb = [0u8; 12];
        ivb.copy_from_slice(&iv);
        let nonce = xor_seq(&ivb, seq);
        let payload = aes_gcm::aead::Payload { msg: &plain, aad: &aad };
        let ct = match kind {
            AeadKind::Aes128Gcm => Aes128Gcm::new_from_slice(&key)
                .unwrap()
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
                .unwrap(),
            _ => unreachable!(),
        };
        record(23, &ct)
    }

    /// Build a full synthetic session for the given logged random:
    /// ClientHello, ServerHello, encrypted server Finished, one app
    /// record each way. Returns (up, down, secrets).
    fn synth_session(logged_random: &[u8; 32]) -> (Vec<u8>, Vec<u8>, Tls13Secrets) {
        let crand = *logged_random;
        let srand = [0x77u8; 32];
        let secrets = Tls13Secrets {
            client_hs: Some([0x11; 48]),
            server_hs: Some([0x22; 48]),
            client_app: Some([0x33; 48]),
            server_app: Some([0x44; 48]),
            hs_len: 32,
            app_len: 32,
        };
        let finished = handshake_msg(20, &[0xAB; 32]);
        let down = [
            server_hello(&srand),
            seal_record(AeadKind::Aes128Gcm, &secrets.server_hs.unwrap(), 32, 0, &finished, 22),
            seal_record(AeadKind::Aes128Gcm, &secrets.server_app.unwrap(), 32, 0, b"hello down", 23),
        ]
        .concat();
        // A real client's first application record precedes its
        // Finished in flight order only on the wire timeline; in the
        // reassembled up-stream the client Finished (handshake keys,
        // seq 0) comes before application data (app keys, seq 0),
        // which is what decrypt13_direction's phase machine expects.
        let cfinished = handshake_msg(20, &[0xCD; 32]);
        let up = [
            client_hello(&crand),
            seal_record(AeadKind::Aes128Gcm, &secrets.client_hs.unwrap(), 32, 0, &cfinished, 22),
            seal_record(AeadKind::Aes128Gcm, &secrets.client_app.unwrap(), 32, 0, b"hello up", 23),
        ]
        .concat();
        (up, down, secrets)
    }

    fn keylog_with(random: &[u8; 32], s: &Tls13Secrets) -> KeyLog {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let r = hex(random);
        let text = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {r} {}\nSERVER_HANDSHAKE_TRAFFIC_SECRET {r} {}\nCLIENT_TRAFFIC_SECRET_0 {r} {}\nSERVER_TRAFFIC_SECRET_0 {r} {}\n",
            hex(&s.client_hs.unwrap()[..32]),
            hex(&s.server_hs.unwrap()[..32]),
            hex(&s.client_app.unwrap()[..32]),
            hex(&s.server_app.unwrap()[..32]),
        );
        let path = std::env::temp_dir().join(format!(
            "pk-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, text).unwrap();
        let mut kl = KeyLog::new();
        kl.refresh(&path);
        let _ = std::fs::remove_file(&path);
        kl
    }

    #[test]
    fn direct_match_by_random() {
        let (up, down, secrets) = synth_session(&[0x42; 32]);
        let mut kl = keylog_with(&[0x42; 32], &secrets);
        let (m, (stage, dec)) = try_decrypt_match(&up, &down, &mut kl);
        assert_eq!(m, Some(MatchKind::Direct));
        assert_eq!(stage, "ok");
        let dec = dec.expect("decrypted");
        assert_eq!(dec.up, b"hello up");
        assert_eq!(dec.down, b"hello down");
    }

    /// The ECH case (field logs, Nov 2026): the wire ClientHello
    /// carries the OUTER random; the key log holds the secrets under
    /// the INNER random. Trial decryption must recover the session
    /// and bind the set to the outer random.
    #[test]
    fn trial_match_when_random_differs() {
        let inner = [0x99u8; 32];
        let (mut up, down, secrets) = synth_session(&inner);
        // Rewrite the ClientHello random to the "outer" one.
        let outer = [0x55u8; 32];
        let pos = up.windows(32).position(|w| w == inner).unwrap();
        up[pos..pos + 32].copy_from_slice(&outer);
        let mut kl = keylog_with(&inner, &secrets);
        let (m, (stage, dec)) = try_decrypt_match(&up, &down, &mut kl);
        assert_eq!(kl.tls13_candidates().len(), 1, "candidates: key log must hold the set");
        assert_eq!(m, Some(MatchKind::Trial), "stage was {stage}");
        assert_eq!(stage, "ok-trial");
        let dec = dec.expect("decrypted by trial");
        assert_eq!(dec.up, b"hello up");
        assert_eq!(dec.down, b"hello down");
        // Bound now: the direct path finds it too.
        assert!(kl.tls13_for(&outer).is_some());
    }

    /// A key log full of unrelated sessions must not yield output.
    #[test]
    fn trial_no_false_positive() {
        let (up, down, _secrets) = synth_session(&[0x42; 32]);
        let other = Tls13Secrets {
            client_hs: Some([0x91; 48]),
            server_hs: Some([0x92; 48]),
            client_app: Some([0x93; 48]),
            server_app: Some([0x94; 48]),
            hs_len: 32,
            app_len: 32,
        };
        let mut kl = keylog_with(&[0x24; 32], &other);
        let (m, (stage, dec)) = try_decrypt_match(&up, &down, &mut kl);
        assert_eq!(m, None);
        assert_eq!(stage, "tls13-no-secret-for-random");
        assert!(dec.is_none());
    }
}

