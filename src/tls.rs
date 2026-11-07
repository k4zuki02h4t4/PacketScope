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
    offset: u64,
    partial: String,
}

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
    pub fn refresh(&mut self, path: &Path) {
        let Ok(meta) = std::fs::metadata(path) else { return };
        if meta.len() < self.offset {
            self.offset = 0; // rotated / truncated: start over
            self.partial.clear();
        }
        if meta.len() == self.offset {
            return;
        }
        let Ok(bytes) = std::fs::read(path) else { return };
        if (bytes.len() as u64) < self.offset {
            return;
        }
        let new = &bytes[self.offset as usize..];
        self.offset = bytes.len() as u64;
        let text = format!("{}{}", self.partial, String::from_utf8_lossy(new));
        let mut lines: Vec<&str> = text.split('\n').collect();
        self.partial = lines.pop().unwrap_or("").to_string();
        for line in lines {
            self.parse_line(line.trim());
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
                    let mut ms = [0u8; 48];
                    ms.copy_from_slice(&secret);
                    self.tls12.insert(rand, ms);
                }
            }
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" | "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                if secret.len() == 32 || secret.len() == 48 {
                    let e = self.tls13.entry(rand).or_default();
                    let mut buf = [0u8; 48];
                    buf[..secret.len()].copy_from_slice(&secret);
                    if label.starts_with("CLIENT") {
                        e.client_hs = Some(buf);
                    } else {
                        e.server_hs = Some(buf);
                    }
                    e.hs_len = secret.len();
                }
            }
            "CLIENT_TRAFFIC_SECRET_0" | "SERVER_TRAFFIC_SECRET_0" => {
                if secret.len() == 32 || secret.len() == 48 {
                    let e = self.tls13.entry(rand).or_default();
                    let mut buf = [0u8; 48];
                    buf[..secret.len()].copy_from_slice(&secret);
                    if label.starts_with("CLIENT") {
                        e.client_app = Some(buf);
                    } else {
                        e.server_app = Some(buf);
                    }
                    e.app_len = secret.len();
                }
            }
            _ => {}
        }
    }

    fn tls13_for(&self, client_random: &[u8; 32]) -> Option<Tls13Secrets> {
        self.tls13.get(client_random).copied()
    }

    fn master_for(&self, client_random: &[u8; 32]) -> Option<[u8; 48]> {
        self.tls12.get(client_random).copied()
    }
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
        let mut off = seq_diff(seq, base);
        let mut data = data;
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
            if !self.pending.contains_key(&seq) {
                self.pending_bytes += data.len();
                self.pending.insert(seq, data);
            }
            return;
        }
        if off + data.len() > cur {
            let skip = cur - off;
            self.buf.extend_from_slice(&data[skip..]);
        }
        // Drain parked segments that are now contiguous.
        loop {
            let next = base.wrapping_add(self.buf.len() as u32);
            let Some(seg) = self.pending.remove(&next) else { break };
            self.pending_bytes -= seg.len();
            self.insert(next, seg);
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
pub fn try_decrypt(up: &[u8], down: &[u8], keys: &KeyLog) -> Option<Decrypted> {
    let crand = client_random(up)?;
    let sh = server_hello(down)?;
    let up_records = iter_records(up);
    let down_records = iter_records(down);
    if up_records.is_empty() || down_records.is_empty() {
        return None;
    }
    if sh.tls13 {
        let (kind, hash) = suite13(sh.cipher)?;
        let secrets = keys.tls13_for(&crand)?;
        let up_plain = decrypt13_direction(&up_records, true, kind, hash, &secrets);
        let down_plain = decrypt13_direction(&down_records, false, kind, hash, &secrets);
        if up_plain.is_empty() && down_plain.is_empty() {
            return None;
        }
        return Some(Decrypted { up: up_plain, down: down_plain });
    }
    // TLS 1.2 (or older): CLIENT_RANDOM -> master secret.
    let (kind, hash) = suite12(sh.cipher)?;
    let master = keys.master_for(&crand)?;
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
        return None;
    }
    Some(Decrypted { up: up_plain, down: down_plain })
}
