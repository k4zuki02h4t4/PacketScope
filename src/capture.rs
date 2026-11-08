//! Packet capture backends.
//!
//! The `npcap` backend uses libpcap (Npcap on Windows) and feeds raw
//! frames to the engine. Before touching pcap it (a) points the DLL
//! search path at the Npcap install directory — without WinPcap
//! compatible mode wpcap.dll lives in System32\Npcap and is otherwise
//! not found — and (b) tries to start the npcap driver service.
//! Every outcome is reported to the engine as a CaptureStatus so the UI
//! can show whether capture is actually running (v2 failed silently,
//! which looked like "no content anywhere").

use crate::engine::EngineEvent;
use std::sync::mpsc::{SyncSender, TrySendError};

#[cfg(feature = "npcap")]
pub fn run_pcap(
    tx: SyncSender<EngineEvent>,
    queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use pcap::{Capture, Device};

    #[cfg(windows)]
    prepare_npcap();

    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            let _ = tx.send(EngineEvent::CaptureStatus(format!(
                "キャプチャ停止: Npcap のデバイス一覧が取得できません（{e}）。接続表モードで表示しています"
            )));
            return;
        }
    };
    if devices.is_empty() {
        let _ = tx.send(EngineEvent::CaptureStatus(
            "キャプチャ停止: ネットワークデバイスが見つかりません。接続表モードで表示しています".into(),
        ));
        return;
    }
    let mut handles = Vec::new();
    let mut last_err = String::new();
    for dev in devices {
        match Capture::from_device(dev)
            .and_then(|c| c.promisc(false).snaplen(65535).timeout(200).open())
        {
            Ok(c) => handles.push(c),
            Err(e) => last_err = e.to_string(),
        }
    }
    if handles.is_empty() {
        let _ = tx.send(EngineEvent::CaptureStatus(format!(
            "キャプチャ停止: デバイスを開けませんでした（{last_err}）。Npcap ドライバが起動していない可能性があります。接続表モードで表示しています"
        )));
        return;
    }
    let _ = tx.send(EngineEvent::CaptureStatus(format!(
        "キャプチャ中（Npcap）: {} デバイスを監視しています",
        handles.len()
    )));
    // One thread per device keeps a busy interface from starving the rest.
    let mut threads = Vec::new();
    for mut cap in handles {
        let t = tx.clone();
        let queued_dev = queued_bytes.clone();
        let linktype = cap.get_datalink().0;
        threads.push(std::thread::spawn(move || loop {
            match cap.next_packet() {
                Ok(pkt) => {
                    let data = pkt.data.to_vec();
                    let len = data.len();
                    // Bounded queue, in bytes as well as in frame
                    // count: under a packet flood we drop frames
                    // instead of growing memory without limit.
                    if queued_dev.load(std::sync::atomic::Ordering::Relaxed) + len
                        > crate::engine::MAX_QUEUED_FRAME_BYTES
                    {
                        continue;
                    }
                    queued_dev.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                    match t.try_send(EngineEvent::Frame(data, linktype)) {
                        Err(TrySendError::Disconnected(_)) => return,
                        Err(_) => {
                            queued_dev
                                .fetch_sub(len, std::sync::atomic::Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }));
    }
    for t in threads {
        let _ = t.join();
    }
}

/// Point the DLL loader at the Npcap directory and try to start the
/// driver service. Best effort; failures show up as capture status.
#[cfg(all(windows, feature = "npcap"))]
fn prepare_npcap() {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    // Registry: HKLM\SOFTWARE\Npcap (and WOW6432Node) default value is the
    // install directory, e.g. C:\Program Files\Npcap. The DLLs live in
    // <dir> and in %SystemRoot%\System32\Npcap.
    for key in ["SOFTWARE\\Npcap", "SOFTWARE\\WOW6432Node\\Npcap"] {
        if let Some(dir) = crate::system_setup::read_registry_sz_local_machine(key, "") {
            let wide: Vec<u16> = OsStr::new(&dir).encode_wide().chain(Some(0)).collect();
            unsafe {
                windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(wide.as_ptr());
            }
            break;
        }
    }
    // The pcap DLLs also land in System32\Npcap in recent installers.
    if let Some(sysroot) = std::env::var_os("SystemRoot") {
        let sub = std::path::PathBuf::from(&sysroot).join("System32").join("Npcap");
        if sub.join("wpcap.dll").exists() {
            let wide: Vec<u16> = OsStr::new(&sub).encode_wide().chain(Some(0)).collect();
            unsafe {
                windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW(wide.as_ptr());
            }
        }
    }
    // Start the driver service if it is stopped (we run as admin).
    // Absolute System32 path: a bare "sc.exe" would be resolved with
    // this process's own directory first (audit 2026-11-08).
    use std::os::windows::process::CommandExt;
    for svc in ["npcap", "npf"] {
        let _ = std::process::Command::new(crate::system_setup::system32_tool("sc.exe"))
            .args(["start", svc])
            .creation_flags(0x0800_0000)
            .output();
    }
}

#[cfg(not(feature = "npcap"))]
pub fn run_pcap(
    _tx: SyncSender<EngineEvent>,
    _queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
}
