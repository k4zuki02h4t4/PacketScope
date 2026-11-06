//! PacketScope setup: a single-file installer (capture-only app).
//!
//! The application binary is embedded (staged into installer-assets/ by
//! the build script before this binary is compiled) and installed to
//! C:\Program Files\PacketScope with Start Menu / Desktop shortcuts and an
//! Add/Remove Programs entry. If Npcap is missing, the OFFICIAL Npcap
//! installer is downloaded from npcap.com and launched — Npcap's free
//! license forbids redistributing (bundling) the driver itself and
//! reserves silent installs for OEM licensees, so this is the closest
//! legal equivalent of "bundled": one extra click-through inside setup.
//! PacketScope is capture-only: setup changes no proxy or certificate
//! settings.

#![cfg_attr(windows, windows_subsystem = "windows")]

use netwatch::system_setup::{confirm_box, info_box};
use std::path::PathBuf;

static PAYLOAD: &[u8] = include_bytes!("../../installer-assets/packetscope.exe");

const NPCAP_URL: &str = "https://npcap.com/dist/npcap-1.90.exe";

/// Append one line to packetscope-setup.log *next to this exe*
/// (falling back to %TEMP% when that directory is not writable).
/// The installer is a GUI-subsystem binary, so without this a
/// failure midway is invisible; the log records every stage (with
/// COM HRESULTs) so the exact stopping point can be identified
/// from one run.
pub fn log_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("packetscope-setup.log");
        }
    }
    std::env::var_os("TEMP").map(PathBuf::from).unwrap_or_default().join("packetscope-setup.log")
}

pub fn log_line(msg: &str) {
    use std::io::Write;
    let try_open = |p: &PathBuf| {
        std::fs::OpenOptions::new().create(true).append(true).open(p).ok()
    };
    let primary = log_path();
    if let Some(mut f) = try_open(&primary) {
        let _ = writeln!(f, "{msg}");
        return;
    }
    if let Some(tmp) = std::env::var_os("TEMP") {
        if let Some(mut f) = try_open(&PathBuf::from(tmp).join("packetscope-setup.log")) {
            let _ = writeln!(f, "{msg}");
        }
    }
}

fn log_reset() {
    let _ = std::fs::remove_file(log_path());
    if let Some(tmp) = std::env::var_os("TEMP") {
        let _ = std::fs::remove_file(PathBuf::from(tmp.clone()).join("packetscope-setup.log"));
        let _ = std::fs::remove_file(PathBuf::from(tmp).join("PacketScope-setup.log"));
    }
}

fn main() {
    log_reset();
    log_line("setup: start");
    if !confirm_box(
        "PacketScope をインストールしますか？\n\n・C:\\Program Files\\PacketScope に本体を配置します\n・Npcap が無い場合は公式サイトからダウンロードしてインストールします（Npcap 本体の再配布はライセンスで禁止されているため同梱はできません）\n・PacketScope はパケットキャプチャ専用です。プロキシや証明書の設定は変更しません",
        "PacketScope セットアップ",
    ) {
        log_line("setup: cancelled at confirm dialog");
        return;
    }
    log_line("setup: confirmed, installing");
    if let Err(e) = install() {
        log_line(&format!("install: FAILED: {e}"));
        info_box(&format!("インストールに失敗しました。\n\n{e}\n\n詳細は packetscope-setup.exe と同じフォルダの packetscope-setup.log に記録されています。"), "PacketScope セットアップ");
        return;
    }
    log_line("setup: done");
    info_box(
        "インストールが完了しました。\nスタートメニューまたはデスクトップの「PacketScope」から起動できます。",
        "PacketScope セットアップ",
    );
}

fn install() -> Result<(), String> {
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .ok_or("ProgramFiles が取得できません")?;
    let dir = program_files.join("PacketScope");
    std::fs::create_dir_all(&dir).map_err(|e| format!("フォルダ作成に失敗: {e}"))?;
    log_line(&format!("install: dir ready: {}", dir.to_string_lossy()));
    let app = dir.join("packetscope.exe");
    std::fs::write(&app, PAYLOAD).map_err(|e| format!("本体の配置に失敗: {e}"))?;
    log_line(&format!("install: app written ({} bytes)", PAYLOAD.len()));
    // The uninstaller is the same binary under the uninstall.exe name;
    // the app switches to uninstall mode by its file name.
    std::fs::write(dir.join("uninstall.exe"), PAYLOAD)
        .map_err(|e| format!("アンインストーラの配置に失敗: {e}"))?;
    log_line("install: uninstall.exe written");

    make_shortcuts(&app);
    log_line("install: shortcuts step finished");
    register_uninstall(&dir);
    log_line("install: uninstall entry registered");

    let npcap = npcap_present();
    log_line(&format!("install: npcap_present = {npcap}"));
    if !npcap {
        install_npcap()?;
        log_line("install: npcap install step finished");
    }
    Ok(())
}

fn npcap_present() -> bool {
    // wpcap.dll lands in System32 (and SysWOW64) when Npcap is installed.
    let sysroot = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    sysroot.join("System32").join("wpcap.dll").exists()
        || sysroot.join("System32").join("Npcap").join("wpcap.dll").exists()
}

fn install_npcap() -> Result<(), String> {
    info_box(
        "パケット監視に必要な Npcap が見つかりませんでした。\n公式サイト（npcap.com）から Npcap 1.90 のインストーラをダウンロードして起動します。表示される画面でそのままインストールしてください（WinPcap 互換モードは任意です）。",
        "PacketScope セットアップ",
    );
    let tmp = std::env::var_os("TEMP")
        .map(PathBuf::from)
        .ok_or("TEMP が取得できません")?;
    let installer = tmp.join("npcap-1.90.exe");
    let ok = std::process::Command::new("curl.exe")
        .args(["-L", "-f", "-o", &installer.to_string_lossy(), NPCAP_URL])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    log_line(&format!("npcap: download ok = {ok}"));
    if !ok {
        return Err(
            "Npcap のダウンロードに失敗しました。https://npcap.com/ から手動でインストールしてから、PacketScope を起動してください。"
                .into(),
        );
    }
    // The downloaded installer runs elevated: verify its Authenticode
    // signature first, and that the signer is the expected publisher.
    let sig_ok = authenticode_ok(&installer, "Nmap");
    log_line(&format!("npcap: authenticode ok = {sig_ok}"));
    if !sig_ok {
        let _ = std::fs::remove_file(&installer);
        return Err(
            "ダウンロードした Npcap インストーラの署名（Authenticode）を検証できませんでした。安全のため実行を中止しました。https://npcap.com/ から手動で入手してください。"
                .into(),
        );
    }
    let status = std::process::Command::new(&installer)
        .status()
        .map_err(|e| format!("Npcap インストーラの起動に失敗: {e}"))?;
    if !status.success() && !npcap_present() {
        return Err("Npcap のインストールが確認できませんでした".into());
    }
    Ok(())
}

fn register_uninstall(dir: &std::path::Path) {
    let uninstall = dir.join("uninstall.exe");
    let base = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketScope";
    let pairs: [(&str, &str, &str); 5] = [
        ("DisplayName", "REG_SZ", "PacketScope"),
        ("DisplayVersion", "REG_SZ", "1.0.0"),
        ("Publisher", "REG_SZ", "PacketScope"),
        ("InstallLocation", "REG_SZ", &dir.to_string_lossy()),
        ("UninstallString", "REG_SZ", &format!("\"{}\"", uninstall.to_string_lossy())),
    ];
    for (name, ty, value) in pairs {
        let _ = std::process::Command::new("reg")
            .args(["add", base, "/v", name, "/t", ty, "/d", value, "/f"])
            .status();
    }
}

fn make_shortcuts(app: &std::path::Path) {
    #[cfg(windows)]
    unsafe {
        win_shortcut::create(app);
    }
}

#[cfg(windows)]
mod win_shortcut {
    //! Shortcut creation through IShellLinkW. windows-sys does not ship
    //! the interface vtables, so they are declared here directly (the
    //! method order is the documented COM interface layout).
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use windows_sys::core::{GUID, HRESULT, PCWSTR};
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::UI::Shell::ShellLink;

    type IUnknownPtr = *mut c_void;

    #[repr(C)]
    struct IShellLinkWVtbl {
        query_interface: unsafe extern "system" fn(IUnknownPtr, *const GUID, *mut IUnknownPtr) -> HRESULT,
        add_ref: unsafe extern "system" fn(IUnknownPtr) -> u32,
        release: unsafe extern "system" fn(IUnknownPtr) -> u32,
        get_path: unsafe extern "system" fn(IUnknownPtr, *mut u16, i32, *mut c_void, u32) -> HRESULT,
        get_id_list: unsafe extern "system" fn(IUnknownPtr, *mut *mut c_void) -> HRESULT,
        set_id_list: unsafe extern "system" fn(IUnknownPtr, *const c_void) -> HRESULT,
        get_description: unsafe extern "system" fn(IUnknownPtr, *mut u16, i32) -> HRESULT,
        set_description: unsafe extern "system" fn(IUnknownPtr, PCWSTR) -> HRESULT,
        get_working_directory: unsafe extern "system" fn(IUnknownPtr, *mut u16, i32) -> HRESULT,
        set_working_directory: unsafe extern "system" fn(IUnknownPtr, PCWSTR) -> HRESULT,
        get_arguments: unsafe extern "system" fn(IUnknownPtr, *mut u16, i32) -> HRESULT,
        set_arguments: unsafe extern "system" fn(IUnknownPtr, PCWSTR) -> HRESULT,
        get_hotkey: unsafe extern "system" fn(IUnknownPtr, *mut u16) -> HRESULT,
        set_hotkey: unsafe extern "system" fn(IUnknownPtr, u16) -> HRESULT,
        get_show_cmd: unsafe extern "system" fn(IUnknownPtr, *mut i32) -> HRESULT,
        set_show_cmd: unsafe extern "system" fn(IUnknownPtr, i32) -> HRESULT,
        get_icon_location: unsafe extern "system" fn(IUnknownPtr, *mut u16, i32, *mut i32) -> HRESULT,
        set_icon_location: unsafe extern "system" fn(IUnknownPtr, PCWSTR, i32) -> HRESULT,
        set_relative_path: unsafe extern "system" fn(IUnknownPtr, PCWSTR, u32) -> HRESULT,
        resolve: unsafe extern "system" fn(IUnknownPtr, HWND, u32) -> HRESULT,
        set_path: unsafe extern "system" fn(IUnknownPtr, PCWSTR) -> HRESULT,
    }

    #[repr(C)]
    struct IPersistFileVtbl {
        query_interface: unsafe extern "system" fn(IUnknownPtr, *const GUID, *mut IUnknownPtr) -> HRESULT,
        add_ref: unsafe extern "system" fn(IUnknownPtr) -> u32,
        release: unsafe extern "system" fn(IUnknownPtr) -> u32,
        get_class_id: unsafe extern "system" fn(IUnknownPtr, *mut GUID) -> HRESULT,
        is_dirty: unsafe extern "system" fn(IUnknownPtr) -> HRESULT,
        load: unsafe extern "system" fn(IUnknownPtr, PCWSTR, u32) -> HRESULT,
        save: unsafe extern "system" fn(IUnknownPtr, PCWSTR, i32) -> HRESULT,
        save_completed: unsafe extern "system" fn(IUnknownPtr, PCWSTR) -> HRESULT,
        get_cur_file: unsafe extern "system" fn(IUnknownPtr, *mut *mut u16) -> HRESULT,
    }

    // IID_IShellLinkW {000214F9-0000-0000-C000-000000000046}
    const IID_ISHELLLINKW: GUID = GUID::from_u128(0x000214F9_0000_0000_C000_000000000046);
    // IID_IPersistFile {0000010B-0000-0000-C000-000000000046}
    const IID_IPERSISTFILE: GUID = GUID::from_u128(0x0000010B_0000_0000_C000_000000000046);
    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    pub unsafe fn create(app: &Path) {
        crate::log_line("shortcut: create start");
        CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED as u32);
        let mut link: IUnknownPtr = null_mut();
        let hr_create = CoCreateInstance(
            &ShellLink,
            null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ISHELLLINKW,
            &mut link,
        );
        crate::log_line(&format!("shortcut: CoCreateInstance hr=0x{hr_create:08x}"));
        if hr_create < 0 || link.is_null() {
            crate::log_line("shortcut: ABORT (no IShellLink)");
            return;
        }
        let vtbl = *(link as *const *const IShellLinkWVtbl);
        ((*vtbl).set_path)(link, wide(&app.to_string_lossy()).as_ptr());
        ((*vtbl).set_description)(link, wide("PacketScope - パケットキャプチャ").as_ptr());
        if let Some(dir) = app.parent() {
            ((*vtbl).set_working_directory)(link, wide(&dir.to_string_lossy()).as_ptr());
        }
        // "Run as administrator" on the shortcut itself is applied
        // after each Save by ensure_runas_flag() (direct .lnk patch).
        // An earlier version also set it through IShellLinkDataList
        // (SLDF_RUNAS_USER); the setup died inside that call on a
        // real machine (log stopped right after a successful
        // QueryInterface for the data list), so that route was
        // removed — the byte patch sets the same flag on its own.
        let mut persist: IUnknownPtr = null_mut();
        let hr_pf = ((*vtbl).query_interface)(link, &IID_IPERSISTFILE, &mut persist);
        crate::log_line(&format!("shortcut: QI PersistFile hr=0x{hr_pf:08x}"));
        if hr_pf >= 0 && !persist.is_null() {
            let pvtbl = *(persist as *const *const IPersistFileVtbl);
            for dest in shortcut_destinations() {
                let hr_save = ((*pvtbl).save)(persist, wide(&dest.to_string_lossy()).as_ptr(), 1);
                let patched = hr_save >= 0 && ensure_runas_flag(&dest);
                crate::log_line(&format!(
                    "shortcut: Save hr=0x{hr_save:08x} runas_patched={patched} dest={}",
                    dest.to_string_lossy()
                ));
            }
            ((*pvtbl).release)(persist);
        }
        ((*vtbl).release)(link);
        crate::log_line("shortcut: create finished");
    }

    /// Set the shortcut's RunAsUser flag in the saved .lnk: the
    /// header is a fixed 0x4C-byte layout whose LinkFlags field sits
    /// at offset 0x14, and RunAsUser (0x2000) is bit 0x20 of the
    /// byte at 0x15. Doing it as a file patch (the same technique
    /// scripting tools use) avoids the shell data-list interface.
    fn ensure_runas_flag(lnk: &Path) -> bool {
        if let Ok(mut bytes) = std::fs::read(lnk) {
            // Header signature 0x4C at 0x00 and LinkFlags at 0x14.
            if bytes.len() > 0x16 && bytes[0] == 0x4C && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 {
                bytes[0x15] |= 0x20;
                return std::fs::write(lnk, bytes).is_ok();
            }
        }
        false
    }

    fn shortcut_destinations() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(appdata) = std::env::var_os("APPDATA") {
            out.push(
                PathBuf::from(appdata)
                    .join("Microsoft\\Windows\\Start Menu\\Programs")
                    .join("PacketScope.lnk"),
            );
        }
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            out.push(PathBuf::from(profile).join("Desktop").join("PacketScope.lnk"));
        }
        out
    }
}

/// Verify an executable's Authenticode signature before running it
/// elevated. Requires a valid signature chained to a trusted root; when
/// the signer subject can be read, it must contain `expected_signer`.
#[cfg(windows)]
fn authenticode_ok(path: &std::path::Path, expected_signer: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::CertGetNameStringW;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = wide.as_ptr();
        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file_info };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(null_mut(), &mut action, &mut data as *mut _ as *mut _);
        let mut signer_ok = true;
        if status == 0 && !data.hWVTStateData.is_null() {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut buf = vec![0u16; 256];
                        let n = CertGetNameStringW(
                            cert,
                            4, // CERT_NAME_SIMPLE_DISPLAY_TYPE
                            0,
                            null(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        );
                        if n > 1 {
                            let name =
                                String::from_utf16_lossy(&buf[..(n as usize).min(buf.len()) - 1]);
                            signer_ok = name.contains(expected_signer);
                        }
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut action2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WinVerifyTrust(null_mut(), &mut action2, &mut data as *mut _ as *mut _);
        status == 0 && signer_ok
    }
}

#[cfg(not(windows))]
fn authenticode_ok(_path: &std::path::Path, _expected_signer: &str) -> bool {
    true
}
