//! Small Windows helpers shared by the app (uninstall mode) and the
//! setup binary: message boxes for user confirmation, and a read-only
//! registry lookup used to locate the Npcap install directory.

/// Small message-box helpers shared by the app (uninstall mode) and the
/// setup binary. `confirm` returns true when the user picks OK/Yes.
#[cfg(windows)]
pub fn info_box(text: &str, caption: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    let w = |s: &str| OsStr::new(s).encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            w(text).as_ptr(),
            w(caption).as_ptr(),
            0x0000_0040, // MB_ICONINFORMATION
        );
    }
}

#[cfg(windows)]
pub fn confirm_box(text: &str, caption: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    let w = |s: &str| OsStr::new(s).encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            w(text).as_ptr(),
            w(caption).as_ptr(),
            0x0000_0001 | 0x0000_0020, // MB_OKCANCEL | MB_ICONQUESTION
        ) == 1 // IDOK
    }
}

#[cfg(not(windows))]
pub fn info_box(_text: &str, _caption: &str) {}

#[cfg(not(windows))]
pub fn confirm_box(_text: &str, _caption: &str) -> bool {
    false
}

/// Absolute path to a tool in %SystemRoot%\System32. Elevated
/// processes should never spawn system tools by bare name: the
/// loader searches the spawning executable's own directory before
/// System32, so a same-named file planted next to the executable
/// would run with our privileges (audit 2026-11-08).
pub fn system32_tool(name: &str) -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\Windows"));
    root.join("System32").join(name)
}

/// A short unpredictable tag from the OS-seeded hash state, the
/// current time and this process's id — used by the app and the
/// setup binary to make temporary file names unguessable, so a
/// same-user process cannot pre-plant or predict the file an
/// elevated process is about to run (audit 2026-11-08).
pub fn random_tag() -> String {
    use std::hash::{BuildHasher, Hasher};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let v = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
        ^ nanos as u64
        ^ ((std::process::id() as u64) << 32);
    format!("{v:016x}")
}

/// Read a string value from HKEY_LOCAL_MACHINE (used to locate the
/// Npcap install directory). `value_name` may be "" for the default value.
#[cfg(windows)]
pub fn read_registry_sz_local_machine(key_path: &str, value_name: &str) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    let wide = |s: &str| OsStr::new(s).encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    unsafe {
        let mut hk: HKEY = null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(key_path).as_ptr(),
            0,
            KEY_READ,
            &mut hk,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        let mut ty = 0u32;
        let rc = RegQueryValueExW(
            hk,
            wide(value_name).as_ptr(),
            null_mut(),
            &mut ty,
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        );
        RegCloseKey(hk);
        if rc != ERROR_SUCCESS || len < 2 {
            return None;
        }
        let chars = (len as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buf[..chars]))
    }
}

#[cfg(not(windows))]
pub fn read_registry_sz_local_machine(_key_path: &str, _value_name: &str) -> Option<String> {
    None
}
