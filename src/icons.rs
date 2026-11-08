//! Application icon extraction, returned as PNG bytes.
//!
//! Windows: the icon resource of the executable itself (SHGetFileInfo +
//! GDI). macOS: the .app bundle's .icns (modern icns entries are PNG).
//! Linux: the app's .desktop entry and the hicolor icon theme.
//! Anything we cannot resolve returns None and the UI draws a letter
//! tile instead — the layout stays the same.

#[cfg(windows)]
pub fn icon_png(exe_path: &str) -> Option<Vec<u8>> {
    win::icon_png(exe_path)
}

#[cfg(target_os = "macos")]
pub fn icon_png(exe_path: &str) -> Option<Vec<u8>> {
    mac::icon_png(exe_path)
}

#[cfg(target_os = "linux")]
pub fn icon_png(exe_path: &str) -> Option<Vec<u8>> {
    linux::icon_png(exe_path)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn icon_png(_exe_path: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
mod win {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Graphics::Gdi::{
        CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, GetObjectW, BITMAP,
        BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC,
    };
    use windows_sys::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

    pub fn icon_png(exe_path: &str) -> Option<Vec<u8>> {
        // Never resolve icons for executables on a network share:
        // SHGetFileInfoW opens the file, which makes Windows present
        // this (elevated) user's credentials to the share's server —
        // SMB forced authentication (audit 2026-11-08). The `\\?\`
        // and `\\.\` prefixes are local device paths, not shares,
        // and local mapped drives arrive as drive letters anyway.
        if exe_path.starts_with("\\\\")
            && !exe_path.starts_with("\\\\?")
            && !exe_path.starts_with("\\\\.")
        {
            return None;
        }
        let wide: Vec<u16> = OsStr::new(exe_path).encode_wide().chain(Some(0)).collect();
        unsafe {
            let mut shfi: SHFILEINFOW = std::mem::zeroed();
            let rc = SHGetFileInfoW(
                wide.as_ptr(),
                0,
                &mut shfi,
                std::mem::size_of::<SHFILEINFOW>() as u32,
                SHGFI_ICON | SHGFI_LARGEICON,
            );
            if rc == 0 || shfi.hIcon.is_null() {
                return None;
            }
            let result = icon_to_png(shfi.hIcon);
            DestroyIcon(shfi.hIcon);
            result
        }
    }

    unsafe fn icon_to_png(hicon: windows_sys::Win32::UI::WindowsAndMessaging::HICON) -> Option<Vec<u8>> {
        let mut ii: ICONINFO = std::mem::zeroed();
        if GetIconInfo(hicon, &mut ii) == 0 {
            return None;
        }
        let out = (|| {
            let mut bm: BITMAP = std::mem::zeroed();
            if GetObjectW(
                ii.hbmColor as _,
                std::mem::size_of::<BITMAP>() as i32,
                &mut bm as *mut _ as *mut _,
            ) == 0
            {
                return None;
            }
            let (w, h) = (bm.bmWidth, bm.bmHeight);
            if w <= 0 || h <= 0 || w > 1024 || h > 1024 {
                return None;
            }
            let dc: HDC = CreateCompatibleDC(null_mut());
            if dc.is_null() {
                return None;
            }
            let mut read = |hbm: HBITMAP| -> Option<Vec<u8>> {
                let mut info: BITMAPINFO = std::mem::zeroed();
                info.bmiHeader = std::mem::zeroed();
                info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
                info.bmiHeader.biWidth = w;
                info.bmiHeader.biHeight = -h; // top-down
                info.bmiHeader.biPlanes = 1;
                info.bmiHeader.biBitCount = 32;
                info.bmiHeader.biCompression = BI_RGB;
                let mut buf = vec![0u8; (w * h * 4) as usize];
                let got = GetDIBits(
                    dc,
                    hbm,
                    0,
                    h as u32,
                    buf.as_mut_ptr() as *mut _,
                    &mut info,
                    DIB_RGB_COLORS,
                );
                if got == 0 {
                    None
                } else {
                    Some(buf)
                }
            };
            // Read both bitmaps, then release the DC *before* any
            // early return: the color read's `?` used to skip
            // DeleteDC and leak a GDI handle per failed icon (audit
            // 2026-11-08). The mask is only consulted for old-style
            // icons without alpha, but reading it eagerly is cheap.
            let color = read(ii.hbmColor);
            let mask = read(ii.hbmMask);
            DeleteDC(dc);
            let color = color?;
            let mut rgba = Vec::with_capacity(color.len());
            let has_alpha = color.chunks_exact(4).any(|px| px[3] != 0);
            if has_alpha {
                for px in color.chunks_exact(4) {
                    rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
                }
            } else {
                // Old-style icon: derive alpha from the AND mask
                // (white = transparent).
                for (i, px) in color.chunks_exact(4).enumerate() {
                    let transparent = mask
                        .as_ref()
                        .map(|m| m[i * 4] > 127)
                        .unwrap_or(false);
                    rgba.extend_from_slice(&[px[2], px[1], px[0], if transparent { 0 } else { 255 }]);
                }
            }
            encode_png(&rgba, w as u32, h as u32)
        })();
        if !ii.hbmColor.is_null() {
            DeleteObject(ii.hbmColor as _);
        }
        if !ii.hbmMask.is_null() {
            DeleteObject(ii.hbmMask as _);
        }
        out
    }

    fn encode_png(rgba: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc.write_header().ok()?;
            writer.write_image_data(rgba).ok()?;
        }
        Some(out)
    }
}

#[cfg(target_os = "macos")]
mod mac {
    /// Find the .app bundle for an executable path and pull the largest
    /// PNG-backed entry out of its .icns.
    pub fn icon_png(exe_path: &str) -> Option<Vec<u8>> {
        let app_end = exe_path.find(".app/")? + 4;
        let bundle = &exe_path[..app_end];
        let plist_path = format!("{bundle}/Contents/Info.plist");
        let plist = std::fs::read_to_string(&plist_path).ok()?;
        let icon_name = plist
            .split("<key>CFBundleIconFile</key>")
            .nth(1)?
            .split("<string>")
            .nth(1)?
            .split("</string>")
            .next()?
            .trim()
            .to_string();
        let icns_path = format!(
            "{bundle}/Contents/Resources/{}",
            if icon_name.ends_with(".icns") {
                icon_name.clone()
            } else {
                format!("{icon_name}.icns")
            }
        );
        let data = std::fs::read(icns_path).ok()?;
        parse_icns(&data)
    }

    fn parse_icns(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 8 || &data[0..4] != b"icns" {
            return None;
        }
        let mut best: Option<&[u8]> = None;
        let mut off = 8usize;
        while off + 8 <= data.len() {
            let size = u32::from_be_bytes(data[off + 4..off + 8].try_into().ok()?) as usize;
            if size < 8 || off + size > data.len() {
                break;
            }
            let chunk = &data[off + 8..off + size];
            // Modern entries (ic07..ic10) hold PNG data.
            if chunk.starts_with(b"\x89PNG") {
                if best.map(|b| b.len()).unwrap_or(0) < chunk.len() {
                    best = Some(chunk);
                }
            }
            off += size;
        }
        best.map(|b| b.to_vec())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    /// Resolve through .desktop files and the hicolor theme / pixmaps.
    pub fn icon_png(exe_path: &str) -> Option<Vec<u8>> {
        let base = exe_path.rsplit('/').next().unwrap_or("");
        let mut icon_ref: Option<String> = None;
        'outer: for dir in ["/usr/share/applications", "/usr/local/share/applications"] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e != "desktop").unwrap_or(true) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let exec_ok = text
                    .lines()
                    .find(|l| l.starts_with("Exec="))
                    .map(|l| l[5..].split_whitespace().any(|t| t == exe_path || t.ends_with(&format!("/{base}")) || t == base))
                    .unwrap_or(false);
                if exec_ok {
                    if let Some(icon) = text.lines().find(|l| l.starts_with("Icon=")) {
                        icon_ref = Some(icon[5..].trim().to_string());
                        break 'outer;
                    }
                }
            }
        }
        let icon = icon_ref?;
        if icon.starts_with('/') {
            return std::fs::read(&icon).ok().filter(|b| b.starts_with(b"\x89PNG"));
        }
        for size in ["256x256", "128x128", "96x96", "64x64", "48x48"] {
            let p = format!("/usr/share/icons/hicolor/{size}/apps/{icon}.png");
            if let Ok(b) = std::fs::read(&p) {
                return Some(b);
            }
        }
        std::fs::read(format!("/usr/share/pixmaps/{icon}.png")).ok()
    }
}
