//! Embed the Windows application manifest (requireAdministrator) and
//! the app icon (`assets/app.ico`, design M2) into every binary of
//! this package, so a double-click launches the app elevated (UAC
//! prompt) instead of needing "Run as administrator", and Explorer /
//! shortcuts / the taskbar show the PacketScope icon.
//!
//! The manifest itself is `app.manifest` in the package root; its key
//! line is:
//!   <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
//!
//! Two embedding routes, tried in order:
//!
//! 1. Resource compiler: compile a `.rc` holding both resources
//!    (`1 ICON "assets/app.ico"` and `1 RT_MANIFEST "app.manifest"`;
//!    the numeric IDs are per resource type, so both can be 1) into a
//!    COFF `.res` and pass it to the linker as an input file. Tried
//!    with llvm-rc first (cross-compiling from Linux via cargo-xwin /
//!    llvm-mingw, or LLVM installed on Windows), then with the
//!    Windows SDK's rc.exe (stock VS Build Tools installs). This was
//!    llvm-rc only before, and it *silently* produced a non-elevating
//!    binary on a normal Windows machine without llvm-rc — hence the
//!    extra routes.
//! 2. MSVC linker flags: `/MANIFEST:EMBED` + `/MANIFESTINPUT:<file>`
//!    (+ `/MANIFESTUAC:NO`, so the linker's default asInvoker fragment
//!    does not fight the requireAdministrator one). This is the native
//!    route: a stock Windows install of the Visual Studio Build Tools
//!    ships the linker and mt.exe it needs, no LLVM required. It is
//!    only used when the build *host* is Windows — under a Linux
//!    cross-compile lld-link cannot find mt.exe and the link fails,
//!    which is exactly why route 1 exists.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=assets/app.ico");
    // Delay-load Npcap's wpcap.dll in the main binary: it must NOT be
    // mapped into the process at startup. This one binary also runs
    // as uninstall.exe and as the cleanup helper, and with a load-time
    // import the loader maps wpcap.dll into those processes too —
    // whereupon Npcap's own uninstaller lists "uninstall.exe" as a
    // program using Npcap resources, and choosing OK in its dialog
    // ("close the program manually or it will be forcibly closed")
    // kills our uninstaller in the middle of the Npcap wait, so the
    // completion dialog and the folder cleanup never run (field logs
    // + screen recording, 2026-11-08). Delay-loaded, the DLL only
    // loads on the first real pcap call, which only the capture path
    // of the main app ever makes. The setup binary does not import
    // wpcap at all (it references no pcap symbols), so the flag is
    // scoped to the packetscope bin.
    println!("cargo:rustc-link-arg-bin=packetscope=/DELAYLOAD:wpcap.dll");
    println!("cargo:rustc-link-lib=delayimp");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest = format!("{manifest_dir}/app.manifest");
    let icon = format!("{manifest_dir}/assets/app.ico");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc_path = out_dir.join("packetscope.rc");
    let res_path = out_dir.join("packetscope.res");
    // Keep the paths exactly as Cargo gives them: resource compilers
    // accept '/' separators on Windows too, and rewriting them to '\'
    // would break the paths outright when cross-compiling from Linux.
    let _ = std::fs::write(
        &rc_path,
        format!("1 ICON \"{icon}\"\n1 RT_MANIFEST \"{manifest}\"\n"),
    );

    // Route 1: a resource compiler (llvm-rc, then the SDK's rc.exe).
    for tool in ["llvm-rc", "rc"] {
        let ok = rc_path.exists()
            && Command::new(tool)
                .arg("/fo")
                .arg(&res_path)
                .arg(&rc_path)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        if ok {
            println!("cargo:rustc-link-arg-bins={}", res_path.display());
            return;
        }
    }

    // Route 2: native MSVC linker + mt.exe (stock VS Build Tools).
    // Only on a Windows host: cross-linking with lld-link has no mt.exe.
    // This embeds the manifest only — the exe icon is lost on this
    // route (the in-app window icon still applies at runtime).
    let host = std::env::var("HOST").unwrap_or_default();
    if target.contains("windows-msvc") && host.contains("windows") {
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{manifest}");
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
        println!(
            "cargo:warning=no resource compiler (llvm-rc / rc.exe) found; \
             manifest embedded via linker flags, but the exe icon was NOT embedded."
        );
        return;
    }

    // No route available in this environment: we cannot embed it here.
    // Say so loudly in the build log instead of shipping a binary that
    // quietly fails to elevate.
    println!(
        "cargo:warning=llvm-rc not available; manifest (requireAdministrator) was NOT embedded. \
         Build on Windows with the MSVC target, or install LLVM, to get a double-click-elevating binary."
    );
}
