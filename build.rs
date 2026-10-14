//! Build script: compiles the Win32 resources and sets the image-level linker
//! options so aicalc.exe's PE headers match the original calc.exe.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    let res_dir = manifest_dir.join("res");
    for f in ["aicalc.rc", "calc.ico", "aicalc.exe.manifest"] {
        println!("cargo:rerun-if-changed={}", res_dir.join(f).display());
    }
    println!("cargo:rerun-if-env-changed=AICALC_RC");

    if target_env != "msvc" {
        panic!("aicalc must be built with an MSVC target (link.exe + rc.exe)");
    }

    // ---- Resources --------------------------------------------------------
    let res_file = out_dir.join("aicalc.res");
    let rc = find_rc().expect("rc.exe not found: install the Windows SDK or set AICALC_RC");
    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_file)
        .arg(res_dir.join("aicalc.rc"))
        .current_dir(&res_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", rc.display()));
    assert!(status.success(), "rc.exe failed");
    println!("cargo:rustc-link-arg-bins={}", res_file.display());

    // ---- Image layout ------------------------------------------------------
    let link_args: &[&str] = &[
        // No C runtime: the entry point is our wWinMainCRTStartup.
        "/NODEFAULTLIB",
        "/ENTRY:wWinMainCRTStartup",
        // Subsystem / OS / image version 10.00, as in the original.
        "/SUBSYSTEM:WINDOWS,10.00",
        "/OSVERSION:10.00",
        "/VERSION:10.00",
        // Stack reserve 0x40000 / commit 0x2000; heap reserve 0x100000 / commit 0x1000.
        "/STACK:0x40000,0x2000",
        "/HEAP:0x100000,0x1000",
        "/DYNAMICBASE",
        "/NXCOMPAT",
        "/TSAWARE",
        // Set the optional-header checksum, as the original has one.
        "/RELEASE",
        // The manifest comes from the resource script.
        "/MANIFEST:NO",
    ];
    for a in link_args {
        println!("cargo:rustc-link-arg-bins={a}");
    }
    if target_arch == "x86" {
        // The original x86 image is not large-address aware.
        println!("cargo:rustc-link-arg-bins=/LARGEADDRESSAWARE:NO");
    }
}

/// Locates rc.exe: `AICALC_RC`, then PATH, then the newest Windows 10/11 SDK.
fn find_rc() -> Option<PathBuf> {
    if let Some(p) = env::var_os("AICALC_RC") {
        return Some(PathBuf::from(p));
    }
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            let cand = dir.join("rc.exe");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    let host = if cfg!(target_arch = "aarch64") { "arm64" } else if cfg!(target_arch = "x86") { "x86" } else { "x64" };
    let mut roots = Vec::new();
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(pf) = env::var_os(var) {
            roots.push(Path::new(&pf).join("Windows Kits").join("10").join("bin"));
        }
    }
    let mut best: Option<(Vec<u32>, PathBuf)> = None;
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(ver) = parse_version(&name) else { continue };
            let cand = e.path().join(host).join("rc.exe");
            if cand.is_file() && best.as_ref().map_or(true, |(v, _)| ver > *v) {
                best = Some((ver, cand));
            }
        }
        let flat = root.join(host).join("rc.exe");
        if best.is_none() && flat.is_file() {
            best = Some((vec![0], flat));
        }
    }
    best.map(|(_, p)| p)
}

fn parse_version(s: &str) -> Option<Vec<u32>> {
    let parts: Option<Vec<u32>> = s.split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|v| v.len() == 4)
}
