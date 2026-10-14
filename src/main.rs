//! Image entry point for aicalc.exe. There is no C runtime: like the
//! original, the image depends only on system DLLs.

#![no_std]
#![no_main]

#[cfg(not(target_arch = "x86"))]
compile_error!("aicalc reproduces the x86 calc.exe image: build for i686-pc-windows-msvc");

mod loadcfg;

use core::ptr::{addr_of, addr_of_mut};

use aicalc::win32::{fastfail, HINSTANCE, FAST_FAIL_FATAL_APP_EXIT};

extern "C" {
    /// Linker-provided start of this image (`__ImageBase`), the `hInstance`
    /// the CRT passes to `wWinMain`.
    static __ImageBase: u8;
}

/// `wWinMainCRTStartup` @ 0x00401CF0 (named by `/ENTRY` in build.rs):
/// `__security_init_cookie()` then `__tmainCRTStartup()`.
#[no_mangle]
pub unsafe extern "C" fn wWinMainCRTStartup() -> u32 {
    aicalc::startup::security_init_cookie(
        addr_of_mut!(loadcfg::__security_cookie),
        addr_of_mut!(loadcfg::__security_cookie_complement),
    );
    aicalc::startup::wwinmain_crt_startup(addr_of!(__ImageBase) as HINSTANCE)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Equivalent of the CRT's abort(): a non-continuable fail-fast.
    fastfail(FAST_FAIL_FATAL_APP_EXIT)
}
