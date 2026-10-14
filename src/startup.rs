//! Process startup: translation of the msvcrt `wWinMainCRTStartup` stub that
//! the original image links statically (crtexe.c, `_WINMAIN_` + `WPRFLAG`).
//!
//! | Original address | Original routine                 | Rust                          |
//! |------------------|----------------------------------|-------------------------------|
//! | 0x00401CF0       | `wWinMainCRTStartup`             | `main.rs` entry point         |
//! | 0x00401933       | `__security_init_cookie`         | [`security_init_cookie`]      |
//! | 0x00401A69       | `__tmainCRTStartup`              | [`wwinmain_crt_startup`]      |
//! | 0x00401B7A       | command-line tail scan           | [`skip_program_name`]         |
//! | 0x00401BA0       | `nShowCmd` selection             | [`show_command`]              |
//! | 0x004019C0       | `pre_c_init` (.CRT$XIAA)         | msvcrt-only state, see below  |
//! | 0x00401A30       | `pre_cpp_init` (.CRT$XCAA)       | msvcrt-only state, see below  |
//! | 0x00401D50       | `__CxxSetUnhandledExceptionFilter` | n/a: no C++ exceptions      |
//!
//! `pre_c_init`/`pre_cpp_init` only configure msvcrt.dll's own globals
//! (`__set_app_type`, `_fmode`, `_commode`, `__setusermatherr`, `_controlfp`
//! precision, `__wgetmainargs`). The application never touches the C runtime,
//! so none of that state is observable; the Rust image has no C runtime at all.
//! Likewise the native-startup lock (`__native_startup_lock`, `Sleep(1000)`
//! spin) only matters if two threads enter the CRT entry point at once, which
//! cannot happen for a process's initial thread, and the image has no C++
//! initialisers or TLS callbacks to run.

use core::mem::MaybeUninit;
use core::ptr::{self, addr_of};

use crate::calc::w_win_main;
use crate::win32::*;

/// `DEFAULT_SECURITY_COOKIE` for 32-bit images (the cookie's initial value).
pub const DEFAULT_SECURITY_COOKIE: usize = 0xBB40_E64E;

/// `__security_init_cookie` @ 0x00401933.
///
/// Modern loaders already randomise the cookie before the entry point runs,
/// in which case only the complement is derived. Otherwise (older loaders, or
/// a cookie still holding the default/zero) it mixes the same entropy sources
/// as the original, including the address of a stack local.
pub unsafe fn security_init_cookie(cookie: *mut usize, complement: *mut usize) {
    let mut value = ptr::read_volatile(cookie);

    if value == 0 || value == DEFAULT_SECURITY_COOKIE {
        let mut system_time = FILETIME::default();
        let mut perf_counter: i64 = 0;

        GetSystemTimeAsFileTime(&mut system_time);
        let mut mixed: usize = (system_time.dwHighDateTime ^ system_time.dwLowDateTime) as usize;
        mixed ^= GetCurrentProcessId() as usize;
        mixed ^= GetCurrentThreadId() as usize;
        mixed ^= GetTickCount() as usize;
        mixed ^= addr_of!(mixed) as usize;

        QueryPerformanceCounter(&mut perf_counter);
        mixed ^= ((perf_counter >> 32) as u32 ^ perf_counter as u32) as usize;

        value = if mixed != 0 { mixed } else { DEFAULT_SECURITY_COOKIE };
        ptr::write_volatile(cookie, value);
    }

    ptr::write_volatile(complement, !value);
}

/// `wWinMainCRTStartup` / `__tmainCRTStartup`.
///
/// Returns only on the early-failure path (no command line), where the
/// original also returns 255 from the thread start routine; otherwise ends
/// the process with `wWinMain`'s result, as `exit(mainret)` does.
pub unsafe fn wwinmain_crt_startup(image_base: HINSTANCE) -> u32 {
    let mut startup_info = MaybeUninit::<STARTUPINFOW>::uninit();
    GetStartupInfoW(startup_info.as_mut_ptr());
    let startup_info = startup_info.assume_init();

    // msvcrt's `_wcmdln` is the process command line (GetCommandLineW()).
    let command_line = GetCommandLineW();
    if command_line.is_null() {
        return 255;
    }

    let cmd_tail = skip_program_name(command_line);
    let show = show_command(&startup_info);

    let main_ret = w_win_main(image_base, ptr::null_mut(), cmd_tail, show);

    // Not a managed image, so: exit(mainret).
    ExitProcess(main_ret as u32)
}

/// Skips the program name (honouring double quotes) and the whitespace that
/// follows it, returning the `lpCmdLine` passed to `wWinMain`.
pub unsafe fn skip_program_name(command_line: PWSTR) -> PWSTR {
    const SPACE: u16 = b' ' as u16;
    const DQUOTE: u16 = b'"' as u16;

    let mut p = command_line;
    let mut in_double_quote = false;

    while *p > SPACE || (*p != 0 && in_double_quote) {
        if *p == DQUOTE {
            in_double_quote = !in_double_quote;
        }
        p = p.add(1);
    }

    while *p != 0 && *p <= SPACE {
        p = p.add(1);
    }

    p
}

/// `nShowCmd` for `wWinMain`: the creator's `wShowWindow` if it supplied one,
/// otherwise `SW_SHOWDEFAULT`.
#[inline]
pub fn show_command(startup_info: &STARTUPINFOW) -> i32 {
    if startup_info.dwFlags & STARTF_USESHOWWINDOW != 0 {
        startup_info.wShowWindow as i32
    } else {
        SW_SHOWDEFAULT
    }
}
