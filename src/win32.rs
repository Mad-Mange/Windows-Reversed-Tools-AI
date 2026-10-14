//! Minimal Win32 / ETW surface used by calc.exe.
//!
//! The import set mirrors the original image's import table:
//!
//! | DLL                                          | Function            |
//! |----------------------------------------------|---------------------|
//! | SHELL32.dll                                  | ShellExecuteW       |
//! | ADVAPI32.dll                                 | EventRegister       |
//! | ADVAPI32.dll                                 | EventSetInformation |
//! | ADVAPI32.dll                                 | EventWriteTransfer  |
//! | api-ms-win-core-processthreads-l1-1-0.dll    | GetStartupInfoW     |
//! | KERNEL32.dll                                 | GetSystemTimeAsFileTime, GetCurrentProcessId, GetCurrentThreadId, GetTickCount, QueryPerformanceCounter (`__security_init_cookie`) |
//!
//! The original also imports msvcrt.dll for its C runtime startup; the Rust
//! translation has no C runtime, so the two pieces of CRT state it actually
//! consumed (`_wcmdln` and `exit`) come from KERNEL32 (`GetCommandLineW`, which
//! is what msvcrt's `_wcmdln` points at, and `ExitProcess`, which is what
//! msvcrt's `exit` ends in).
//!
//! Under `cfg(test)` every import is replaced by a recording mock (see
//! [`mock`]) so the translated logic can be exercised without side effects.

#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use core::ffi::c_void;

pub type BOOL = i32;
pub type HRESULT = i32;
pub type HWND = *mut c_void;
pub type HINSTANCE = *mut c_void;
pub type PCWSTR = *const u16;
pub type PWSTR = *mut u16;
pub type REGHANDLE = u64;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl GUID {
    pub const fn from_parts(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        GUID { data1: d1, data2: d2, data3: d3, data4: d4 }
    }
}

/// `EVENT_DESCRIPTOR` (evntprov.h), 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EVENT_DESCRIPTOR {
    pub Id: u16,
    pub Version: u8,
    pub Channel: u8,
    pub Level: u8,
    pub Opcode: u8,
    pub Task: u16,
    pub Keyword: u64,
}

/// `EVENT_DATA_DESCRIPTOR` (evntprov.h), 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EVENT_DATA_DESCRIPTOR {
    pub Ptr: u64,
    pub Size: u32,
    /// Union with `{ UCHAR Type; UCHAR Reserved1; USHORT Reserved2; }`.
    pub Reserved: u32,
}

pub const EVENT_DATA_DESCRIPTOR_TYPE_NONE: u32 = 0;
pub const EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA: u32 = 1;
pub const EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA: u32 = 2;

/// `EVENT_FILTER_DESCRIPTOR`; only ever passed through as an opaque pointer.
#[repr(C)]
pub struct EVENT_FILTER_DESCRIPTOR {
    pub Ptr: u64,
    pub Size: u32,
    pub Type: u32,
}

/// `PENABLECALLBACK` (evntprov.h).
pub type PENABLECALLBACK = unsafe extern "system" fn(
    source_id: *const GUID,
    is_enabled: u32,
    level: u8,
    match_any_keyword: u64,
    match_all_keyword: u64,
    filter_data: *mut EVENT_FILTER_DESCRIPTOR,
    callback_context: *mut c_void,
);

pub const EVENT_CONTROL_CODE_DISABLE_PROVIDER: u32 = 0;
pub const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;

/// `EVENT_INFO_CLASS::EventProviderSetTraits`.
pub const EVENT_PROVIDER_SET_TRAITS: i32 = 2;

/// `STARTUPINFOW` (processthreadsapi.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STARTUPINFOW {
    pub cb: u32,
    pub lpReserved: PWSTR,
    pub lpDesktop: PWSTR,
    pub lpTitle: PWSTR,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: *mut c_void,
    pub hStdOutput: *mut c_void,
    pub hStdError: *mut c_void,
}

/// `FILETIME` (minwinbase.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

pub const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
pub const SW_SHOWNORMAL: i32 = 1;
pub const SW_SHOWDEFAULT: i32 = 10;

pub const FACILITY_WIN32: u32 = 7;
pub const FAST_FAIL_INVALID_ARG: u32 = 5;
pub const FAST_FAIL_FATAL_APP_EXIT: u32 = 7;

/// `HRESULT_FROM_WIN32` (winerror.h).
#[inline]
pub const fn hresult_from_win32(x: u32) -> HRESULT {
    if (x as HRESULT) <= 0 {
        x as HRESULT
    } else {
        ((x & 0x0000_FFFF) | (FACILITY_WIN32 << 16) | 0x8000_0000) as HRESULT
    }
}

/// Builds a NUL-terminated UTF-16 string from an ASCII literal at compile
/// time (the Rust spelling of an `L"..."` literal). `N` must be `len + 1`.
pub const fn wide<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    assert!(bytes.len() + 1 == N, "wide(): N must be the string length plus the terminator");
    let mut out = [0u16; N];
    let mut i = 0;
    while i < bytes.len() {
        assert!(bytes[i] < 0x80, "wide(): ASCII only");
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

/// `__fastfail` intrinsic: raises a non-continuable failure (int 29h on x86/x64).
#[cfg(not(test))]
#[inline(always)]
pub fn fastfail(code: u32) -> ! {
    unsafe {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        core::arch::asm!("int 0x29", in("ecx") code, options(noreturn, nostack));
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        core::arch::asm!("brk #0xF003", in("x0") code, options(noreturn, nostack));
    }
}

#[cfg(test)]
pub fn fastfail(code: u32) -> ! {
    std::panic::panic_any(mock::FastFail(code))
}

// --------------------------------------------------------------------------
// Real imports
// --------------------------------------------------------------------------

#[cfg(not(test))]
mod imports {
    use super::*;

    #[cfg_attr(target_arch = "x86", link(name = "SHELL32", kind = "raw-dylib", import_name_type = "undecorated"))]
    #[cfg_attr(not(target_arch = "x86"), link(name = "SHELL32", kind = "raw-dylib"))]
    extern "system" {
        pub fn ShellExecuteW(
            hwnd: HWND,
            lpOperation: PCWSTR,
            lpFile: PCWSTR,
            lpParameters: PCWSTR,
            lpDirectory: PCWSTR,
            nShowCmd: i32,
        ) -> HINSTANCE;
    }

    #[cfg_attr(target_arch = "x86", link(name = "ADVAPI32", kind = "raw-dylib", import_name_type = "undecorated"))]
    #[cfg_attr(not(target_arch = "x86"), link(name = "ADVAPI32", kind = "raw-dylib"))]
    extern "system" {
        pub fn EventRegister(
            ProviderId: *const GUID,
            EnableCallback: Option<PENABLECALLBACK>,
            CallbackContext: *mut c_void,
            RegHandle: *mut REGHANDLE,
        ) -> u32;

        pub fn EventSetInformation(
            RegHandle: REGHANDLE,
            InformationClass: i32,
            EventInformation: *const c_void,
            InformationLength: u32,
        ) -> u32;

        pub fn EventWriteTransfer(
            RegHandle: REGHANDLE,
            EventDescriptor: *const EVENT_DESCRIPTOR,
            ActivityId: *const GUID,
            RelatedActivityId: *const GUID,
            UserDataCount: u32,
            UserData: *const EVENT_DATA_DESCRIPTOR,
        ) -> u32;
    }

    #[cfg_attr(
        target_arch = "x86",
        link(name = "api-ms-win-core-processthreads-l1-1-0", kind = "raw-dylib", import_name_type = "undecorated")
    )]
    #[cfg_attr(not(target_arch = "x86"), link(name = "api-ms-win-core-processthreads-l1-1-0", kind = "raw-dylib"))]
    extern "system" {
        pub fn GetStartupInfoW(lpStartupInfo: *mut STARTUPINFOW);
    }

    #[cfg_attr(target_arch = "x86", link(name = "KERNEL32", kind = "raw-dylib", import_name_type = "undecorated"))]
    #[cfg_attr(not(target_arch = "x86"), link(name = "KERNEL32", kind = "raw-dylib"))]
    extern "system" {
        pub fn GetCommandLineW() -> PWSTR;
        pub fn ExitProcess(uExitCode: u32) -> !;
        pub fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut FILETIME);
        pub fn GetCurrentProcessId() -> u32;
        pub fn GetCurrentThreadId() -> u32;
        pub fn GetTickCount() -> u32;
        pub fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> BOOL;
    }
}

#[cfg(not(test))]
pub use imports::*;

// --------------------------------------------------------------------------
// Test doubles
// --------------------------------------------------------------------------

#[cfg(test)]
pub use mock::{
    EventRegister, EventSetInformation, EventWriteTransfer, ExitProcess, GetCommandLineW, GetCurrentProcessId,
    GetCurrentThreadId, GetStartupInfoW, GetSystemTimeAsFileTime, GetTickCount, QueryPerformanceCounter,
    ShellExecuteW,
};

#[cfg(test)]
pub mod mock {
    //! Recording stand-ins for the imported APIs. `EventRegister` behaves like
    //! the real one in the way that matters here: if a trace session already
    //! has the provider enabled, ETW invokes the enable callback synchronously
    //! from inside `EventRegister`.

    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FastFail(pub u32);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExitCode(pub u32);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DataBlock {
        pub bytes: Vec<u8>,
        pub size: u32,
        pub reserved: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Call {
        EventRegister { provider_id: GUID, has_callback: bool },
        EventSetInformation { reg_handle: REGHANDLE, class: i32, info: Vec<u8> },
        EventWriteTransfer {
            reg_handle: REGHANDLE,
            descriptor: EVENT_DESCRIPTOR,
            activity_id_null: bool,
            related_activity_id_null: bool,
            data: Vec<DataBlock>,
        },
        ShellExecuteW {
            hwnd_null: bool,
            operation: Option<String>,
            file: Option<String>,
            parameters: Option<String>,
            directory: Option<String>,
            show: i32,
        },
        GetStartupInfoW,
        GetCommandLineW,
    }

    /// An enable notification ETW would deliver: (control code, level, any, all).
    pub type Enable = (u32, u8, u64, u64);

    pub struct State {
        pub calls: Vec<Call>,
        pub register_status: u32,
        pub reg_handle: REGHANDLE,
        pub enable_on_register: Vec<Enable>,
        pub startup_flags: u32,
        pub startup_show: u16,
        pub command_line: Vec<u16>,
        pub last_callback: Option<(PENABLECALLBACK, usize)>,
        /// (system time, pid, tid, tick count, performance counter)
        pub entropy: (FILETIME, u32, u32, u32, i64),
    }

    impl State {
        const fn new() -> Self {
            State {
                calls: Vec::new(),
                register_status: 0,
                reg_handle: 0x0000_1234_5678_9ABC,
                enable_on_register: Vec::new(),
                startup_flags: 0,
                startup_show: 0,
                command_line: Vec::new(),
                last_callback: None,
                entropy: (FILETIME { dwLowDateTime: 0x1111_0000, dwHighDateTime: 0x01DC_2222 }, 0x1234, 0x5678, 0x9ABC, 0x0000_0042_0000_0F00),
            }
        }
    }

    pub static STATE: Mutex<State> = Mutex::new(State::new());

    pub fn reset() {
        let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
        *s = State::new();
    }

    pub fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
        let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s)
    }

    pub fn calls() -> Vec<Call> {
        with(|s| s.calls.clone())
    }

    unsafe fn wstr(p: PCWSTR) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        Some(String::from_utf16_lossy(core::slice::from_raw_parts(p, n)))
    }

    /// Simulates ETW delivering an enable/disable notification later on.
    pub unsafe fn deliver(enable: Enable) {
        let (cb, ctx) = with(|s| s.last_callback).expect("provider not registered");
        cb(core::ptr::null(), enable.0, enable.1, enable.2, enable.3, core::ptr::null_mut(), ctx as *mut c_void);
    }

    pub unsafe extern "system" fn EventRegister(
        provider_id: *const GUID,
        enable_callback: Option<PENABLECALLBACK>,
        callback_context: *mut c_void,
        reg_handle: *mut REGHANDLE,
    ) -> u32 {
        let (status, handle, enables) = with(|s| {
            s.calls.push(Call::EventRegister { provider_id: *provider_id, has_callback: enable_callback.is_some() });
            (s.register_status, s.reg_handle, s.enable_on_register.clone())
        });
        if status != 0 {
            *reg_handle = 0;
            return status;
        }
        *reg_handle = handle;
        if let Some(cb) = enable_callback {
            with(|s| s.last_callback = Some((cb, callback_context as usize)));
            for e in enables {
                cb(provider_id, e.0, e.1, e.2, e.3, core::ptr::null_mut(), callback_context);
            }
        }
        0
    }

    pub unsafe extern "system" fn EventSetInformation(
        reg_handle: REGHANDLE,
        class: i32,
        info: *const c_void,
        len: u32,
    ) -> u32 {
        let bytes = core::slice::from_raw_parts(info as *const u8, len as usize).to_vec();
        with(|s| s.calls.push(Call::EventSetInformation { reg_handle, class, info: bytes }));
        0
    }

    pub unsafe extern "system" fn EventWriteTransfer(
        reg_handle: REGHANDLE,
        descriptor: *const EVENT_DESCRIPTOR,
        activity_id: *const GUID,
        related_activity_id: *const GUID,
        count: u32,
        data: *const EVENT_DATA_DESCRIPTOR,
    ) -> u32 {
        let mut blocks = Vec::new();
        for i in 0..count as usize {
            let d = *data.add(i);
            let bytes = core::slice::from_raw_parts(d.Ptr as usize as *const u8, d.Size as usize).to_vec();
            blocks.push(DataBlock { bytes, size: d.Size, reserved: d.Reserved });
        }
        with(|s| {
            s.calls.push(Call::EventWriteTransfer {
                reg_handle,
                descriptor: *descriptor,
                activity_id_null: activity_id.is_null(),
                related_activity_id_null: related_activity_id.is_null(),
                data: blocks,
            })
        });
        0
    }

    pub unsafe extern "system" fn ShellExecuteW(
        hwnd: HWND,
        operation: PCWSTR,
        file: PCWSTR,
        parameters: PCWSTR,
        directory: PCWSTR,
        show: i32,
    ) -> HINSTANCE {
        let call = Call::ShellExecuteW {
            hwnd_null: hwnd.is_null(),
            operation: wstr(operation),
            file: wstr(file),
            parameters: wstr(parameters),
            directory: wstr(directory),
            show,
        };
        with(|s| s.calls.push(call));
        42 as HINSTANCE
    }

    pub unsafe extern "system" fn GetStartupInfoW(si: *mut STARTUPINFOW) {
        let (flags, show) = with(|s| {
            s.calls.push(Call::GetStartupInfoW);
            (s.startup_flags, s.startup_show)
        });
        let mut v: STARTUPINFOW = core::mem::zeroed();
        v.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
        v.dwFlags = flags;
        v.wShowWindow = show;
        // Poison the remaining fields the way an uninitialised stack would be.
        v.dwX = 0xCCCC_CCCC;
        *si = v;
    }

    pub unsafe extern "system" fn GetCommandLineW() -> PWSTR {
        with(|s| {
            s.calls.push(Call::GetCommandLineW);
            if s.command_line.is_empty() {
                core::ptr::null_mut()
            } else {
                s.command_line.as_mut_ptr()
            }
        })
    }

    pub unsafe extern "system" fn GetSystemTimeAsFileTime(ft: *mut FILETIME) {
        *ft = with(|s| s.entropy.0);
    }

    pub unsafe extern "system" fn GetCurrentProcessId() -> u32 {
        with(|s| s.entropy.1)
    }

    pub unsafe extern "system" fn GetCurrentThreadId() -> u32 {
        with(|s| s.entropy.2)
    }

    pub unsafe extern "system" fn GetTickCount() -> u32 {
        with(|s| s.entropy.3)
    }

    pub unsafe extern "system" fn QueryPerformanceCounter(count: *mut i64) -> BOOL {
        *count = with(|s| s.entropy.4);
        1
    }

    /// Plain Rust ABI (not "system") so the panic can unwind into the test.
    pub unsafe fn ExitProcess(code: u32) -> ! {
        std::panic::panic_any(ExitCode(code))
    }
}
