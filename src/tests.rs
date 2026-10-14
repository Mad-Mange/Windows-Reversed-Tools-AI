//! Unit tests for the translated logic, run against recording mocks of the
//! imported APIs (`win32::mock`). Expected byte strings are copied verbatim
//! from the original calc.exe image (addresses noted).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, MutexGuard};

use crate::calc::*;
use crate::startup::*;
use crate::tracelogging::*;
use crate::win32::mock::{self, Call, DataBlock, ExitCode, FastFail};
use crate::win32::*;

/// The provider block and mock state are process globals: serialise tests.
static SERIAL: Mutex<()> = Mutex::new(());

fn setup() -> MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    mock::reset();
    unsafe {
        let p = G_TRACE_LOGGING_PROVIDER.get();
        (*p).level_plus1 = 0;
        (*p).keyword_any = 0;
        (*p).keyword_all = 0;
        (*p).reg_handle = 0;
        (*p).enable_callback = None;
        (*p).callback_context = ptr::null_mut();
    }
    guard
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

fn as_bytes<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

/// calc.exe .rdata$zETW0 @ 0x00401248 (16 bytes).
fn original_header() -> Vec<u8> {
    hex("45 54 57 30 10 00 00 00 86 0E 04 88 2B 05 8A BB")
}

/// calc.exe .rdata$zETW1 @ 0x00401258 (0x36 bytes).
fn original_event_blob() -> Vec<u8> {
    hex("06 0B 05 00 00 00 00 00 00 00 02 00 2A 00 00 43 61 6C 63 75 6C 61 74 6F 72 57 69 6E 4D 61 69 6E 00 \
         22 43 61 6C 63 75 6C 61 74 6F 72 53 74 61 72 74 65 64 22 00 02")
}

/// calc.exe .rdata$zETW2 @ 0x0040128E (0x3A bytes).
fn original_provider_blob() -> Vec<u8> {
    hex("04 09 CA 05 09 0E 61 1E 40 B6 50 2F 21 29 80 B9 E0 29 00 4D 69 63 72 6F 73 6F 66 74 43 61 6C 63 75 \
         6C 61 74 6F 72 00 13 00 01 1A 73 50 4F CF 89 82 47 B3 E0 DC E8 C9 04 76 BA")
}

fn expected_shell_execute() -> Call {
    Call::ShellExecuteW {
        hwnd_null: true,
        operation: None,
        file: Some("ms-calculator:".into()),
        parameters: None,
        directory: None,
        show: SW_SHOWNORMAL,
    }
}

fn expected_register() -> Call {
    Call::EventRegister { provider_id: CALCULATOR_PROVIDER_ID, has_callback: true }
}

fn expected_set_traits(handle: REGHANDLE) -> Call {
    // EventSetInformation receives the blob from RemainingSize onwards.
    Call::EventSetInformation { reg_handle: handle, class: EVENT_PROVIDER_SET_TRAITS, info: original_provider_blob()[17..].to_vec() }
}

fn expected_event_write(handle: REGHANDLE) -> Call {
    Call::EventWriteTransfer {
        reg_handle: handle,
        descriptor: EVENT_DESCRIPTOR {
            Id: 0,
            Version: 0,
            Channel: 11,
            Level: 5,
            Opcode: 0,
            Task: 0,
            Keyword: 0x0002_0000_0000_0000,
        },
        activity_id_null: true,
        related_activity_id_null: true,
        data: vec![
            DataBlock { bytes: original_provider_blob()[17..].to_vec(), size: 0x29, reserved: 2 },
            DataBlock { bytes: original_event_blob()[12..].to_vec(), size: 0x2A, reserved: 1 },
            DataBlock { bytes: b"CalculatorStarted\0".to_vec(), size: 0x12, reserved: 0 },
        ],
    }
}

fn run_main() -> i32 {
    let mut cmd = wide::<6>("hello");
    unsafe { w_win_main(0x40_0000 as HINSTANCE, ptr::null_mut(), cmd.as_mut_ptr(), SW_SHOWDEFAULT) }
}

// ---------------------------------------------------------------- metadata

#[test]
fn metadata_blobs_match_original_bytes() {
    assert_eq!(as_bytes(&TLG_HEADER), &original_header()[..]);
    assert_eq!(as_bytes(&CALCULATOR_WIN_MAIN_EVENT), &original_event_blob()[..]);
    assert_eq!(as_bytes(&PROVIDER_METADATA), &original_provider_blob()[..]);
    assert_eq!(TLG_END_OF_BLOBS, [1, 0, 0, 0]);
    assert_eq!(std::mem::size_of::<TlgProvider>(), 0x28);
    assert_eq!(std::mem::size_of::<EVENT_DESCRIPTOR>(), 16);
    assert_eq!(std::mem::size_of::<EVENT_DATA_DESCRIPTOR>(), 16);
}

#[test]
fn provider_block_initial_state() {
    let _g = setup();
    unsafe {
        let p = G_TRACE_LOGGING_PROVIDER.get();
        let meta = (*p).provider_metadata_ptr as *const u8;
        // ProviderMetadataPtr points at RemainingSize, 17 bytes into the blob.
        assert_eq!(meta, (ptr::addr_of!(PROVIDER_METADATA) as *const u8).add(17));
        // Unaligned, exactly like the original's 0x0040129F.
        assert_eq!(ptr::read_unaligned(meta as *const u16), 0x29);
        assert_eq!((*p).level_plus1, 0);
    }
}

#[test]
fn string_constants() {
    assert_eq!(String::from_utf16(&MS_CALCULATOR_URI[..14]).unwrap(), "ms-calculator:");
    assert_eq!(MS_CALCULATOR_URI[14], 0);
    assert_eq!(&CALCULATOR_STARTED, b"CalculatorStarted\0");
}

// ---------------------------------------------------------------- wWinMain

#[test]
fn winmain_without_trace_session_registers_and_launches() {
    let _g = setup();
    let ret = run_main();
    assert_eq!(ret, 0);
    let handle = mock::with(|s| s.reg_handle);
    assert_eq!(mock::calls(), vec![expected_register(), expected_set_traits(handle), expected_shell_execute()]);
}

#[test]
fn winmain_with_matching_session_writes_event() {
    let _g = setup();
    mock::with(|s| s.enable_on_register = vec![(1, 5, 0x0002_0000_0000_0000, 0)]);
    assert_eq!(run_main(), 0);
    let handle = mock::with(|s| s.reg_handle);
    assert_eq!(
        mock::calls(),
        vec![expected_register(), expected_set_traits(handle), expected_event_write(handle), expected_shell_execute()]
    );
}

#[test]
fn winmain_event_level_filtering() {
    // (session level, should write): event level is 5 (verbose).
    for (level, writes) in [(1u8, false), (4, false), (5, true), (6, true), (255, true), (0, true)] {
        let _g = setup();
        mock::with(|s| s.enable_on_register = vec![(1, level, u64::MAX, 0)]);
        run_main();
        let wrote = mock::calls().iter().any(|c| matches!(c, Call::EventWriteTransfer { .. }));
        assert_eq!(wrote, writes, "session level {level}");
    }
}

#[test]
fn winmain_event_keyword_filtering() {
    let kw = CALCULATOR_WIN_MAIN_KEYWORD;
    let cases = [
        (0u64, 0u64, false),                      // no MatchAny bits
        (0x0000_8000_0000_0000, 0, false),        // telemetry-only session
        (kw, 0, true),                            // exact keyword
        (u64::MAX, 0, true),                      // all keywords
        (kw, kw, true),                           // MatchAll satisfied
        (u64::MAX, kw | 0x0000_4000_0000_0000, false), // MatchAll needs a bit the event lacks
        (u64::MAX, 1, false),
    ];
    for (any, all, writes) in cases {
        let _g = setup();
        mock::with(|s| s.enable_on_register = vec![(1, 5, any, all)]);
        run_main();
        let wrote = mock::calls().iter().any(|c| matches!(c, Call::EventWriteTransfer { .. }));
        assert_eq!(wrote, writes, "any={any:#x} all={all:#x}");
    }
}

#[test]
fn winmain_after_disable_writes_nothing() {
    let _g = setup();
    mock::with(|s| s.enable_on_register = vec![(1, 5, u64::MAX, 0), (0, 0, 0, 0)]);
    run_main();
    assert!(!mock::calls().iter().any(|c| matches!(c, Call::EventWriteTransfer { .. })));
}

#[test]
fn winmain_capture_state_leaves_settings() {
    let _g = setup();
    // EVENT_CONTROL_CODE_CAPTURE_STATE (2) must not touch the cached settings.
    mock::with(|s| s.enable_on_register = vec![(1, 5, u64::MAX, 0), (2, 0, 0, 0)]);
    run_main();
    assert!(mock::calls().iter().any(|c| matches!(c, Call::EventWriteTransfer { .. })));
}

#[test]
fn winmain_register_failure_still_launches() {
    let _g = setup();
    mock::with(|s| s.register_status = 5 /* ERROR_ACCESS_DENIED */);
    assert_eq!(run_main(), 0);
    assert_eq!(mock::calls(), vec![expected_register(), expected_shell_execute()]);
}

// ---------------------------------------------------------- TraceLogging

#[test]
fn register_returns_hresult_from_win32() {
    for (status, hr) in [(0u32, 0i32), (5, 0x8007_0005u32 as i32), (8, 0x8007_0008u32 as i32), (0x8000_4005, 0x8000_4005u32 as i32)] {
        let _g = setup();
        mock::with(|s| s.register_status = status);
        let got = unsafe { trace_logging_register(G_TRACE_LOGGING_PROVIDER.get()) };
        assert_eq!(got, hr, "status {status:#x}");
    }
}

#[test]
fn register_twice_fails_fast() {
    let _g = setup();
    unsafe {
        assert_eq!(trace_logging_register(G_TRACE_LOGGING_PROVIDER.get()), 0);
        let r = catch_unwind(AssertUnwindSafe(|| trace_logging_register(G_TRACE_LOGGING_PROVIDER.get())));
        let payload = r.expect_err("second registration must fail fast");
        assert_eq!(payload.downcast_ref::<FastFail>(), Some(&FastFail(FAST_FAIL_INVALID_ARG)));
    }
}

#[test]
fn enable_callback_updates_provider_block() {
    let _g = setup();
    unsafe {
        let p = G_TRACE_LOGGING_PROVIDER.get();
        trace_logging_register(p);
        mock::deliver((1, 3, 0x1111, 0x0101));
        assert_eq!(((*p).level_plus1, (*p).keyword_any, (*p).keyword_all), (4, 0x1111, 0x0101));
        mock::deliver((1, 0, 7, 0));
        assert_eq!((*p).level_plus1, 0x100);
        mock::deliver((0, 9, 9, 9));
        assert_eq!(((*p).level_plus1, (*p).keyword_any, (*p).keyword_all), (0, 7, 0));
        // A null context is ignored outright.
        tlg_enable_callback(ptr::null(), 1, 5, 1, 1, ptr::null_mut(), ptr::null_mut());
        assert_eq!((*p).level_plus1, 0);
    }
}

static mut CHAINED: Vec<(u32, u8, u64, u64, usize)> = Vec::new();

unsafe extern "system" fn chained_callback(
    _id: *const GUID,
    code: u32,
    level: u8,
    any: u64,
    all: u64,
    _filter: *mut EVENT_FILTER_DESCRIPTOR,
    ctx: *mut core::ffi::c_void,
) {
    (*ptr::addr_of_mut!(CHAINED)).push((code, level, any, all, ctx as usize));
}

#[test]
fn enable_callback_forwards_to_user_callback() {
    let _g = setup();
    unsafe {
        (*ptr::addr_of_mut!(CHAINED)).clear();
        let p = G_TRACE_LOGGING_PROVIDER.get();
        trace_logging_register(p);
        (*p).enable_callback = Some(chained_callback);
        (*p).callback_context = 0x55 as *mut _;
        mock::deliver((1, 4, 0xAA, 0xBB));
        mock::deliver((2, 0, 1, 2));
        assert_eq!(&*ptr::addr_of!(CHAINED), &[(1, 4, 0xAA, 0xBB, 0x55), (2, 0, 1, 2, 0x55)]);
    }
}

#[test]
fn provider_enabled_semantics() {
    let _g = setup();
    unsafe {
        let p = G_TRACE_LOGGING_PROVIDER.get();
        (*p).level_plus1 = 6;
        (*p).keyword_any = 0;
        assert!(trace_logging_provider_enabled(p, 5, 0), "keyword 0 ignores masks");
        assert!(!trace_logging_provider_enabled(p, 6, 0));
        assert!(!trace_logging_provider_enabled(p, 5, 1));
        (*p).keyword_any = 3;
        (*p).keyword_all = 2;
        assert!(trace_logging_provider_enabled(p, 5, 2));
        assert!(!trace_logging_provider_enabled(p, 5, 1));
    }
}

#[test]
fn create_1sz_char_counts_terminator() {
    let mut d = EVENT_DATA_DESCRIPTOR::default();
    unsafe { tlg_create_1sz_char(&mut d, b"abc\0".as_ptr()) };
    assert_eq!((d.Size, d.Reserved), (4, 0));
    unsafe { tlg_create_1sz_char(&mut d, b"\0".as_ptr()) };
    assert_eq!(d.Size, 1);
}

// ---------------------------------------------------------------- startup

fn tail(cmdline: &str) -> String {
    let mut w: Vec<u16> = cmdline.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let p = skip_program_name(w.as_mut_ptr());
        let off = p.offset_from(w.as_ptr()) as usize;
        String::from_utf16(&w[off..w.len() - 1]).unwrap()
    }
}

#[test]
fn command_line_tail() {
    assert_eq!(tail(""), "");
    assert_eq!(tail("calc.exe"), "");
    assert_eq!(tail("calc.exe   "), "");
    assert_eq!(tail("calc.exe a b"), "a b");
    assert_eq!(tail("calc.exe \t  a  "), "a  ");
    assert_eq!(tail(r#""C:\Program Files\x\calc.exe" /x"#), "/x");
    assert_eq!(tail(r#""C:\a b\calc.exe"/x y"#), "y");
    assert_eq!(tail(r#"C:\a" b"\calc.exe z"#), "z");
    assert_eq!(tail(r#""unterminated quote with spaces"#), "");
    assert_eq!(tail("   leading"), "leading");
    assert_eq!(tail("calc\u{1}\u{2}x"), "x"); // control chars count as whitespace
}

#[test]
fn show_command_selection() {
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    assert_eq!(show_command(&si), SW_SHOWDEFAULT);
    si.wShowWindow = 7;
    assert_eq!(show_command(&si), SW_SHOWDEFAULT);
    si.dwFlags = STARTF_USESHOWWINDOW;
    assert_eq!(show_command(&si), 7);
    si.dwFlags = STARTF_USESHOWWINDOW | 0x100;
    si.wShowWindow = 0;
    assert_eq!(show_command(&si), 0);
}

#[test]
fn crt_startup_runs_winmain_and_exits_zero() {
    let _g = setup();
    mock::with(|s| {
        s.command_line = "aicalc.exe --foo".encode_utf16().chain(Some(0)).collect();
        s.startup_flags = STARTF_USESHOWWINDOW;
        s.startup_show = 3;
    });
    let r = catch_unwind(|| unsafe { wwinmain_crt_startup(0x40_0000 as HINSTANCE) });
    let payload = r.expect_err("startup must end in ExitProcess");
    assert_eq!(payload.downcast_ref::<ExitCode>(), Some(&ExitCode(0)));
    let calls = mock::calls();
    assert_eq!(calls[0], Call::GetStartupInfoW);
    assert_eq!(calls[1], Call::GetCommandLineW);
    assert_eq!(calls.last(), Some(&expected_shell_execute()));
}

#[test]
fn security_cookie_already_initialised_by_loader() {
    let _g = setup();
    let (mut cookie, mut complement) = (0x1357_9BDFusize, 0usize);
    unsafe { security_init_cookie(&mut cookie, &mut complement) };
    assert_eq!((cookie, complement), (0x1357_9BDF, !0x1357_9BDFusize));
}

#[test]
fn security_cookie_generated_from_default_or_zero() {
    for initial in [DEFAULT_SECURITY_COOKIE, 0] {
        let _g = setup();
        let (mut cookie, mut complement) = (initial, 0usize);
        unsafe { security_init_cookie(&mut cookie, &mut complement) };
        assert_ne!(cookie, DEFAULT_SECURITY_COOKIE);
        assert_ne!(cookie, 0);
        assert_eq!(complement, !cookie);

        // cookie = (time.hi ^ time.lo) ^ pid ^ tid ^ ticks ^ &local ^ (qpc.hi ^ qpc.lo):
        // strip the known terms and the remainder must be a stack address.
        let (ft, pid, tid, ticks, qpc) = mock::with(|s| s.entropy);
        let known = (ft.dwHighDateTime ^ ft.dwLowDateTime ^ pid ^ tid ^ ticks ^ (qpc >> 32) as u32 ^ qpc as u32) as usize;
        let stack_term = cookie ^ known;
        let here = &stack_term as *const usize as usize;
        assert!(here.abs_diff(stack_term) < 0x1_0000, "stack term {stack_term:#x} vs local {here:#x}");
    }
}

#[test]
fn crt_startup_without_command_line_returns_255() {
    let _g = setup();
    let r = unsafe { wwinmain_crt_startup(0x40_0000 as HINSTANCE) };
    assert_eq!(r, 255);
    assert_eq!(mock::calls(), vec![Call::GetStartupInfoW, Call::GetCommandLineW]);
}
