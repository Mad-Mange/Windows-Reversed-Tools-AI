//! Application logic of calc.exe: `wWinMain` and its TraceLogging provider.
//!
//! Since Windows 10, calc.exe is a launcher: it reports a telemetry event and
//! asks the shell to activate the `ms-calculator:` protocol, which starts the
//! packaged Calculator app (Microsoft.WindowsCalculator). The calculator UI
//! the user sees is that app, exactly as with the original binary.

use core::mem::{offset_of, size_of, MaybeUninit};
use core::ptr::{self, addr_of};

use crate::tracelogging::*;
use crate::win32::*;

// --------------------------------------------------------------------------
// TRACELOGGING_DEFINE_PROVIDER(
//     g_hTraceLoggingProvider,
//     "MicrosoftCalculator",
//     (0x0905ca09, 0x610e, 0x401e, 0xb6, 0x50, 0x2f, 0x21, 0x29, 0x80, 0xb9, 0xe0),
//     TraceLoggingOptionMicrosoftTelemetry());
// --------------------------------------------------------------------------

/// {0905CA09-610E-401E-B650-2F212980B9E0}
pub const CALCULATOR_PROVIDER_ID: GUID =
    GUID::from_parts(0x0905_CA09, 0x610E, 0x401E, [0xB6, 0x50, 0x2F, 0x21, 0x29, 0x80, 0xB9, 0xE0]);

/// Microsoft telemetry provider group {4F50731A-89CF-4782-B3E0-DCE8C90476BA}
/// (`TraceLoggingOptionMicrosoftTelemetry()`).
pub const MICROSOFT_TELEMETRY_GROUP_ID: GUID =
    GUID::from_parts(0x4F50_731A, 0x89CF, 0x4782, [0xB3, 0xE0, 0xDC, 0xE8, 0xC9, 0x04, 0x76, 0xBA]);

/// `_TlgBlobProvider3` metadata blob (`.rdata$zETW2`, 0x3A bytes).
#[repr(C, packed)]
pub struct ProviderMetadata {
    pub blob_type: u8,
    pub provider_id: GUID,
    /// Size of everything from this field to the end (name + traits).
    pub remaining_size: u16,
    pub name: [u8; 20],
    pub group_trait_size: u16,
    pub group_trait_type: u8,
    pub group_id: GUID,
}

#[link_section = ".rdata$zETW2"]
pub static PROVIDER_METADATA: ProviderMetadata = ProviderMetadata {
    blob_type: TLG_BLOB_PROVIDER3,
    provider_id: CALCULATOR_PROVIDER_ID,
    remaining_size: (size_of::<ProviderMetadata>() - offset_of!(ProviderMetadata, remaining_size)) as u16,
    name: *b"MicrosoftCalculator\0",
    group_trait_size: (size_of::<ProviderMetadata>() - offset_of!(ProviderMetadata, group_trait_size)) as u16,
    group_trait_type: ETW_PROVIDER_TRAIT_TYPE_GROUP,
    group_id: MICROSOFT_TELEMETRY_GROUP_ID,
};

/// The provider block (`.data`); `ProviderMetadataPtr` points at
/// `PROVIDER_METADATA.remaining_size`.
pub static G_TRACE_LOGGING_PROVIDER: TlgProviderCell =
    TlgProviderCell::new(addr_of!(PROVIDER_METADATA.remaining_size));

// --------------------------------------------------------------------------
// TraceLoggingWrite(
//     g_hTraceLoggingProvider,
//     "CalculatorWinMain",
//     TraceLoggingValue("CalculatorStarted"),
//     TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
//     TraceLoggingKeyword(0x0002000000000000));
//
// TraceLoggingValue without an explicit name uses the stringised argument,
// so the field is literally named `"CalculatorStarted"` (quotes included).
// --------------------------------------------------------------------------

pub const WINEVENT_LEVEL_VERBOSE: u8 = 5;
pub const CALCULATOR_WIN_MAIN_KEYWORD: u64 = 0x0002_0000_0000_0000;

/// `_TlgBlobEvent4` metadata blob (`.rdata$zETW1`, 0x36 bytes).
#[repr(C, packed)]
pub struct CalculatorWinMainEventMetadata {
    pub blob_type: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub keyword: u64,
    /// Size of everything from this field to the end (tags, name, fields).
    pub remaining_size: u16,
    /// Event tags; a single 0 byte means "no tags".
    pub tags: u8,
    pub name: [u8; 18],
    pub field0_name: [u8; 20],
    pub field0_in_type: u8,
}

#[link_section = ".rdata$zETW1"]
pub static CALCULATOR_WIN_MAIN_EVENT: CalculatorWinMainEventMetadata = CalculatorWinMainEventMetadata {
    blob_type: TLG_BLOB_EVENT4,
    channel: WINEVENT_CHANNEL_TRACELOGGING,
    level: WINEVENT_LEVEL_VERBOSE,
    opcode: 0,
    keyword: CALCULATOR_WIN_MAIN_KEYWORD,
    remaining_size: (size_of::<CalculatorWinMainEventMetadata>()
        - offset_of!(CalculatorWinMainEventMetadata, remaining_size)) as u16,
    tags: 0,
    name: *b"CalculatorWinMain\0",
    field0_name: *b"\"CalculatorStarted\"\0",
    field0_in_type: TLG_IN_ANSISTRING,
};

/// Payload of the `"CalculatorStarted"` field.
pub static CALCULATOR_STARTED: [u8; 18] = *b"CalculatorStarted\0";

/// `L"ms-calculator:"`
pub static MS_CALCULATOR_URI: [u16; 15] = wide("ms-calculator:");

/// `wWinMain` @ 0x0040176D.
///
/// All four parameters are unused by the original, and its result is always 0
/// (the `ShellExecuteW` result is not checked).
pub unsafe extern "system" fn w_win_main(
    _h_instance: HINSTANCE,
    _h_prev_instance: HINSTANCE,
    _cmd_line: PWSTR,
    _n_cmd_show: i32,
) -> i32 {
    let provider = G_TRACE_LOGGING_PROVIDER.get();

    // Result ignored: telemetry failing to register must not stop the launch.
    let _ = trace_logging_register(provider);

    // TraceLoggingWrite(...) expands to an enabled check followed by the write.
    let event = &CALCULATOR_WIN_MAIN_EVENT;
    if trace_logging_provider_enabled(provider, event.level, event.keyword) {
        // [0] provider traits, [1] event metadata, [2] "CalculatorStarted" value.
        let mut data = MaybeUninit::<[EVENT_DATA_DESCRIPTOR; 3]>::uninit();
        let data = data.as_mut_ptr() as *mut EVENT_DATA_DESCRIPTOR;
        tlg_create_1sz_char(data.add(2), CALCULATOR_STARTED.as_ptr());
        let _ = tlg_write_transfer(provider, addr_of!(event.channel), ptr::null(), ptr::null(), 3, data);
    }

    // The provider is deliberately never unregistered (the original has no
    // TraceLoggingUnregister); ETW cleans up at process exit.

    ShellExecuteW(
        ptr::null_mut(),
        ptr::null(),
        MS_CALCULATOR_URI.as_ptr(),
        ptr::null(),
        ptr::null(),
        SW_SHOWNORMAL,
    );

    0
}
