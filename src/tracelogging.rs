//! Translation of the TraceLogging runtime that calc.exe statically contains
//! (TraceLoggingProvider.h, compiled inline into the image).
//!
//! | Original address | Original symbol (TraceLoggingProvider.h)   | Rust                              |
//! |------------------|--------------------------------------------|-----------------------------------|
//! | 0x004015A0       | `_tlgEnableCallback`                       | [`tlg_enable_callback`]           |
//! | 0x00401623       | `TraceLoggingRegister`                     | [`trace_logging_register`]        |
//! | 0x004016CF       | `_tlgWriteTransfer_EventWriteTransfer`     | [`tlg_write_transfer`]            |
//! | (inlined)        | `TraceLoggingProviderEnabled`              | [`trace_logging_provider_enabled`]|
//! | (inlined)        | `_tlgCreate1Sz_char`                       | [`tlg_create_1sz_char`]           |
//! | .rdata$zETW0     | `_tlgHeader`                               | [`TLG_HEADER`]                    |
//! | .rdata$zETW9     | end-of-blobs marker                        | [`TLG_END_OF_BLOBS`]              |
//!
//! The metadata blobs themselves (provider and event) live next to their
//! users in [`crate::calc`], in `.rdata$zETW1` / `.rdata$zETW2`, so the image
//! carries the same `ETW0 ... end` metadata run that TraceLogging tools scan.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{self, addr_of, addr_of_mut};

use crate::win32::*;

/// `_TlgBlobTypes`: tags at the start of each metadata blob.
pub const TLG_BLOB_END: u8 = 1;
pub const TLG_BLOB_PROVIDER3: u8 = 4;
pub const TLG_BLOB_EVENT4: u8 = 6;

/// `TlgInANSISTRING`: nul-terminated 8-bit string field.
pub const TLG_IN_ANSISTRING: u8 = 2;

/// `TRACELOGGING_DEFINE_PROVIDER` channel for TraceLogging events.
pub const WINEVENT_CHANNEL_TRACELOGGING: u8 = 11;

/// `EtwProviderTraitTypeGroup`.
pub const ETW_PROVIDER_TRAIT_TYPE_GROUP: u8 = 1;

/// `struct _tlgProvider_t` (32-bit layout: 0x28 bytes).
///
/// ```text
/// +0x00 ULONG                LevelPlus1
/// +0x04 UINT16 const*        ProviderMetadataPtr  (points at RemainingSize)
/// +0x08 ULONGLONG            KeywordAny
/// +0x10 ULONGLONG            KeywordAll
/// +0x18 REGHANDLE            RegHandle
/// +0x20 TLG_PENABLECALLBACK  EnableCallback
/// +0x24 PVOID                CallbackContext
/// ```
#[repr(C)]
pub struct TlgProvider {
    pub level_plus1: u32,
    pub provider_metadata_ptr: *const u16,
    pub keyword_any: u64,
    pub keyword_all: u64,
    pub reg_handle: REGHANDLE,
    pub enable_callback: Option<PENABLECALLBACK>,
    pub callback_context: *mut c_void,
}

/// Static storage for a provider (`TraceLoggingHProvider` points into it).
/// ETW writes the level/keyword fields from its own notification thread.
#[repr(transparent)]
pub struct TlgProviderCell(UnsafeCell<TlgProvider>);

// SAFETY: mirrors the C original, where the provider block is a plain global
// that the ETW enable callback updates; all accesses are word-sized.
unsafe impl Sync for TlgProviderCell {}

impl TlgProviderCell {
    pub const fn new(provider_metadata_ptr: *const u16) -> Self {
        TlgProviderCell(UnsafeCell::new(TlgProvider {
            level_plus1: 0,
            provider_metadata_ptr,
            keyword_any: 0,
            keyword_all: 0,
            reg_handle: 0,
            enable_callback: None,
            callback_context: ptr::null_mut(),
        }))
    }

    #[inline(always)]
    pub const fn get(&self) -> *mut TlgProvider {
        self.0.get()
    }
}

/// `_tlgHeader` (`.rdata$zETW0`): marks the start of the metadata blobs.
#[repr(C, packed)]
pub struct TlgHeader {
    pub signature: [u8; 4],
    pub size: u16,
    pub version: u8,
    pub flags: u8,
    pub magic: u64,
}

#[used]
#[link_section = ".rdata$zETW0"]
pub static TLG_HEADER: TlgHeader = TlgHeader {
    signature: *b"ETW0",
    size: core::mem::size_of::<TlgHeader>() as u16,
    version: 0,
    // Bit 0: image uses 64-bit pointers.
    flags: (core::mem::size_of::<usize>() == 8) as u8,
    magic: 0xBB8A_052B_8804_0E86,
};

/// End-of-blobs marker (`.rdata$zETW9`).
#[used]
#[link_section = ".rdata$zETW9"]
pub static TLG_END_OF_BLOBS: [u8; 4] = [TLG_BLOB_END, 0, 0, 0];

/// `_tlgEnableCallback` @ 0x004015A0.
///
/// Registered with `EventRegister`; ETW calls it whenever a session enables
/// or disables the provider. It caches the session's level and keyword masks
/// in the provider block so `TraceLoggingWrite` can test them without a call.
pub unsafe extern "system" fn tlg_enable_callback(
    source_id: *const GUID,
    control_code: u32,
    level: u8,
    keyword_any: u64,
    keyword_all: u64,
    filter_data: *mut EVENT_FILTER_DESCRIPTOR,
    callback_context: *mut c_void,
) {
    let provider = callback_context as *mut TlgProvider;
    if provider.is_null() {
        return;
    }

    match control_code {
        EVENT_CONTROL_CODE_DISABLE_PROVIDER => {
            ptr::write_volatile(addr_of_mut!((*provider).level_plus1), 0);
        }
        EVENT_CONTROL_CODE_ENABLE_PROVIDER => {
            // Level 0 means "all levels": stored as 256 so every UCHAR level passes.
            let level_plus1 = if level != 0 { level as u32 + 1 } else { 0x100 };
            ptr::write_volatile(addr_of_mut!((*provider).level_plus1), level_plus1);
            ptr::write_volatile(addr_of_mut!((*provider).keyword_any), keyword_any);
            ptr::write_volatile(addr_of_mut!((*provider).keyword_all), keyword_all);
        }
        _ => {}
    }

    if let Some(callback) = ptr::read_volatile(addr_of!((*provider).enable_callback)) {
        // The original routes this indirect call through the CFG check thunk.
        callback(
            source_id,
            control_code,
            level,
            keyword_any,
            keyword_all,
            filter_data,
            ptr::read_volatile(addr_of!((*provider).callback_context)),
        );
    }
}

/// `TraceLoggingRegister` @ 0x00401623.
///
/// Returns `S_OK` or `HRESULT_FROM_WIN32(EventRegister status)`. On success
/// it also hands ETW the provider traits (name + group) via
/// `EventSetInformation(EventProviderSetTraits)`, ignoring that result.
pub unsafe fn trace_logging_register(provider: *mut TlgProvider) -> HRESULT {
    let metadata = ptr::read_volatile(addr_of!((*provider).provider_metadata_ptr));

    // The provider GUID immediately precedes the metadata size field.
    let provider_id: GUID = ptr::read_unaligned((metadata as *const u8).sub(16) as *const GUID);

    if ptr::read_volatile(addr_of!((*provider).reg_handle)) != 0 {
        // Registering an already-registered provider is a programming error.
        fastfail(FAST_FAIL_INVALID_ARG);
    }

    ptr::write_volatile(addr_of_mut!((*provider).enable_callback), None);
    ptr::write_volatile(addr_of_mut!((*provider).callback_context), ptr::null_mut());

    let status = EventRegister(
        &provider_id,
        Some(tlg_enable_callback),
        provider as *mut c_void,
        addr_of_mut!((*provider).reg_handle),
    );

    if status != 0 {
        return hresult_from_win32(status);
    }

    let traits_size = ptr::read_unaligned(metadata) as u32;
    let _ = EventSetInformation(
        ptr::read_volatile(addr_of!((*provider).reg_handle)),
        EVENT_PROVIDER_SET_TRAITS,
        metadata as *const c_void,
        traits_size,
    );
    0
}

/// `TraceLoggingProviderEnabled(hProvider, level, keyword)` (inlined in the original).
#[inline(always)]
pub unsafe fn trace_logging_provider_enabled(provider: *const TlgProvider, level: u8, keyword: u64) -> bool {
    let level_plus1 = ptr::read_volatile(addr_of!((*provider).level_plus1));
    if (level as u32) >= level_plus1 {
        return false;
    }
    if keyword == 0 {
        return true;
    }
    let keyword_any = ptr::read_volatile(addr_of!((*provider).keyword_any));
    let keyword_all = ptr::read_volatile(addr_of!((*provider).keyword_all));
    (keyword & keyword_any) != 0 && (keyword & keyword_all) == keyword_all
}

/// `_tlgCreate1Sz_char`: describes a nul-terminated ANSI string payload
/// (the terminator is part of the data).
#[inline(always)]
pub unsafe fn tlg_create_1sz_char(desc: *mut EVENT_DATA_DESCRIPTOR, psz: *const u8) {
    let mut len = 0usize;
    while *psz.add(len) != 0 {
        len += 1;
    }
    ptr::write(
        desc,
        EVENT_DATA_DESCRIPTOR {
            Ptr: psz as usize as u64,
            Size: (len + 1) as u32,
            Reserved: EVENT_DATA_DESCRIPTOR_TYPE_NONE,
        },
    );
}

/// `_tlgWriteTransfer_EventWriteTransfer` @ 0x004016CF.
///
/// `event_metadata` points at the `Channel` byte of a `_TlgBlobEvent4` blob:
///
/// ```text
/// +0  UCHAR     Channel
/// +1  UCHAR     Level
/// +2  UCHAR     Opcode
/// +3  ULONGLONG Keyword        (unaligned)
/// +11 UINT16    RemainingSize  (start of the self-describing event metadata)
/// ```
///
/// `data[0]` and `data[1]` are reserved for the provider traits and event
/// metadata; the caller fills `data[2..]` with the payload.
pub unsafe fn tlg_write_transfer(
    provider: *const TlgProvider,
    event_metadata: *const u8,
    activity_id: *const GUID,
    related_activity_id: *const GUID,
    data_count: u32,
    data: *mut EVENT_DATA_DESCRIPTOR,
) -> u32 {
    let descriptor = EVENT_DESCRIPTOR {
        Id: 0,
        Version: 0,
        Channel: *event_metadata,
        Level: *event_metadata.add(1),
        Opcode: *event_metadata.add(2),
        Task: 0,
        Keyword: ptr::read_unaligned(event_metadata.add(3) as *const u64),
    };
    let event_metadata_size = event_metadata.add(11) as *const u16;

    let provider_metadata = ptr::read_volatile(addr_of!((*provider).provider_metadata_ptr));
    ptr::write(
        data,
        EVENT_DATA_DESCRIPTOR {
            Ptr: provider_metadata as usize as u64,
            Size: ptr::read_unaligned(provider_metadata) as u32,
            Reserved: EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA,
        },
    );
    ptr::write(
        data.add(1),
        EVENT_DATA_DESCRIPTOR {
            Ptr: event_metadata_size as usize as u64,
            Size: ptr::read_unaligned(event_metadata_size) as u32,
            Reserved: EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA,
        },
    );

    // The original keeps the zETW0..zETW9 run alive with a volatile
    // `&end - &header` store; do the same so the linker can never drop it.
    let mut keep_alive = 0usize;
    ptr::write_volatile(
        &mut keep_alive,
        (addr_of!(TLG_END_OF_BLOBS) as usize).wrapping_sub(addr_of!(TLG_HEADER) as usize),
    );

    EventWriteTransfer(
        ptr::read_volatile(addr_of!((*provider).reg_handle)),
        &descriptor,
        activity_id,
        related_activity_id,
        data_count,
        data,
    )
}
