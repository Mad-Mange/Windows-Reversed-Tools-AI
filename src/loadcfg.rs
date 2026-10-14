//! Image load configuration (`_load_config_used`), normally supplied by the C
//! runtime's loadcfg.c. aicalc.exe has no C runtime, so it is defined here.
//!
//! It is what makes the image Control Flow Guard enabled like the original
//! (`IMAGE_DLLCHARACTERISTICS_GUARD_CF`). That matters beyond this image:
//! Windows only enforces CFG inside a process (for every CFG-built DLL it
//! loads, e.g. SHELL32 here) when the process's main executable is CFG-built.
//!
//! Layout and field values follow the original's 0xC4-byte
//! `IMAGE_LOAD_CONFIG_DIRECTORY32` at 0x00401008. The `__guard_*`,
//! `__safe_se_handler_*` and `__volatile_metadata` symbols are synthesised by
//! link.exe; "count"/"flags" symbols are absolute, so their *address* is the
//! value (as in loadcfg.c's `(DWORD)(size_t)&__guard_fids_count`).
//!
//! The `SecurityCookie` field is load-bearing: the loader refuses an x86
//! image whose subsystem version is 10.0 (as calc.exe's is) and whose load
//! configuration has no security cookie, failing process creation with
//! STATUS_INVALID_IMAGE_FORMAT (0xC000007B).

#![allow(non_upper_case_globals)]

use core::ptr::{addr_of, null};

use aicalc::startup::DEFAULT_SECURITY_COOKIE;

/// `__security_cookie` (.data @ 0x00403028). The loader replaces the default
/// value with a per-process random one before the entry point runs.
#[no_mangle]
pub static mut __security_cookie: usize = DEFAULT_SECURITY_COOKIE;

/// `__security_cookie_complement` (.data @ 0x0040302C).
#[no_mangle]
pub static mut __security_cookie_complement: usize = !DEFAULT_SECURITY_COOKIE;

extern "C" {
    static __safe_se_handler_table: u8;
    static __safe_se_handler_count: u8;
    static __guard_fids_table: u8;
    static __guard_fids_count: u8;
    static __guard_flags: u8;
    static __guard_iat_table: u8;
    static __guard_iat_count: u8;
    static __guard_longjmp_table: u8;
    static __guard_longjmp_count: u8;
    static __guard_eh_cont_table: u8;
    static __guard_eh_cont_count: u8;
    static __volatile_metadata: u8;
}

/// `_guard_check_icall_nop` @ 0x00402070: the CFG check used until the loader
/// installs the real one (and forever when CFG is off for the process).
unsafe extern "fastcall" fn guard_check_icall_nop(_target: usize) {}

/// `__guard_check_icall_fptr` (`.00cfg`): every CFG-instrumented indirect
/// call goes through this pointer; the loader overwrites it at startup.
#[no_mangle]
#[used]
#[link_section = ".00cfg"]
pub static __guard_check_icall_fptr: unsafe extern "fastcall" fn(usize) = guard_check_icall_nop;

/// `__castguard_check_failure_os_handled_fptr` (`.00cfg`), left null.
#[no_mangle]
#[used]
#[link_section = ".00cfg"]
pub static __castguard_check_failure_os_handled_fptr: usize = 0;

/// `IMAGE_LOAD_CONFIG_DIRECTORY32`, 0xC4 bytes.
#[repr(C)]
pub struct ImageLoadConfigDirectory32 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u32,
    de_commit_total_free_threshold: u32,
    lock_prefix_table: *const u8,
    maximum_allocation_size: u32,
    virtual_memory_threshold: u32,
    process_heap_flags: u32,
    process_affinity_mask: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: *const u8,
    security_cookie: *const u8,
    se_handler_table: *const u8,
    se_handler_count: *const u8,
    guard_cf_check_function_pointer: *const u8,
    guard_cf_dispatch_function_pointer: *const u8,
    guard_cf_function_table: *const u8,
    guard_cf_function_count: *const u8,
    guard_flags: *const u8,
    code_integrity_flags: u16,
    code_integrity_catalog: u16,
    code_integrity_catalog_offset: u32,
    code_integrity_reserved: u32,
    guard_address_taken_iat_entry_table: *const u8,
    guard_address_taken_iat_entry_count: *const u8,
    guard_long_jump_target_table: *const u8,
    guard_long_jump_target_count: *const u8,
    dynamic_value_reloc_table: *const u8,
    chpe_metadata_pointer: *const u8,
    guard_rf_failure_routine: *const u8,
    guard_rf_failure_routine_function_pointer: *const u8,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: *const u8,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: *const u8,
    volatile_metadata_pointer: *const u8,
    guard_eh_continuation_table: *const u8,
    guard_eh_continuation_count: *const u8,
    guard_xfg_check_function_pointer: *const u8,
    guard_xfg_dispatch_function_pointer: *const u8,
    guard_xfg_table_dispatch_function_pointer: *const u8,
    cast_guard_os_determined_failure_mode: *const u8,
    guard_memcpy_function_pointer: *const u8,
    uma_function_pointers: *const u8,
}

const _: () = assert!(core::mem::size_of::<ImageLoadConfigDirectory32>() == 0xC4);

#[repr(transparent)]
pub struct LoadConfig(ImageLoadConfigDirectory32);

// SAFETY: read-only image metadata; the raw pointers are only ever read by the loader.
unsafe impl Sync for LoadConfig {}

#[no_mangle]
#[used]
pub static _load_config_used: LoadConfig = LoadConfig(ImageLoadConfigDirectory32 {
    size: core::mem::size_of::<ImageLoadConfigDirectory32>() as u32,
    time_date_stamp: 0,
    major_version: 0,
    minor_version: 0,
    global_flags_clear: 0,
    global_flags_set: 0,
    critical_section_default_timeout: 0,
    de_commit_free_block_threshold: 0,
    de_commit_total_free_threshold: 0,
    lock_prefix_table: null(),
    maximum_allocation_size: 0,
    virtual_memory_threshold: 0,
    process_heap_flags: 0,
    process_affinity_mask: 0,
    csd_version: 0,
    dependent_load_flags: 0,
    edit_list: null(),
    security_cookie: addr_of!(__security_cookie) as *const u8,
    se_handler_table: addr_of!(__safe_se_handler_table),
    se_handler_count: addr_of!(__safe_se_handler_count),
    guard_cf_check_function_pointer: addr_of!(__guard_check_icall_fptr) as *const u8,
    guard_cf_dispatch_function_pointer: null(),
    guard_cf_function_table: addr_of!(__guard_fids_table),
    guard_cf_function_count: addr_of!(__guard_fids_count),
    guard_flags: addr_of!(__guard_flags),
    code_integrity_flags: 0,
    code_integrity_catalog: 0,
    code_integrity_catalog_offset: 0,
    code_integrity_reserved: 0,
    guard_address_taken_iat_entry_table: addr_of!(__guard_iat_table),
    guard_address_taken_iat_entry_count: addr_of!(__guard_iat_count),
    guard_long_jump_target_table: addr_of!(__guard_longjmp_table),
    guard_long_jump_target_count: addr_of!(__guard_longjmp_count),
    dynamic_value_reloc_table: null(),
    chpe_metadata_pointer: null(),
    guard_rf_failure_routine: null(),
    guard_rf_failure_routine_function_pointer: null(),
    dynamic_value_reloc_table_offset: 0,
    dynamic_value_reloc_table_section: 0,
    reserved2: 0,
    guard_rf_verify_stack_pointer_function_pointer: null(),
    hot_patch_table_offset: 0,
    reserved3: 0,
    enclave_configuration_pointer: null(),
    volatile_metadata_pointer: addr_of!(__volatile_metadata),
    guard_eh_continuation_table: addr_of!(__guard_eh_cont_table),
    guard_eh_continuation_count: addr_of!(__guard_eh_cont_count),
    guard_xfg_check_function_pointer: null(),
    guard_xfg_dispatch_function_pointer: null(),
    guard_xfg_table_dispatch_function_pointer: null(),
    cast_guard_os_determined_failure_mode: addr_of!(__castguard_check_failure_os_handled_fptr) as *const u8,
    guard_memcpy_function_pointer: null(),
    uma_function_pointers: null(),
});
