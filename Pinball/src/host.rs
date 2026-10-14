//! Host API boundary. Native machine code is used only for ABI stack switching
//! and callback entry stubs, never to execute original game instructions.
use crate::{
    cpu::Cpu,
    generated::{self, CODE_LEN, START},
    SENTINEL,
};
use std::arch::{asm, global_asm};
use std::{collections::HashMap, ffi::CString, sync::OnceLock};
global_asm!(include_str!("bridge.s"));
#[no_mangle]
static mut BRIDGE_STACK: u32 = 0;
extern "C" {
    fn native_bridge(cpu: *mut Cpu, target: u32);
    fn callback_entry();
}
#[link(name = "kernel32")]
extern "system" {
    pub fn VirtualAlloc(addr: *mut u8, size: usize, allocation: u32, protect: u32) -> *mut u8;
    fn VirtualFree(addr: *mut u8, size: usize, kind: u32) -> i32;
    fn VirtualProtect(addr: *mut u8, size: usize, protect: u32, old: *mut u32) -> i32;
    fn LoadLibraryA(name: *const u8) -> u32;
    fn GetProcAddress(module: u32, name: *const u8) -> u32;
    pub fn GetModuleHandleA(name: *const u8) -> u32;
    fn SetErrorMode(mode: u32) -> u32;
    fn VirtualQuery(addr: *const u8, info: *mut u32, len: usize) -> usize;
}
static IMPORTS: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
static API_TRACE: OnceLock<bool> = OnceLock::new();
thread_local! {static CALLBACKS:std::cell::RefCell<HashMap<u32,u32>>=std::cell::RefCell::new(HashMap::new());}
pub struct Stack {
    addr: *mut u8,
    pub top: u32,
}
impl Stack {
    pub unsafe fn new() -> Self {
        let addr = VirtualAlloc(std::ptr::null_mut(), 4 * 1024 * 1024, 0x3000, 4);
        assert!(!addr.is_null());
        Self {
            addr,
            top: addr as u32 + 4 * 1024 * 1024 - 4096,
        }
    }
}
impl Stack {
    pub fn attach(&self, cpu: &mut Cpu) {
        cpu.stack_base = self.addr as u32 + 4 * 1024 * 1024;
        cpu.stack_limit = self.addr as u32;
        cpu.r[4] = self.top;
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        unsafe {
            VirtualFree(self.addr, 0, 0x8000);
        }
    }
}
pub unsafe fn initialize() {
    SetErrorMode(3);
    let image = include_bytes!("../generated/image.bin");
    assert_eq!(
        GetModuleHandleA(std::ptr::null()),
        generated::BASE,
        "Run the laid-out aipinball.exe produced by tools/check.py build"
    );
    let addr = (generated::BASE + 4096) as *mut u8;
    let mut info = [0u32; 7];
    VirtualQuery(addr, info.as_mut_ptr(), 28);
    assert!(
        info[5] == 4 || info[5] == 8,
        "reference data must be writable and non-executable: {info:08x?}"
    );
    std::ptr::copy_nonoverlapping(image.as_ptr().add(4096), addr, image.len() - 4096);
    let mut imports = HashMap::new();
    for &(dll, name, iat) in generated::IMPORTS {
        let library = CString::new(dll).unwrap();
        let module = LoadLibraryA(library.as_ptr() as _);
        assert_ne!(module, 0, "missing {dll}");
        let symbol = CString::new(name).unwrap();
        let target = GetProcAddress(module, symbol.as_ptr() as _);
        assert_ne!(target, 0, "missing {dll}!{name}");
        Cpu::write(iat, 4, target);
        imports.insert(target, name);
    }
    IMPORTS.set(imports).unwrap();
    API_TRACE
        .set(std::env::var_os("AIPINBALL_APITRACE").is_some())
        .unwrap();
    asm!("fninit", options(nostack));
}
pub unsafe fn callback(address: u32) -> u32 {
    if address.wrapping_sub(START) >= CODE_LEN as u32 {
        return address;
    }
    CALLBACKS.with(|map| {
        let mut map = map.borrow_mut();
        if let Some(&stub) = map.get(&address) {
            return stub;
        }
        let mem = VirtualAlloc(std::ptr::null_mut(), 4096, 0x3000, 4);
        assert!(!mem.is_null());
        // push original-address; jmp the Rust callback ABI entry.
        *mem = 0x68;
        std::ptr::write_unaligned(mem.add(1) as *mut u32, address);
        *mem.add(5) = 0xe9;
        std::ptr::write_unaligned(
            mem.add(6) as *mut u32,
            (callback_entry as *const () as u32).wrapping_sub(mem as u32 + 10),
        );
        let mut old = 0;
        assert_ne!(VirtualProtect(mem, 4096, 0x20, &mut old), 0);
        map.insert(address, mem as u32);
        mem as u32
    })
}
#[repr(C, align(16))]
struct FxState([u8; 512]);
#[no_mangle]
pub unsafe extern "C" fn callback_dispatch(frame: *const u32) -> u64 {
    let mut saved = FxState([0; 512]);
    asm!("fxsave [{p}]",p=in(reg) saved.0.as_mut_ptr(),options(nostack));
    asm!("fninit", "fldcw word ptr [{p}]",p=in(reg) saved.0.as_ptr(),options(nostack));
    let stack = Stack::new();
    let mut cpu = Cpu::new();
    stack.attach(&mut cpu);
    cpu.r = [
        *frame.add(7),
        *frame.add(6),
        *frame.add(5),
        *frame.add(4),
        stack.top,
        *frame.add(2),
        *frame.add(1),
        *frame,
    ];
    cpu.flags = *frame.add(8);
    cpu.ip = *frame.add(9);
    std::ptr::copy_nonoverlapping(frame.add(11), stack.top as *mut u32, 64);
    cpu.push(SENTINEL);
    cpu.run();
    let result = cpu.r[0] as u64 | ((cpu.r[4].wrapping_sub(stack.top) as u64) << 32);
    asm!("fxrstor [{p}]",p=in(reg) saved.0.as_ptr(),options(nostack));
    result
}
pub unsafe fn invoke(cpu: &mut Cpu, target: u32) {
    let name = IMPORTS
        .get()
        .and_then(|m| m.get(&target))
        .copied()
        .unwrap_or("dynamic");
    if API_TRACE.get() == Some(&true) {
        eprintln!(
            "API {name} ({target:08x}) @ {:08x} args {:08x} {:08x} {:08x} {:08x}",
            cpu.ip,
            Cpu::read(cpu.r[4], 4),
            Cpu::read(cpu.r[4] + 4, 4),
            Cpu::read(cpu.r[4] + 8, 4),
            Cpu::read(cpu.r[4] + 12, 4)
        );
    }
    match name {
        "RegisterClassA" => {
            let wc = Cpu::read(cpu.r[4], 4);
            let proc = Cpu::read(wc + 4, 4);
            Cpu::write(wc + 4, 4, callback(proc));
        }
        "DialogBoxParamA" | "DialogBoxIndirectParamA" => {
            let ptr = cpu.r[4] + 12;
            Cpu::write(ptr, 4, callback(Cpu::read(ptr, 4)));
        }
        "SetWindowLongA" => {
            if Cpu::read(cpu.r[4] + 4, 4) == (-4i32) as u32 {
                let ptr = cpu.r[4] + 8;
                Cpu::write(ptr, 4, callback(Cpu::read(ptr, 4)));
            }
        }
        "__setusermatherr" => {
            return;
        }
        "_initterm" => {
            let mut ptr = Cpu::read(cpu.r[4], 4);
            let end = Cpu::read(cpu.r[4] + 4, 4);
            let resume = cpu.ip;
            while ptr < end {
                let f = Cpu::read(ptr, 4);
                if f != 0 {
                    cpu.push(SENTINEL);
                    cpu.ip = f;
                    cpu.run();
                }
                ptr += 4;
            }
            cpu.ip = resume;
            return;
        }
        // Guest SEH addresses cannot be installed in the host's exception chain.
        "SetUnhandledExceptionFilter" => {
            cpu.r[0] = 0;
            cpu.r[4] += 4;
            return;
        }
        _ => {}
    }
    native_bridge(cpu, target);
}
