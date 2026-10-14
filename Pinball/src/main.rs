#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(not(target_arch = "x86"))]
compile_error!("Build with --target i686-pc-windows-msvc");
mod core_checks;
mod cpu;
mod host;
#[allow(dead_code)]
mod generated {
    include!("../generated/metadata.rs");
}
mod fpu {
    include!("../generated/fpu.rs");
}
const SENTINEL: u32 = 0xfffffff0;
fn main() {
    std::panic::set_hook(Box::new(|info| {
        let text = format!("{info}\n");
        eprintln!("{text}");
        let _ = std::fs::write("aipinball-error.log", text);
    }));
    unsafe {
        host::initialize();
        if std::env::args().any(|a| a == "--verify-core") {
            core_checks::run();
            return;
        }
        let stack = host::Stack::new();
        let mut cpu = cpu::Cpu::new();
        stack.attach(&mut cpu);
        cpu.ip = generated::ENTRY;
        cpu.push(SENTINEL);
        cpu.run();
    }
}
