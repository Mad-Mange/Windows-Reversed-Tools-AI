//! Checks of recovered game math, run inside the final image's fixed data layout.
//! 0x01008ae9: normalize a float[2] in place and return its length in ST(0).
use crate::{cpu::Cpu, host::Stack, SENTINEL};
use std::arch::asm;
pub unsafe fn run() {
    let stack = Stack::new();
    let control: u16 = 0x027f;
    let cases: [([f32; 2], [f32; 2], f64); 7] = [
        ([0., 0.], [0., 0.], 0.),
        ([3., 4.], [0.6, 0.8], 5.),
        ([-3., 4.], [-0.6, 0.8], 5.),
        ([3., -4.], [0.6, -0.8], 5.),
        ([0., -5.], [0., -1.], 5.),
        ([13., 0.], [1., 0.], 13.),
        ([30000., 40000.], [0.6, 0.8], 50000.),
    ];
    for (input, expected, expected_len) in cases {
        let mut vector = input;
        let mut cpu = Cpu::new();
        stack.attach(&mut cpu);
        cpu.push(vector.as_mut_ptr() as u32);
        cpu.push(SENTINEL);
        cpu.ip = 0x01008ae9;
        asm!("fninit","fldcw word ptr [{p}]",p=in(reg) &control,options(nostack));
        cpu.run();
        let mut length = 0f64;
        asm!("fstp qword ptr [{p}]",p=in(reg) &mut length,options(nostack));
        assert_eq!(
            vector.map(f32::to_bits),
            expected.map(f32::to_bits),
            "normalize {input:?}"
        );
        assert_eq!(length, expected_len, "length {input:?}");
        assert_eq!(cpu.r[4], stack.top, "stdcall cleanup");
    }
    std::fs::write(
        "artifacts/core-checks.json",
        "{\"normalize_cases\":7,\"all_passed\":true}\n",
    )
    .unwrap();
    println!("7 recovered vector normalization cases passed (exact float bits and return values).");
}
