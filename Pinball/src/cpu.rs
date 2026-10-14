//! Rust semantics for the decoded 32-bit x86 IR. No original instructions execute.
use crate::generated::{Op, CODE_LEN, START};
use std::ptr::{read_unaligned, write_unaligned};

pub const CF: u32 = 1;
pub const PF: u32 = 4;
pub const AF: u32 = 16;
pub const ZF: u32 = 64;
pub const SF: u32 = 128;
pub const DF: u32 = 1024;
pub const OF: u32 = 2048;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Operand {
    pub kind: u8,
    pub width: u8,
    pub reg: u8,
    pub index: u8,
    pub scale: u8,
    pub seg: u8,
    pub pad: [u8; 2],
    pub value: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Inst {
    pub op: Op,
    pub len: u8,
    pub count: u8,
    pub prefix: u8,
    pub pad: [u8; 3],
    pub a: [Operand; 3],
}
const IR: &[u8] = include_bytes!("../generated/instructions.bin");
#[repr(C)]
pub struct Cpu {
    pub r: [u32; 8],
    pub flags: u32,
    pub ip: u32,
    pub native_target: u32,
    pub stack_base: u32,
    pub stack_limit: u32,
    pub fs0: u32,
    pub steps: u64,
    pub trace: bool,
    pub recent: [u32; 64],
}
impl Cpu {
    pub fn new() -> Self {
        Self {
            r: [0; 8],
            flags: 0x202,
            ip: 0,
            native_target: 0,
            stack_base: 0,
            stack_limit: 0,
            fs0: u32::MAX,
            steps: 0,
            trace: std::env::var_os("AIPINBALL_TRACE").is_some(),
            recent: [0; 64],
        }
    }
    #[inline]
    pub unsafe fn read(addr: u32, w: u8) -> u32 {
        match w {
            1 => read_unaligned(addr as *const u8) as u32,
            2 => read_unaligned(addr as *const u16) as u32,
            4 => read_unaligned(addr as *const u32),
            _ => panic!("bad integer width {w}"),
        }
    }
    #[inline]
    pub unsafe fn write(addr: u32, w: u8, v: u32) {
        match w {
            1 => write_unaligned(addr as *mut u8, v as u8),
            2 => write_unaligned(addr as *mut u16, v as u16),
            4 => write_unaligned(addr as *mut u32, v),
            _ => panic!("bad integer width {w}"),
        }
    }
    #[inline]
    pub fn addr(&self, o: Operand) -> u32 {
        o.value
            .wrapping_add(if o.reg < 8 { self.r[o.reg as usize] } else { 0 })
            .wrapping_add(if o.index < 8 {
                self.r[o.index as usize].wrapping_mul(o.scale as u32)
            } else {
                0
            })
    }
    #[inline]
    pub unsafe fn get(&self, o: Operand) -> u32 {
        match o.kind {
            1 => {
                if o.reg < 8 {
                    self.r[o.reg as usize] & mask(o.width)
                } else if o.reg < 12 {
                    (self.r[(o.reg - 8) as usize] >> 8) & 255
                } else {
                    panic!("bad reg {o:?}")
                }
            }
            2 => o.value & mask(o.width),
            3 => {
                if o.seg == 1 {
                    assert_eq!(self.addr(o), 0, "unsupported TEB access");
                    self.fs0
                } else {
                    Self::read(self.addr(o), o.width)
                }
            }
            _ => 0,
        }
    }
    #[inline]
    pub unsafe fn set(&mut self, o: Operand, v: u32) {
        let m = mask(o.width);
        match o.kind {
            1 => {
                if o.reg < 8 {
                    let r = &mut self.r[o.reg as usize];
                    *r = (*r & !m) | (v & m)
                } else if o.reg < 12 {
                    let r = &mut self.r[(o.reg - 8) as usize];
                    *r = (*r & !0xff00) | ((v & 255) << 8)
                } else {
                    panic!("bad reg {o:?}")
                }
            }
            3 => {
                if o.seg == 1 {
                    assert_eq!(self.addr(o), 0);
                    self.fs0 = v
                } else {
                    Self::write(self.addr(o), o.width, v)
                }
            }
            _ => panic!("bad destination {o:?}"),
        }
    }
    #[inline]
    pub unsafe fn push(&mut self, v: u32) {
        self.r[4] = self.r[4].wrapping_sub(4);
        Self::write(self.r[4], 4, v)
    }
    #[inline]
    pub unsafe fn pop(&mut self) -> u32 {
        let v = Self::read(self.r[4], 4);
        self.r[4] = self.r[4].wrapping_add(4);
        v
    }
    #[inline]
    fn zsp(&mut self, v: u32, w: u8) {
        let v = v & mask(w);
        self.flags = (self.flags & !(ZF | SF | PF))
            | if v == 0 { ZF } else { 0 }
            | if v & (1 << (w * 8 - 1)) != 0 { SF } else { 0 }
            | if (v as u8).count_ones() % 2 == 0 {
                PF
            } else {
                0
            };
    }
    #[inline]
    pub fn arithmetic(&mut self, a: u32, b: u32, w: u8, subtract: bool, carry: u32) -> u32 {
        let m = mask(w);
        let a = a & m;
        let b = b & m;
        let sign = 1 << (w * 8 - 1);
        let full = if subtract {
            (a as u64).wrapping_sub(b as u64 + carry as u64)
        } else {
            a as u64 + b as u64 + carry as u64
        };
        let v = full as u32 & m;
        let cf = if subtract {
            (a as u64) < b as u64 + carry as u64
        } else {
            full > m as u64
        };
        let of = if subtract {
            ((a ^ b) & (a ^ v) & sign) != 0
        } else {
            (!(a ^ b) & (a ^ v) & sign) != 0
        };
        self.flags = (self.flags & !(CF | OF | AF))
            | if cf { CF } else { 0 }
            | if of { OF } else { 0 }
            | if (a ^ b ^ v) & 16 != 0 { AF } else { 0 };
        self.zsp(v, w);
        v
    }
    #[inline]
    fn condition(&self, n: u16) -> bool {
        let f = self.flags;
        let z = f & ZF != 0;
        let c = f & CF != 0;
        let s = f & SF != 0;
        let o = f & OF != 0;
        let p = f & PF != 0;
        match n {
            0 => z,
            1 => !z,
            2 => c,
            3 => !c,
            4 => c || z,
            5 => !c && !z,
            6 => s != o,
            7 => s == o,
            8 => z || s != o,
            9 => !z && s == o,
            10 => s,
            11 => !s,
            12 => o,
            13 => !o,
            14 => p,
            15 => !p,
            _ => unreachable!(),
        }
    }
    pub unsafe fn run(&mut self) {
        while self.ip != crate::SENTINEL {
            self.step();
        }
    }
    pub unsafe fn step(&mut self) {
        let offset = self.ip.wrapping_sub(START) as usize;
        if offset >= CODE_LEN {
            let target = self.ip;
            let return_ip = self.pop();
            crate::host::invoke(self, target);
            self.ip = return_ip;
            return;
        }
        let i = read_unaligned(IR.as_ptr().add(offset * 44) as *const Inst);
        self.recent[(self.steps as usize) & 63] = self.ip;
        self.steps += 1;
        if self.trace {
            eprintln!(
                "{:08x} {:?} r={:08x?} f={:04x}",
                self.ip, i, self.r, self.flags
            );
        }
        let old_ip = self.ip;
        self.ip = self.ip.wrapping_add(i.len as u32);
        let a = i.a[0];
        let b = i.a[1];
        let c = i.a[2];
        let op = i.op;
        use Op::*;
        match op {
            mov | movzx => {
                let v = self.get(b);
                self.set(a, v)
            }
            movsx => {
                let v = signed(self.get(b), b.width) as u32;
                self.set(a, v)
            }
            lea => self.set(a, self.addr(b)),
            push => {
                let v = self.get(a);
                self.push(v)
            }
            pop => {
                let v = self.pop();
                self.set(a, v)
            }
            add | adc | sub | sbb | cmp => {
                let carry = if op == adc || op == sbb {
                    self.flags & CF
                } else {
                    0
                };
                let v = self.arithmetic(
                    self.get(a),
                    self.get(b),
                    a.width,
                    op == sub || op == sbb || op == cmp,
                    carry,
                );
                if op != cmp {
                    self.set(a, v)
                }
            }
            and | or | xor | test => {
                let av = self.get(a);
                let bv = self.get(b);
                let v = match op {
                    and | test => av & bv,
                    or => av | bv,
                    _ => av ^ bv,
                };
                self.flags &= !(CF | OF | AF);
                self.zsp(v, a.width);
                if op != test {
                    self.set(a, v)
                }
            }
            inc | dec => {
                let carry = self.flags & CF;
                let v = self.arithmetic(self.get(a), 1, a.width, op == dec, 0);
                self.flags = (self.flags & !CF) | carry;
                self.set(a, v)
            }
            neg => {
                let v = self.arithmetic(0, self.get(a), a.width, true, 0);
                self.set(a, v)
            }
            not => {
                let v = !self.get(a);
                self.set(a, v)
            }
            shl | shr | sar | rol | ror | rcl | rcr => {
                let mut count = self.get(b) & 31;
                let bits = a.width as u32 * 8;
                let mut v = self.get(a);
                let original = v;
                if op == rol || op == ror {
                    count %= bits;
                }
                if op == rcl || op == rcr {
                    if bits < 32 {
                        count %= bits + 1;
                    }
                }
                if count > 0 {
                    for _ in 0..count {
                        let carry = self.flags & CF;
                        let next;
                        match op {
                            shl | rol | rcl => {
                                next = (v >> (bits - 1)) & 1;
                                v = (v << 1)
                                    | if op == rol {
                                        next
                                    } else if op == rcl {
                                        carry
                                    } else {
                                        0
                                    };
                                v &= mask(a.width)
                            }
                            _ => {
                                next = v & 1;
                                v = match op {
                                    sar => (signed(v, a.width) >> 1) as u32 & mask(a.width),
                                    ror => (v >> 1) | (next << (bits - 1)),
                                    rcr => (v >> 1) | (carry << (bits - 1)),
                                    _ => v >> 1,
                                }
                            }
                        }
                        self.flags = (self.flags & !CF) | next;
                    }
                    if count == 1 {
                        let ov = match op {
                            shl | rol | rcl => ((v >> (bits - 1)) ^ (self.flags & CF)) & 1,
                            shr => original >> (bits - 1),
                            sar => 0,
                            _ => ((v >> (bits - 1)) ^ (v >> (bits - 2))) & 1,
                        };
                        self.flags = (self.flags & !OF) | if ov != 0 { OF } else { 0 };
                    }
                    if op == shl || op == shr || op == sar {
                        self.zsp(v, a.width);
                    }
                    self.set(a, v);
                }
            }
            shld | shrd => {
                let n = self.get(c) & 31;
                if n > 0 {
                    let av = self.get(a);
                    let bv = self.get(b);
                    let bits = a.width as u32 * 8;
                    let v = if op == shld {
                        (av << n) | (bv >> (bits - n))
                    } else {
                        (av >> n) | (bv << (bits - n))
                    };
                    let cf = if op == shld {
                        (av >> (bits - n)) & 1
                    } else {
                        (av >> (n - 1)) & 1
                    };
                    self.flags = (self.flags & !CF) | cf;
                    if n == 1 {
                        self.flags = (self.flags & !OF)
                            | if (av ^ v) & (1 << (bits - 1)) != 0 {
                                OF
                            } else {
                                0
                            };
                    }
                    self.zsp(v, a.width);
                    self.set(a, v);
                }
            }
            imul | mul => {
                let w = a.width;
                let bits = w as u32 * 8;
                let (av, bv) = if i.count == 1 {
                    (self.r[0] & mask(w), self.get(a))
                } else if i.count == 2 {
                    (self.get(a), self.get(b))
                } else {
                    (self.get(b), self.get(c))
                };
                let full = if op == imul {
                    (signed(av, w) as i64).wrapping_mul(signed(bv, w) as i64) as u64
                } else {
                    (av as u64) * (bv as u64)
                };
                let v = full as u32 & mask(w);
                let overflow = if op == imul {
                    full as i64 != signed(v, w) as i64
                } else {
                    full >> bits != 0
                };
                self.flags = (self.flags & !(CF | OF)) | if overflow { CF | OF } else { 0 };
                if i.count == 1 {
                    if w == 1 {
                        self.r[0] = (self.r[0] & 0xffff0000) | (full as u32 & 65535)
                    } else {
                        self.r[0] = (self.r[0] & !mask(w)) | v;
                        self.r[2] = (self.r[2] & !mask(w)) | ((full >> bits) as u32 & mask(w));
                    }
                } else {
                    self.set(a, v)
                }
            }
            div | idiv => {
                let w = a.width;
                let bits = w as u32 * 8;
                let denominator = self.get(a);
                let numerator = if w == 1 {
                    (self.r[0] & 65535) as u64
                } else {
                    ((self.r[2] & mask(w)) as u64) << bits | (self.r[0] & mask(w)) as u64
                };
                let (q, r) = if op == idiv {
                    let n = if w == 4 {
                        numerator as i64
                    } else {
                        let shift = 64 - bits * 2;
                        (numerator as i64) << shift >> shift
                    };
                    let d = signed(denominator, w) as i64;
                    ((n / d) as u64, (n % d) as u64)
                } else {
                    (
                        numerator / denominator as u64,
                        numerator % denominator as u64,
                    )
                };
                if w == 1 {
                    self.r[0] =
                        (self.r[0] & 0xffff0000) | (q as u32 & 255) | ((r as u32 & 255) << 8)
                } else {
                    self.r[0] = (self.r[0] & !mask(w)) | (q as u32 & mask(w));
                    self.r[2] = (self.r[2] & !mask(w)) | (r as u32 & mask(w));
                }
            }
            cdq => self.r[2] = ((self.r[0] as i32) >> 31) as u32,
            cwd => {
                self.r[2] = (self.r[2] & 0xffff0000) | (((self.r[0] as i16) >> 15) as u16 as u32)
            }
            cwde => self.r[0] = self.r[0] as i16 as i32 as u32,
            cbw => self.r[0] = (self.r[0] & 0xffff0000) | (self.r[0] as i8 as i16 as u16 as u32),
            xchg => {
                let av = self.get(a);
                let bv = self.get(b);
                self.set(a, bv);
                self.set(b, av)
            }
            call => {
                let target = self.get(a);
                if target.wrapping_sub(START) < CODE_LEN as u32 {
                    self.push(self.ip);
                    self.ip = target
                } else {
                    crate::host::invoke(self, target)
                }
            }
            jmp => self.ip = self.get(a),
            ret => {
                self.ip = self.pop();
                if i.count > 0 {
                    self.r[4] = self.r[4].wrapping_add(self.get(a));
                }
            }
            leave => {
                self.r[4] = self.r[5];
                self.r[5] = self.pop()
            }
            nop | wait => {}
            je | jne | jb | jae | jbe | ja | jl | jge | jle | jg | js | jns | jo | jno | jp
            | jnp => {
                if self.condition(op as u16 - je as u16) {
                    self.ip = self.get(a)
                }
            }
            sete | setne | setb | setae | setbe | seta | setl | setge | setle | setg | sets
            | setns | seto | setno | setp | setnp => {
                self.set(a, self.condition(op as u16 - sete as u16) as u32)
            }
            cmove | cmovne | cmovb | cmovae | cmovbe | cmova | cmovl | cmovge | cmovle | cmovg => {
                if self.condition(op as u16 - cmove as u16) {
                    let v = self.get(b);
                    self.set(a, v)
                }
            }
            jecxz => {
                if self.r[1] == 0 {
                    self.ip = self.get(a)
                }
            }
            loop_ | loope | loopne => {
                self.r[1] = self.r[1].wrapping_sub(1);
                if self.r[1] != 0
                    && (op == loop_
                        || op == loope && self.flags & ZF != 0
                        || op == loopne && self.flags & ZF == 0)
                {
                    self.ip = self.get(a)
                }
            }
            pushfd => self.push(self.flags),
            popfd => self.flags = self.pop(),
            pushal => {
                let regs = self.r;
                for v in regs {
                    self.push(v)
                }
            }
            popal => {
                for n in (0..8).rev() {
                    let v = self.pop();
                    if n != 4 {
                        self.r[n] = v
                    }
                }
            }
            sahf => self.flags = (self.flags & !0xd5) | ((self.r[0] >> 8) & 0xd5),
            lahf => self.r[0] = (self.r[0] & !0xff00) | ((self.flags & 0xd5 | 2) << 8),
            cld => self.flags &= !DF,
            std => self.flags |= DF,
            clc => self.flags &= !CF,
            stc => self.flags |= CF,
            cmc => self.flags ^= CF,
            movsb | movsw | movsd | stosb | stosw | stosd | lodsb | lodsw | lodsd | scasb
            | scasw | scasd | cmpsb | cmpsw | cmpsd => {
                let w = match op {
                    movsb | stosb | lodsb | scasb | cmpsb => 1,
                    movsw | stosw | lodsw | scasw | cmpsw => 2,
                    _ => 4,
                };
                let step = if self.flags & DF != 0 {
                    0u32.wrapping_sub(w as u32)
                } else {
                    w as u32
                };
                let repeat = i.prefix != 0;
                let mut count = if repeat { self.r[1] } else { 1 };
                while count > 0 {
                    match op {
                        movsb | movsw | movsd => {
                            Self::write(self.r[7], w, Self::read(self.r[6], w));
                            self.r[6] = self.r[6].wrapping_add(step);
                            self.r[7] = self.r[7].wrapping_add(step)
                        }
                        stosb | stosw | stosd => {
                            Self::write(self.r[7], w, self.r[0]);
                            self.r[7] = self.r[7].wrapping_add(step)
                        }
                        lodsb | lodsw | lodsd => {
                            self.r[0] = (self.r[0] & !mask(w)) | Self::read(self.r[6], w);
                            self.r[6] = self.r[6].wrapping_add(step)
                        }
                        scasb | scasw | scasd => {
                            self.arithmetic(self.r[0], Self::read(self.r[7], w), w, true, 0);
                            self.r[7] = self.r[7].wrapping_add(step)
                        }
                        _ => {
                            self.arithmetic(
                                Self::read(self.r[6], w),
                                Self::read(self.r[7], w),
                                w,
                                true,
                                0,
                            );
                            self.r[6] = self.r[6].wrapping_add(step);
                            self.r[7] = self.r[7].wrapping_add(step)
                        }
                    }
                    count -= 1;
                    if repeat {
                        self.r[1] = count;
                    }
                    if matches!(op, scasb | scasw | scasd | cmpsb | cmpsw | cmpsd)
                        && repeat
                        && ((i.prefix == 1 && self.flags & ZF == 0)
                            || (i.prefix == 2 && self.flags & ZF != 0))
                    {
                        break;
                    }
                }
            }
            _ if op as u16 >= fld as u16 => crate::fpu::execute(self, i),
            _ => panic!(
                "unsupported instruction at {old_ip:08x}: {i:?}; registers={:08x?}, recent={:08x?}",
                self.r, self.recent
            ),
        }
    }
}
#[inline]
pub fn mask(w: u8) -> u32 {
    match w {
        1 => 255,
        2 => 65535,
        _ => u32::MAX,
    }
}
#[inline]
pub fn signed(v: u32, w: u8) -> i32 {
    match w {
        1 => v as i8 as i32,
        2 => v as i16 as i32,
        _ => v as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout() {
        assert_eq!(std::mem::size_of::<Inst>(), 44);
        assert_eq!(std::mem::size_of::<Operand>(), 12);
    }
    #[test]
    fn arithmetic_edges() {
        let mut c = Cpu::new();
        assert_eq!(c.arithmetic(0x7fffffff, 1, 4, false, 0), 0x80000000);
        assert_ne!(c.flags & OF, 0);
        assert_eq!(c.flags & CF, 0);
        assert_eq!(c.arithmetic(0, 1, 4, true, 0), u32::MAX);
        assert_ne!(c.flags & CF, 0);
        assert_eq!(c.arithmetic(255, 0, 1, false, 1), 0);
        assert_eq!(c.flags & (CF | ZF | PF), CF | ZF | PF);
    }
    #[test]
    fn byte_arithmetic_exhaustive() {
        let mut c = Cpu::new();
        for a in 0..256 {
            for b in 0..256 {
                for carry in 0..2 {
                    for sub in [false, true] {
                        let result = c.arithmetic(a, b, 1, sub, carry);
                        let math = if sub {
                            a as i32 - b as i32 - carry as i32
                        } else {
                            a as i32 + b as i32 + carry as i32
                        };
                        assert_eq!(result, math as u32 & 255);
                        assert_eq!(c.flags & CF != 0, math < 0 || math > 255);
                        let signed_math = if sub {
                            a as i8 as i32 - b as i8 as i32 - carry as i32
                        } else {
                            a as i8 as i32 + b as i8 as i32 + carry as i32
                        };
                        assert_eq!(c.flags & OF != 0, !(-128..128).contains(&signed_math));
                    }
                }
            }
        }
    }
}
