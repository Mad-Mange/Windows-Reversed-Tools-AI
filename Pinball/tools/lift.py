"""Decode PINBALL.EXE to a non-executable, address-indexed intermediate representation.

No upstream game source is used. Every possible instruction boundary is decoded,
so switch tables, indirect calls and instructions after embedded data are covered.
Only the Rust semantics engine executes the decoded records. Original code pages
are mapped PAGE_READWRITE, never executable.
"""
from pathlib import Path
import collections
import hashlib
import json
import struct
import re
import capstone as cs
from capstone import x86_const as x
import pefile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'generated'
OUT.mkdir(exist_ok=True)
p = pefile.PE(str(ROOT / 'PINBALL.EXE'))
BASE = p.OPTIONAL_HEADER.ImageBase
section = p.sections[0]
START = BASE + section.VirtualAddress
code = section.get_data()[:section.Misc_VirtualSize]
OPS = '''invalid mov movzx movsx lea push pop add adc sub sbb cmp test and or xor inc dec neg not shl shr sar rol ror rcl rcr shld shrd imul mul idiv div cdq cwd cwde cbw xchg call jmp ret leave nop int3 je jne jb jae jbe ja jl jge jle jg js jns jo jno jp jnp jecxz loop loope loopne sete setne setb setae setbe seta setl setge setle setg sets setns seto setno setp setnp cmove cmovne cmovb cmovae cmovbe cmova cmovl cmovge cmovle cmovg pushfd popfd pushal popal sahf lahf cld std clc stc cmc movsb movsw movsd stosb stosw stosd lodsb lodsw lodsd scasb scasw scasd cmpsb cmpsw cmpsd fld fst fstp fild fist fistp fisttp fldz fld1 fldpi fldl2e fldl2t fldlg2 fldln2 fadd faddp fsub fsubp fsubr fsubrp fmul fmulp fdiv fdivp fdivr fdivrp fiadd fisub fisubr fimul fidiv fidivr fcom fcomp fcompp fucom fucomp fucompp ficom ficomp fxch fchs fabs fsqrt fsin fcos fsincos fptan fpatan fyl2x fyl2xp1 f2xm1 fscale fprem fprem1 frndint ftst fxam fnstsw fnstcw fldcw fnclex fninit ffree fincstp fdecstp wait fnop'''.split()
REGS = {n: (i, 4) for i, n in enumerate(['eax','ecx','edx','ebx','esp','ebp','esi','edi'])}
REGS.update({n: (i, 2) for i,n in enumerate(['ax','cx','dx','bx','sp','bp','si','di'])})
REGS.update({n: (i, 1) for i,n in enumerate(['al','cl','dl','bl'])})
REGS.update({n: (i+8, 1) for i,n in enumerate(['ah','ch','dh','bh'])})
REGS.update({f'st({i})': (16+i, 10) for i in range(8)})
REGS.update({f'st{i}': (16+i, 10) for i in range(8)})

def operand(d, o):
    if o.type == x.X86_OP_IMM:
        return struct.pack('<8BI', 2,o.size,0,0,0,0,0,0,o.imm & 0xffffffff)
    if o.type == x.X86_OP_REG:
        name=d.reg_name(o.reg)
        r,w=REGS.get(name,(255,o.size))
        return struct.pack('<8BI',1,w,r,0,0,0,0,0,0)
    if o.type == x.X86_OP_MEM:
        m=o.mem
        r=REGS.get(d.reg_name(m.base),(255,0))[0]
        idx=REGS.get(d.reg_name(m.index),(255,0))[0]
        return struct.pack('<8BI',3,o.size,r,idx,m.scale,1 if m.segment==x.X86_REG_FS else 0,0,0,m.disp & 0xffffffff)
    return bytes(12)

decoder=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32)
decoder.detail=True
counts=collections.Counter()
fp_forms={}
records=bytearray()
for offset in range(len(code)):
    d=next(decoder.disasm(code[offset:offset+15], START+offset, count=1),None)
    if d is None:
        records.extend(bytes(44)); continue
    mn=d.mnemonic.split()[-1]
    mn={'sal':'shl','retn':'ret'}.get(mn,mn)
    op=OPS.index(mn) if mn in OPS else 0
    prefix=1 if 0xf3 in d.prefix else 2 if 0xf2 in d.prefix else 0
    operands=list(d.operands)
    if mn in OPS and OPS.index(mn)>=OPS.index('fld'):
        packed=[operand(d,o) for o in operands]
        aa=packed[0] if packed else bytes(12)
        bb=packed[1] if len(packed)>1 else bytes(12)
        key=(mn,aa[0],aa[1],aa[2],bb[2])
        asm=re.sub(r'\[[^]]*\]', '[{p}]',d.op_str).replace('xword ptr','tbyte ptr')
        fp_forms[key]=(mn+' '+asm).strip()
    if len(operands)>3: op=0
    records.extend(struct.pack('<H6B',op,d.size,min(3,len(operands)),prefix,0,0,0))
    records.extend(b''.join(operand(d,o) for o in operands[:3]).ljust(36,b'\0'))
    counts[mn]+=1
(OUT/'instructions.bin').write_bytes(records)
(OUT/'image.bin').write_bytes(p.get_memory_mapped_image().ljust(p.OPTIONAL_HEADER.SizeOfImage,b'\0'))
imports=[]
for dll in p.DIRECTORY_ENTRY_IMPORT:
    for imp in dll.imports:
        imports.append({'dll':dll.dll.decode(),'name':imp.name.decode() if imp.name else '#'+str(imp.ordinal),'address':imp.address})
(OUT/'imports.json').write_text(json.dumps(imports,indent=2))
rs='// Generated from PINBALL.EXE by tools/lift.py. Do not edit.\n'
rs+=f'pub const BASE: u32 = {BASE};\npub const START: u32 = {START};\npub const CODE_LEN: usize = {len(code)};\npub const ENTRY: u32 = {BASE+p.OPTIONAL_HEADER.AddressOfEntryPoint};\n'
rs+='pub const IMPORTS: &[(&str, &str, u32)] = &[\n'
rs+=''.join(f'({json.dumps(i["dll"])},{json.dumps(i["name"])},{i["address"]}),\n' for i in imports)+'];\n'
rs+='#[allow(non_camel_case_types)]\n#[derive(Clone,Copy,Debug,PartialEq)]\n#[repr(u16)]\npub enum Op {\n'+','.join(f'{"loop_" if name=="loop" else name}={i}' for i,name in enumerate(OPS))+'}\n'
(OUT/'metadata.rs').write_text(rs)
fp='// Generated x87 operations preserve the original 80-bit arithmetic.\nuse crate::{cpu::{Cpu,Inst},generated::Op};\nuse std::arch::asm;\npub unsafe fn execute(cpu:&mut Cpu,i:Inst) { let a=i.a[0]; let b=i.a[1]; let p=cpu.addr(a);\nmatch (i.op,a.kind,a.width,a.reg,b.reg) {\n'
for (mn,k,w,r,r2),asm in sorted(fp_forms.items()):
    if '{p}' in asm:
        stmt='asm!('+json.dumps(asm)+',p=in(reg) p,options(nostack));'
    elif asm.endswith(' ax'):
        stmt='let status:u16; asm!('+json.dumps(asm)+',out("ax") status,options(nostack)); cpu.r[0]=(cpu.r[0]&0xffff0000)|status as u32;'
    else:
        stmt='asm!('+json.dumps(asm)+',options(nostack));'
    fp+=f'(Op::{mn},{k},{w},{r},{r2})=>{{{stmt}}},\n'
fp+='_=>panic!("unsupported x87 form: {i:?}"),\n}}\n'
(OUT/'fpu.rs').write_text(fp)

def ident(e):
    if e.name is not None:
        return str(e.name).encode('utf-16le')+b'\0\0'
    return struct.pack('<HH',0xffff,e.id)
def align(b): return b+b'\0'*((-len(b))%4)
res=struct.pack('<IIHHHHIHHII',0,32,0xffff,0,0xffff,0,0,0,0,0,0)
resources=[]
for typ in p.DIRECTORY_ENTRY_RESOURCE.entries:
    for name in typ.directory.entries:
        for lang in name.directory.entries:
            data=p.get_data(lang.data.struct.OffsetToData,lang.data.struct.Size)
            names=align(ident(typ)+ident(name))
            header=struct.pack('<II',len(data),8+len(names)+16)+names+struct.pack('<IHHII',0,0x1030,lang.id,0,0)
            res+=header+align(data)
            resources.append({'type':typ.id,'id':name.id,'lang':lang.id,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
(OUT/'original.res').write_bytes(res)
(OUT/'manifest.json').write_text(json.dumps({'sha256':hashlib.sha256((ROOT/'PINBALL.EXE').read_bytes()).hexdigest(),'image_base':BASE,'entry':BASE+p.OPTIONAL_HEADER.AddressOfEntryPoint,'code_size':len(code),'decoded_offsets':len(records)//44,'resources':resources,'opcode_counts_all_offsets':dict(counts)},indent=2))
decoder.skipdata=True
with (OUT/'pinball.disasm.txt').open('w') as f:
    for d in decoder.disasm(code,START):
        f.write(f'{d.address:08x}  {d.bytes.hex():30s} {d.mnemonic:12s} {d.op_str}'.rstrip() + '\n')
print(f'Lifted {len(code):,} instruction offsets, {len(imports)} imports, {len(resources)} resources.')
