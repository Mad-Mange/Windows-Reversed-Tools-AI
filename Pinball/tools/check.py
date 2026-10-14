"""Local build/inspection runner. All outputs stay in the Pinball project."""
from pathlib import Path
import argparse,subprocess,sys,os,shutil,json
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('action',choices=['build','test','inspect','smoke','diagnose','debug','gui','disasm','core','binary','fmt'])
parser.add_argument('--release',action='store_true')
parser.add_argument('--trace',action='store_true')
parser.add_argument('--api-trace',action='store_true')
parser.add_argument('--seconds',type=float,default=8)
parser.add_argument('--address',type=lambda x:int(x,0),default=0x100833a)
parser.add_argument('--length',type=lambda x:int(x,0),default=0x300)
args=parser.parse_args()
if args.action=='fmt':
    subprocess.run(['cargo','fmt'],cwd=ROOT,check=True)
elif args.action=='binary':
    import binary_tests
    binary_tests.run()
elif args.action=='core':
    (ROOT/'artifacts').mkdir(exist_ok=True)
    subprocess.run([str(ROOT/'aipinball.exe'),'--verify-core'],cwd=ROOT,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
elif args.action=='disasm':
    import pefile,capstone
    pe=pefile.PE(str(ROOT/'PINBALL.EXE'));dis=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    for i in dis.disasm(pe.get_data(args.address-0x1000000,args.length),args.address):print(f'{i.address:08x} {i.mnemonic:8s} {i.op_str}')
elif args.action=='gui':
    import gui_test
    gui_test.run()
elif args.action=='debug':
    import debug
    debug.run()
elif args.action in ('build','test'):
    cmd=['cargo',args.action,'--target','i686-pc-windows-msvc']
    if args.release:cmd+=['--release']
    result=subprocess.run(cmd,cwd=ROOT)
    if result.returncode:sys.exit(result.returncode)
    if args.action=='build':
        shutil.copy2(ROOT/'target/i686-pc-windows-msvc'/('release' if args.release else 'debug')/'aipinball.exe',ROOT/'aipinball.exe')
        from layout import arrange
        arrange(ROOT/'aipinball.exe')
elif args.action=='diagnose':
    import pefile
    for binary in [ROOT/'target/i686-pc-windows-msvc/debug/aipinball.exe',ROOT/'aipinball.exe']:
        pe=pefile.PE(str(binary));print(binary,pe.get_warnings())
        print([(s.Name,hex(s.VirtualAddress),hex(s.Misc_VirtualSize),hex(s.PointerToRawData),hex(s.SizeOfRawData),hex(s.Characteristics)) for s in pe.sections])
        if hasattr(pe,'DIRECTORY_ENTRY_LOAD_CONFIG'):
            lc=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            vm=getattr(lc,'VolatileMetadataPointer',0)
            if vm:print('Volatile:',pe.get_data(vm-pe.OPTIONAL_HEADER.ImageBase,40).hex())
        print([(d.dll,hex(d.struct.OriginalFirstThunk),hex(d.struct.FirstThunk)) for d in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])])
        import struct
        dr=pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        desc=struct.unpack('<5I',pe.get_data(dr,20));print('Descriptor:',[hex(v) for v in desc])
        for rva in [desc[0],desc[3],desc[4]]:
            print(hex(rva),pe.get_data(rva,40).hex())
elif args.action=='inspect':
    import pefile
    for binary in ['PINBALL.EXE','aipinball.exe']:
        pe=pefile.PE(str(ROOT/binary));print(binary,hex(pe.OPTIONAL_HEADER.ImageBase),hex(pe.OPTIONAL_HEADER.SizeOfImage),'OS',pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,'subsystem',pe.OPTIONAL_HEADER.MajorSubsystemVersion,pe.OPTIONAL_HEADER.MinorSubsystemVersion,'characteristics',hex(pe.OPTIONAL_HEADER.DllCharacteristics))
    manifest=json.loads((ROOT/'generated/manifest.json').read_text())
    print({k:v for k,v in manifest.items() if k not in ('resources','opcode_counts_all_offsets')})
    print('Rust source files:',[(str(p.relative_to(ROOT)),p.stat().st_size) for p in (ROOT/'src').glob('*')])
    print('FPU forms:',len((ROOT/'generated/fpu.rs').read_text().splitlines()))
elif args.action=='smoke':
    env=os.environ.copy()
    if args.api_trace:env['AIPINBALL_APITRACE']='1'
    if args.trace:env['AIPINBALL_TRACE']='1'
    out=ROOT/'artifacts';out.mkdir(exist_ok=True)
    with (out/'smoke.log').open('w') as log:
        proc=subprocess.Popen([str(ROOT/'aipinball.exe')],cwd=ROOT,env=env,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
        try:code=proc.wait(timeout=args.seconds)
        except subprocess.TimeoutExpired:
            proc.terminate();proc.wait();code='still running at timeout'
    print('Process:',code)
    lines=(out/'smoke.log').read_text(errors='replace').splitlines()
    print('\n'.join(lines[-35:]))
