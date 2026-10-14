"""Reserve the reference's fixed addresses in a Rust-produced PE image.

Rust links normally (with its relocation table). Its sections are relocated above
the reference address range; a non-executable .guest section occupies that range.
This is PE layout work only: no original executable instructions are installed as
executable code. All imported and callback code belongs to Rust or Windows DLLs.
"""
import struct
from pathlib import Path
import pefile

BASE=0x1000000
DELTA=0x50000
def arrange(path):
    path=Path(path)
    p=pefile.PE(str(path))
    if p.sections[0].Name.rstrip(b'\0')==b'.guest':return
    assert hasattr(p,'DIRECTORY_ENTRY_BASERELOC'),'Rust PE needs base relocations'
    # Absolute VA fixups include TLS, load config and all compiled data pointers.
    data=bytearray(path.read_bytes())
    def read(at):return struct.unpack_from('<I',data,at)[0]
    def write(at,value):struct.pack_into('<I',data,at,value)
    def bump(at):
        if read(at):write(at,read(at)+DELTA)
    def off(rva):return p.get_offset_from_rva(rva)
    relocation_delta=BASE+DELTA-p.OPTIONAL_HEADER.ImageBase
    for block in p.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.type==0:continue
            assert entry.type==3, f'unsupported native PE relocation {entry.type}'
            at=off(entry.rva);write(at,(read(at)+relocation_delta)&0xffffffff)
    for imp in p.DIRECTORY_ENTRY_IMPORT:
        s=imp.struct
        for name in ['OriginalFirstThunk','Name','FirstThunk']:bump(s.get_field_absolute_offset(name))
        for rva in set([s.OriginalFirstThunk,s.FirstThunk]):
            if not rva:continue
            ptr=off(rva)
            while read(ptr):
                if read(ptr)&0x80000000==0:bump(ptr)
                ptr+=4
    if hasattr(p,'DIRECTORY_ENTRY_RESOURCE'):
        def walk(directory):
            for entry in directory.entries:
                if hasattr(entry,'directory'):walk(entry.directory)
                else:bump(entry.data.struct.get_field_absolute_offset('OffsetToData'))
        walk(p.DIRECTORY_ENTRY_RESOURCE)
    if hasattr(p,'DIRECTORY_ENTRY_DEBUG'):
        for e in p.DIRECTORY_ENTRY_DEBUG:bump(e.struct.get_field_absolute_offset('AddressOfRawData'))
    for block in p.DIRECTORY_ENTRY_BASERELOC:bump(block.struct.get_field_absolute_offset('VirtualAddress'))
    if hasattr(p,'DIRECTORY_ENTRY_LOAD_CONFIG'):
        lc=p.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        for table,count,stride in [('SEHandlerTable','SEHandlerCount',4),('GuardCFFunctionTable','GuardCFFunctionCount',4+((getattr(lc,'GuardFlags',0)>>28)&15)),('GuardAddressTakenIatEntryTable','GuardAddressTakenIatEntryCount',4),('GuardLongJumpTargetTable','GuardLongJumpTargetCount',4)]:
            address=getattr(lc,table,0)
            if address:
                pos=off(address-p.OPTIONAL_HEADER.ImageBase)
                for i in range(getattr(lc,count,0)):bump(pos+i*stride)
        volatile=getattr(lc,'VolatileMetadataPointer',0)
        if volatile:
            pos=off(volatile-p.OPTIONAL_HEADER.ImageBase)
            for field,stride in [(8,4),(16,8)]:
                table=read(pos+field);size=read(pos+field+4)
                if table:
                    for j in range(0,size,stride):bump(off(table)+j)
                    bump(pos+field)
    optional=p.OPTIONAL_HEADER
    write(optional.get_field_absolute_offset('ImageBase'),BASE)
    for field,value in [('MajorOperatingSystemVersion',5),('MinorOperatingSystemVersion',1),('MajorSubsystemVersion',4),('MinorSubsystemVersion',0)]:
        struct.pack_into('<H',data,optional.get_field_absolute_offset(field),value)
    for field in ['AddressOfEntryPoint','BaseOfCode','BaseOfData','SizeOfImage']:bump(optional.get_field_absolute_offset(field))
    for i,directory in enumerate(optional.DATA_DIRECTORY):
        if i!=4:bump(directory.get_field_absolute_offset('VirtualAddress'))
    # There is room in the aligned header for one additional section descriptor.
    section_start=p.sections[0].get_file_offset()
    section_end=section_start+40*len(p.sections)
    assert section_end+40<=optional.SizeOfHeaders,'not enough section header padding'
    headers=[]
    for s in p.sections:
        raw=bytearray(data[s.get_file_offset():s.get_file_offset()+40])
        struct.pack_into('<I',raw,12,s.VirtualAddress+DELTA)
        headers.append(raw)
    guest=struct.pack('<8sIIIIIIHHI',b'.guest\0\0',0x50000,0x1000,0,0,0,0,0,0,0xc0000080)
    data[section_start:section_end+40]=guest+b''.join(headers)
    struct.pack_into('<H',data,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),len(p.sections)+1)
    write(optional.get_field_absolute_offset('CheckSum'),0)
    write(optional.get_field_absolute_offset('SizeOfUninitializedData'),optional.SizeOfUninitializedData+DELTA)
    result=pefile.PE(data=bytes(data))
    write(optional.get_field_absolute_offset('CheckSum'),result.generate_checksum())
    p.close()
    path.write_bytes(data)
    print('PE layout: non-executable reference data at 0x01001000; Rust sections above 0x01050000')
