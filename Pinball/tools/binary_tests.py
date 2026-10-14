"""Validate the delivered image against the supplied reference binary."""
from pathlib import Path
import hashlib,json,struct,shutil,subprocess,time
import pefile
ROOT=Path(__file__).resolve().parents[1];ART=ROOT/'artifacts';ART.mkdir(exist_ok=True)
def resources(p):
    result={}
    for typ in p.DIRECTORY_ENTRY_RESOURCE.entries:
        for name in typ.directory.entries:
            for lang in name.directory.entries:
                key=(str(typ.name) if typ.name else typ.id,str(name.name) if name.name else name.id,lang.id)
                result[key]=p.get_data(lang.data.struct.OffsetToData,lang.data.struct.Size)
    return result
def run():
    reference=pefile.PE(str(ROOT/'PINBALL.EXE'));rust=pefile.PE(str(ROOT/'aipinball.exe'))
    manifest=json.loads((ROOT/'generated/manifest.json').read_text())
    assert hashlib.sha256((ROOT/'PINBALL.EXE').read_bytes()).hexdigest()==manifest['sha256'],'reference changed'
    assert resources(reference)==resources(rust),'resource bytes differ'
    assert rust.OPTIONAL_HEADER.ImageBase==reference.OPTIONAL_HEADER.ImageBase
    for field in ['MajorOperatingSystemVersion','MinorOperatingSystemVersion','MajorSubsystemVersion','MinorSubsystemVersion']:
        assert getattr(rust.OPTIONAL_HEADER,field)==getattr(reference.OPTIONAL_HEADER,field),field
    guest=rust.sections[0]
    assert guest.Name.rstrip(b'\0')==b'.guest'
    assert guest.Characteristics&0x20000000==0,'reference data is executable'
    assert guest.Characteristics&0x80000000,'reference data is not writable'
    assert rust.OPTIONAL_HEADER.DllCharacteristics&0x100,'DEP disabled'
    assert rust.verify_checksum(),'PE checksum mismatch'
    assert len(rust.DIRECTORY_ENTRY_IMPORT)>0
    for dll in rust.DIRECTORY_ENTRY_IMPORT:
        assert all(i.name or i.ordinal for i in dll.imports)
    native_code=[s for s in rust.sections if s.Characteristics&0x20000000]
    assert all(s.VirtualAddress>=0x51000 for s in native_code)
    ir=(ROOT/'generated/instructions.bin').read_bytes()
    assert len(ir)==manifest['code_size']*44
    stage=ART/'standalone';stage.mkdir(exist_ok=True)
    assert stage.resolve().is_relative_to(ROOT.resolve())
    shutil.copy2(ROOT/'aipinball.exe',stage/'aipinball.exe')
    for asset in ROOT.iterdir():
        if asset.suffix.lower() in ['.dat','.wav','.mid','.bmp','.inf']:shutil.copy2(asset,stage/asset.name)
    assert not (stage/'PINBALL.EXE').exists(),'standalone test contains original executable'
    import gui_test as gui
    with (ART/'standalone.log').open('w') as log:
        proc=subprocess.Popen([str(stage/'aipinball.exe')],cwd=stage,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline=time.monotonic()+35;game=None
            while time.monotonic()<deadline:
                assert proc.poll() is None,f'standalone exited {proc.returncode}'
                game=next((w for w in gui.windows(proc.pid) if w[2] and 'Pinball' in w[1]),None)
                if game:break
                time.sleep(.2)
            assert game,'standalone game window missing'
            gui.send(game[0],0x10);proc.wait(timeout=15);assert proc.returncode==0
        finally:
            if proc.poll() is None:proc.terminate();proc.wait()
    result={'reference_sha256':manifest['sha256'],'identical_resources':len(resources(reference)),'nonexecutable_reference_data':True,'native_rust_code_separate':True,'compatibility_versions_match':True,'standalone_without_original_exe':True,'all_passed':True}
    (ART/'binary-report.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
