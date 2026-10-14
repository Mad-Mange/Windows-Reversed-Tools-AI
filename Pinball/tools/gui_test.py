"""Binary-versus-binary Windows integration and image comparison harness."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import subprocess,time,json,os
from PIL import Image,ImageChops
ROOT=Path(__file__).resolve().parents[1];ART=ROOT/'artifacts';ART.mkdir(exist_ok=True)
u=C.WinDLL('user32',use_last_error=True);g=C.WinDLL('gdi32',use_last_error=True)
k=C.WinDLL('kernel32',use_last_error=True)
H=C.c_void_p
CB=C.WINFUNCTYPE(W.BOOL,H,W.LPARAM)
def declare(lib,name,rest,args):
    f=getattr(lib,name);f.restype=rest;f.argtypes=args;return f
declare(u,'EnumWindows',W.BOOL,[CB,W.LPARAM]);declare(u,'GetWindowThreadProcessId',W.DWORD,[H,C.POINTER(W.DWORD)])
declare(u,'GetWindowTextW',C.c_int,[H,W.LPWSTR,C.c_int]);declare(u,'IsWindowVisible',W.BOOL,[H])
declare(u,'GetClientRect',W.BOOL,[H,C.POINTER(W.RECT)]);declare(u,'GetWindowRect',W.BOOL,[H,C.POINTER(W.RECT)])
declare(u,'GetDC',H,[H]);declare(u,'ReleaseDC',C.c_int,[H,H]);declare(u,'PrintWindow',W.BOOL,[H,H,W.UINT])
declare(u,'GetMenu',H,[H]);declare(u,'GetSubMenu',H,[H,C.c_int]);declare(u,'GetMenuItemCount',C.c_int,[H])
declare(u,'GetMenuItemID',W.UINT,[H,C.c_int]);declare(u,'GetMenuStringW',C.c_int,[H,W.UINT,W.LPWSTR,C.c_int,W.UINT])
declare(u,'PostMessageW',W.BOOL,[H,W.UINT,W.WPARAM,W.LPARAM]);declare(u,'SendMessageTimeoutW',W.LPARAM,[H,W.UINT,W.WPARAM,W.LPARAM,W.UINT,W.UINT,C.POINTER(C.c_size_t)])
declare(u,'SetForegroundWindow',W.BOOL,[H])
declare(k,'OpenProcess',H,[W.DWORD,W.BOOL,W.DWORD]);declare(k,'CloseHandle',W.BOOL,[H]);declare(k,'ReadProcessMemory',W.BOOL,[H,H,H,C.c_size_t,H])
declare(g,'CreateCompatibleDC',H,[H]);declare(g,'CreateCompatibleBitmap',H,[H,C.c_int,C.c_int]);declare(g,'SelectObject',H,[H,H]);declare(g,'DeleteObject',W.BOOL,[H]);declare(g,'DeleteDC',W.BOOL,[H]);declare(g,'GetDIBits',C.c_int,[H,H,W.UINT,W.UINT,H,H,W.UINT])
class BI(C.Structure):_fields_=[('size',W.DWORD),('width',W.LONG),('height',W.LONG),('planes',W.WORD),('bits',W.WORD),('compression',W.DWORD),('sizeimage',W.DWORD),('xppm',W.LONG),('yppm',W.LONG),('used',W.DWORD),('important',W.DWORD)]
def windows(pid):
    found=[]
    @CB
    def visit(hwnd,param):
        owner=W.DWORD();u.GetWindowThreadProcessId(hwnd,C.byref(owner))
        if owner.value==pid:
            title=C.create_unicode_buffer(512);u.GetWindowTextW(hwnd,title,512)
            rect=W.RECT();u.GetClientRect(hwnd,C.byref(rect))
            found.append((hwnd,title.value,bool(u.IsWindowVisible(hwnd)),rect.right,rect.bottom))
        return True
    u.EnumWindows(visit,0);return found
def menus(menu):
    result=[]
    for i in range(u.GetMenuItemCount(menu)):
        text=C.create_unicode_buffer(256);u.GetMenuStringW(menu,i,text,256,0x400)
        sub=u.GetSubMenu(menu,i)
        result.append({'text':text.value,'id':u.GetMenuItemID(menu,i),'children':menus(sub) if sub else []})
    return result
def capture(hwnd,name):
    r=W.RECT();u.GetClientRect(hwnd,C.byref(r));w,h=r.right,r.bottom
    dc=u.GetDC(hwnd);mem=g.CreateCompatibleDC(dc);bmp=g.CreateCompatibleBitmap(dc,w,h);old=g.SelectObject(mem,bmp)
    assert u.PrintWindow(hwnd,mem,1),'PrintWindow failed'
    g.SelectObject(mem,old)
    bi=BI(C.sizeof(BI),w,-h,1,32,0,w*h*4,0,0,0,0);pixels=C.create_string_buffer(w*h*4)
    assert g.GetDIBits(mem,bmp,0,h,pixels,C.byref(bi),0)==h
    im=Image.frombytes('RGB',(w,h),pixels.raw,'raw','BGRX');im.save(ART/name)
    g.DeleteObject(bmp);g.DeleteDC(mem);u.ReleaseDC(hwnd,dc);return im
def send(hwnd,msg,w=0,l=0):
    result=C.c_size_t();assert u.SendMessageTimeoutW(hwnd,msg,w,l,2,5000,C.byref(result)),f'window unresponsive, message {msg:x}'
    return result.value
def key(hwnd,vk,seconds=.1):
    u.PostMessageW(hwnd,0x100,vk,1);time.sleep(seconds);u.PostMessageW(hwnd,0x101,vk,0xc0000001)
def state(pid):
    process=k.OpenProcess(0x10,False,pid);result={}
    try:
        for name,addr in [('paused',0x1024fd8),('focused',0x1024fec),('last_tick',0x10281a0)]:
            value=W.DWORD();assert k.ReadProcessMemory(process,addr,C.byref(value),4,None)
            result[name]=value.value
    finally:k.CloseHandle(process)
    return result
def activate(hwnd,pid):
    u.SetForegroundWindow(hwnd)
    # Test the same focus notifications on both executables even when Windows
    # foreground-lock policy refuses focus to the background test runner.
    send(hwnd,0x1c,1);send(hwnd,7)
    if state(pid)['paused']:send(hwnd,0x111,402)
def run_one(binary):
    tag='original' if binary=='PINBALL.EXE' else 'rust'
    log=(ART/(tag+'-gui.log')).open('w')
    proc=subprocess.Popen([str(ROOT/binary)],cwd=ROOT,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
    started=time.monotonic()
    hwnd=None
    try:
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            if proc.poll() is not None:raise AssertionError(f'{binary} exited: {proc.returncode}')
            allwindows=windows(proc.pid)
            candidates=[w for w in allwindows if w[2] and 'Pinball' in w[1] and w[3]>500 and w[4]>300]
            if candidates:hwnd=max(candidates,key=lambda w:w[3]*w[4])[0];break
            time.sleep(.2)
        assert hwnd,f'no game window: {allwindows}'
        time.sleep(2)
        # Freeze simulation before resetting the board: compare the same game
        # checkpoint, not lamps sampled at two different wall-clock instants.
        send(hwnd,8)
        send(hwnd,0x111,101)
        report={'windows':windows(proc.pid),'menus':menus(u.GetMenu(hwnd)),'startup_seconds':time.monotonic()-started}
        print(tag,'game window ready',round(report['startup_seconds'],2),'seconds',flush=True)
        capture(hwnd,tag+'-initial.png')
        if not state(proc.pid)['paused']:send(hwnd,0x111,402)
        time.sleep(.2)
        capture(hwnd,tag+'-paused.png')
        report['dialogs']=[]
        for command,label in [(406,'controls'),(103,'high-scores')]:
            u.PostMessageW(hwnd,0x111,command,0)
            deadline=time.monotonic()+5;dialog=None
            while time.monotonic()<deadline:
                candidates=[w for w in windows(proc.pid) if w[0]!=hwnd and w[2] and w[3]>100 and w[4]>80]
                if candidates:dialog=candidates[0];break
                time.sleep(.05)
            assert dialog,f'{tag}: missing {label} dialog'
            time.sleep(.2);capture(dialog[0],tag+'-'+label+'.png')
            report['dialogs'].append({'name':label,'title':dialog[1],'size':dialog[3:]})
            u.PostMessageW(dialog[0],0x111,2,0);time.sleep(.2)
        key(hwnd,0x72);key(hwnd,0x71);time.sleep(.5) # F3 resume; F2 new game
        activate(hwnd,proc.pid)
        send(hwnd,0x111,401);time.sleep(3) # launch via the original menu handler
        key(hwnd,0x5a,.3);key(hwnd,0xbf,.3);time.sleep(.5)
        capture(hwnd,tag+'-playing.png')
        send(hwnd,0x111,404);activate(hwnd,proc.pid);time.sleep(8) # automatic demo exercises collisions and scoring
        frame1=capture(hwnd,tag+'-demo-1.png');time.sleep(1)
        frame2=capture(hwnd,tag+'-demo-2.png')
        motion=ImageChops.difference(frame1.crop((0,0,380,400)),frame2.crop((0,0,380,400))).getbbox()
        assert motion,f'{tag}: demo table did not animate: {state(proc.pid)}'
        report['demo_animated']=True
        send(hwnd,0x10)
        time.sleep(.3)
        for dialog in windows(proc.pid):
            if dialog[0]!=hwnd and dialog[2] and dialog[3]>100:
                print('Exit dialog:',dialog,flush=True)
                u.PostMessageW(dialog[0],0x111,6,0)
        proc.wait(timeout=10)
        report['exit_code']=proc.returncode
        assert proc.returncode==0,report
        return report
    finally:
        if proc.poll() is None:proc.terminate();proc.wait()
        log.close()
def run():
    result={}
    for binary in ['PINBALL.EXE','aipinball.exe']:result[binary]=run_one(binary)
    a=Image.open(ART/'original-paused.png');b=Image.open(ART/'rust-paused.png')
    assert a.size==b.size,(a.size,b.size)
    diff=ImageChops.difference(a,b);diff.save(ART/'paused-difference.png')
    changed=sum(pixel!=(0,0,0) for pixel in diff.getdata())
    result['paused_pixels_different']=changed;result['total_pixels']=a.width*a.height
    result['menus_equal']=result['PINBALL.EXE']['menus']==result['aipinball.exe']['menus']
    result['dialogs_equal']=result['PINBALL.EXE']['dialogs']==result['aipinball.exe']['dialogs']
    result['dialog_pixel_differences']={}
    for label in ['controls','high-scores']:
        a=Image.open(ART/f'original-{label}.png');b=Image.open(ART/f'rust-{label}.png')
        assert a.size==b.size,(label,a.size,b.size)
        delta=ImageChops.difference(a,b);delta.save(ART/f'{label}-difference.png')
        result['dialog_pixel_differences'][label]=sum(pixel!=(0,0,0) for pixel in delta.getdata())
    (ART/'gui-report.json').write_text(json.dumps(result,indent=2))
    print(f'Paused image: {changed}/{result["total_pixels"]} pixels different; menus equal: {result["menus_equal"]}; dialogs: {result["dialog_pixel_differences"]}',flush=True)
    assert changed==0,'paused reference image mismatch'
    assert result['menus_equal'] and result['dialogs_equal']
    assert all(v==0 for v in result['dialog_pixel_differences'].values())
if __name__=='__main__':run()
