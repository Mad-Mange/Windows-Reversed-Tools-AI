"""Minimal Windows debugger for startup faults in the local Rust build."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import time
ROOT=Path(__file__).resolve().parents[1]
k=C.WinDLL('kernel32',use_last_error=True)
class SI(C.Structure):
    _fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reserved2',W.WORD),('res2',C.c_void_p),('stdin',W.HANDLE),('stdout',W.HANDLE),('stderr',W.HANDLE)]
class PI(C.Structure):_fields_=[('process',W.HANDLE),('thread',W.HANDLE),('pid',W.DWORD),('tid',W.DWORD)]
class EX(C.Structure):
    _fields_=[('code',W.DWORD),('flags',W.DWORD),('record',C.c_void_p),('address',C.c_void_p),('count',W.DWORD),('params',C.c_size_t*15)]
class EXINFO(C.Structure):_fields_=[('exception',EX),('first',W.DWORD)]
class UNION(C.Union):_fields_=[('ex',EXINFO),('raw',C.c_byte*160)]
class EVENT(C.Structure):_fields_=[('kind',W.DWORD),('pid',W.DWORD),('tid',W.DWORD),('u',UNION)]
k.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,C.c_void_p,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)]
k.WaitForDebugEvent.argtypes=[C.POINTER(EVENT),W.DWORD]
k.ContinueDebugEvent.argtypes=[W.DWORD,W.DWORD,W.DWORD]
k.OpenThread.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenThread.restype=W.HANDLE
k.Wow64GetThreadContext.argtypes=[W.HANDLE,C.c_void_p]
k.ReadProcessMemory.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p]
k.TerminateProcess.argtypes=[W.HANDLE,W.UINT]
k.CloseHandle.argtypes=[W.HANDLE]
def run():
    si=SI();si.cb=C.sizeof(si);pi=PI()
    assert k.CreateProcessW(str(ROOT/'aipinball.exe'),None,None,None,False,2|0x08000000,None,str(ROOT),C.byref(si),C.byref(pi)),C.get_last_error()
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        ev=EVENT()
        if not k.WaitForDebugEvent(C.byref(ev),500):continue
        status=0x10002
        if ev.kind==1:
            ex=ev.u.ex.exception
            print(f'EXCEPTION {ex.code:08x} @ {ex.address:08x}, first={ev.u.ex.first}, params={[hex(p) for p in ex.params[:ex.count]]}',flush=True)
            if ex.code not in (0x80000003,0x4000001f):
                thread=k.OpenThread(0x001f03ff,False,ev.tid)
                context=(C.c_uint32*179)();context[0]=0x10007
                if k.Wow64GetThreadContext(thread,C.byref(context)):
                    print('REGISTERS',dict(zip(['edi','esi','ebx','edx','ecx','eax','ebp','eip','cs','eflags','esp','ss'],[hex(v) for v in context[39:51]])),flush=True)
                    sp=context[49];buf=(C.c_uint32*32)()
                    if k.ReadProcessMemory(pi.process,sp,buf,C.sizeof(buf),None):print('STACK',[hex(v) for v in buf],flush=True)
                k.CloseHandle(thread);status=0x80010001
        elif ev.kind==5:print('EXIT',bytes(v&255 for v in ev.u.raw[:4]).hex(),flush=True);break
        k.ContinueDebugEvent(ev.pid,ev.tid,status)
    k.TerminateProcess(pi.process,0);k.CloseHandle(pi.process);k.CloseHandle(pi.thread)
if __name__=='__main__':run()
