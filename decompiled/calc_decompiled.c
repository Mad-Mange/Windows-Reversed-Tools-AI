/*
 * calc.exe 10.0.26100.8521 (x86, PE32, 26 624 bytes)
 * SHA-256 AD2B108A1B46F93127599C939E733D0995D34D3B7B887992E807E73569510C57
 *
 * Reconstructed C source: the intermediate representation the Rust
 * translation (../src) was written from. Recovered by hand from the dumpbin
 * disassembly in calc.text.disasm.txt; every function carries the address it
 * was recovered from. Names follow the Windows SDK / CRT sources where the
 * code is library code (TraceLoggingProvider.h, msvcrt crtexe.c, gs_support.c).
 *
 * Image layout (sections: .text [code + merged .rdata], .data, .idata, .rsrc, .reloc)
 *   .text$mn       0x004015A0  code
 *   .rdata         0x00401110  "CalculatorStarted", L"ms-calculator:"
 *   .rdata$zETW0   0x00401248  _tlgHeader                       (16 bytes)
 *   .rdata$zETW1   0x00401258  CalculatorWinMain event blob     (0x36 bytes)
 *   .rdata$zETW2   0x0040128E  MicrosoftCalculator provider blob (0x3A bytes)
 *   .rdata$zETW9   0x004012C8  end-of-blobs marker              (4 bytes)
 *   .data          0x00403000  g_hProvider (_tlgProvider_t, 0x28 bytes)
 *                  0x00403028  __security_cookie / complement
 *   .00cfg         0x00404098  __guard_check_icall_fptr
 *
 * Resources: RT_ICON 1-4, RT_GROUP_ICON "IDI_CALC_ICON", RT_VERSION 1,
 * RT_MANIFEST 1 (all LANG_ENGLISH/SUBLANG_ENGLISH_US) -> ../res
 */

#include <windows.h>
#include <shellapi.h>
#include <evntprov.h>

/* ======================================================================
 * Application code (calc.cpp)
 * ====================================================================== */

/* {0905CA09-610E-401E-B650-2F212980B9E0}, group {4F50731A-89CF-4782-B3E0-DCE8C90476BA} */
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,                                   /* .data 0x00403000 */
    "MicrosoftCalculator",
    (0x0905ca09, 0x610e, 0x401e, 0xb6, 0x50, 0x2f, 0x21, 0x29, 0x80, 0xb9, 0xe0),
    TraceLoggingOptionMicrosoftTelemetry());

/* 0x0040176D (stdcall, ret 10h) */
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(pCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    TraceLoggingRegister(g_hProvider);                       /* call 0x00401623, HRESULT ignored */

    /* Expanded below: level 5 < LevelPlus1 && keyword matches, then write. */
    TraceLoggingWrite(
        g_hProvider,
        "CalculatorWinMain",
        TraceLoggingValue("CalculatorStarted"),            /* field named "\"CalculatorStarted\"" */
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),         /* 5 */
        TraceLoggingKeyword(0x0002000000000000));

    ShellExecuteW(NULL, NULL, L"ms-calculator:", NULL, NULL, SW_SHOWNORMAL);   /* result ignored */

    /* No TraceLoggingUnregister. */
    return 0;
}

/* What the TraceLoggingWrite above compiles to (inlined into wWinMain):
 *
 *   if (g_hProvider->LevelPlus1 > 5 &&
 *       (g_hProvider->KeywordAny & 0x0002000000000000) != 0 &&
 *       (g_hProvider->KeywordAll & 0x0002000000000000) == g_hProvider->KeywordAll)
 *   {
 *       EVENT_DATA_DESCRIPTOR data[3];
 *       EventDataDescCreate(&data[2], "CalculatorStarted", 0x12);   // strlen + 1, folded
 *       _tlgWriteTransfer_EventWriteTransfer(g_hProvider, &_tlgEvent.Channel,  // 0x00401259
 *                                            NULL, NULL, 3, data);
 *   }
 */

/* ======================================================================
 * TraceLogging runtime (TraceLoggingProvider.h, inline in the image)
 * ====================================================================== */

#pragma pack(push, 1)
struct _tlgProvider_t {                  /* 0x28 bytes on x86 */
    ULONG LevelPlus1;                    /* +0x00 */
    UINT16 const* ProviderMetadataPtr;   /* +0x04 -> 0x0040129F (blob RemainingSize) */
    ULONGLONG KeywordAny;                /* +0x08 */
    ULONGLONG KeywordAll;                /* +0x10 */
    REGHANDLE RegHandle;                 /* +0x18 */
    PENABLECALLBACK EnableCallback;      /* +0x20 */
    PVOID CallbackContext;               /* +0x24 */
};
#pragma pack(pop)

/* .rdata$zETW0 @ 0x00401248:  45 54 57 30 10 00 00 00 86 0E 04 88 2B 05 8A BB
 *   "ETW0", Size=16, Version=0, Flags=0 (32-bit), Magic=0xBB8A052B88040E86
 *
 * .rdata$zETW1 @ 0x00401258 (_TlgBlobEvent4):
 *   06                         type
 *   0B 05 00                   channel 11 (TraceLogging), level 5, opcode 0
 *   00 00 00 00 00 00 02 00    keyword 0x0002000000000000
 *   2A 00                      remaining size 42
 *   00                         tags: none
 *   "CalculatorWinMain\0"      event name
 *   "\"CalculatorStarted\"\0"  field 0 name
 *   02                         TlgInANSISTRING
 *
 * .rdata$zETW2 @ 0x0040128E (_TlgBlobProvider3):
 *   04                         type
 *   09 CA 05 09 0E 61 1E 40 B6 50 2F 21 29 80 B9 E0   provider GUID
 *   29 00                      remaining size 41      <- ProviderMetadataPtr
 *   "MicrosoftCalculator\0"
 *   13 00 01 + 16-byte GUID    trait: size 19, EtwProviderTraitTypeGroup, group GUID
 *
 * .rdata$zETW9 @ 0x004012C8:  01 00 00 00   _TlgBlobEnd
 */

/* 0x004015A0 (stdcall, ret 24h) */
void NTAPI _tlgEnableCallback(LPCGUID pSourceId, ULONG isEnabled, UCHAR level,
                              ULONGLONG keywordAny, ULONGLONG keywordAll,
                              PEVENT_FILTER_DESCRIPTOR pFilterData, PVOID pCallbackContext)
{
    struct _tlgProvider_t* pProvider = (struct _tlgProvider_t*)pCallbackContext;
    if (pProvider == NULL)
        return;

    switch (isEnabled) {
    case EVENT_CONTROL_CODE_DISABLE_PROVIDER:
        pProvider->LevelPlus1 = 0;
        break;
    case EVENT_CONTROL_CODE_ENABLE_PROVIDER:
        pProvider->LevelPlus1 = level != 0 ? (ULONG)level + 1u : 256u;
        pProvider->KeywordAny = keywordAny;
        pProvider->KeywordAll = keywordAll;
        break;
    }

    if (pProvider->EnableCallback != NULL) {
        /* CFG-checked indirect call (__guard_check_icall_fptr) */
        pProvider->EnableCallback(pSourceId, isEnabled, level, keywordAny, keywordAll,
                                  pFilterData, pProvider->CallbackContext);
    }
}

/* 0x00401623 (stdcall, ret 4; /GS frame) */
HRESULT TraceLoggingRegister(TraceLoggingHProvider hProvider)
{
    HRESULT hr;
    GUID providerId = *(GUID const*)((BYTE const*)hProvider->ProviderMetadataPtr - sizeof(GUID));

    if (hProvider->RegHandle != 0)
        __fastfail(FAST_FAIL_INVALID_ARG);                 /* int 29h, ecx = 5 */

    hProvider->EnableCallback = NULL;
    hProvider->CallbackContext = NULL;

    hr = EventRegister(&providerId, _tlgEnableCallback, (PVOID)hProvider, &hProvider->RegHandle);
    if (hr != 0) {
        hr = HRESULT_FROM_WIN32(hr);
    } else {
        EventSetInformation(hProvider->RegHandle, EventProviderSetTraits,
                            (PVOID)hProvider->ProviderMetadataPtr,
                            *hProvider->ProviderMetadataPtr);
    }
    return hr;
}

/* 0x004016CF (stdcall, ret 18h) */
ULONG _tlgWriteTransfer_EventWriteTransfer(TraceLoggingHProvider hProvider,
                                           void const* pEventMetadata,
                                           LPCGUID pActivityId, LPCGUID pRelatedActivityId,
                                           UINT32 cData, EVENT_DATA_DESCRIPTOR* pData)
{
    UINT8 const* p = (UINT8 const*)pEventMetadata;   /* -> Channel byte */
    UINT16 const* pEventSize = (UINT16 const*)(p + 11);
    EVENT_DESCRIPTOR desc;
    volatile ULONG_PTR keepAlive;

    desc.Id = 0;
    desc.Version = 0;
    desc.Channel = p[0];
    desc.Level = p[1];
    desc.Opcode = p[2];
    desc.Task = 0;
    desc.Keyword = *(ULONGLONG UNALIGNED const*)(p + 3);

    EventDataDescCreate(&pData[0], hProvider->ProviderMetadataPtr, *hProvider->ProviderMetadataPtr);
    pData[0].Reserved = EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA;       /* 2 */
    EventDataDescCreate(&pData[1], pEventSize, *pEventSize);
    pData[1].Reserved = EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA;          /* 1 */

    keepAlive = (ULONG_PTR)&_tlgEndOfBlobs - (ULONG_PTR)&_tlgHeader;       /* 0x4012C8 - 0x401248 */

    return EventWriteTransfer(hProvider->RegHandle, &desc, pActivityId, pRelatedActivityId,
                              cData, pData);
}

/* ======================================================================
 * C runtime startup (msvcrt crtexe.c, _WINMAIN_ + WPRFLAG), gs_support.c
 * ====================================================================== */

/* 0x00401CF0: image entry point */
int wWinMainCRTStartup(void)
{
    __security_init_cookie();                              /* 0x00401933 */
    return __tmainCRTStartup();                            /* jmp 0x00401A69 */
}

/* 0x00401933 */
void __cdecl __security_init_cookie(void)
{
    UINT_PTR cookie;
    FILETIME systime;
    LARGE_INTEGER perfctr = { 0 };

    if (__security_cookie != DEFAULT_SECURITY_COOKIE /* 0xBB40E64E */ && __security_cookie != 0) {
        __security_cookie_complement = ~__security_cookie;
        return;
    }

    GetSystemTimeAsFileTime(&systime);
    cookie = systime.dwHighDateTime ^ systime.dwLowDateTime;
    cookie ^= GetCurrentProcessId();
    cookie ^= GetCurrentThreadId();
    cookie ^= GetTickCount();
    cookie ^= (UINT_PTR)&cookie;
    QueryPerformanceCounter(&perfctr);
    cookie ^= perfctr.HighPart ^ perfctr.LowPart;

    __security_cookie = cookie != 0 ? cookie : DEFAULT_SECURITY_COOKIE;
    __security_cookie_complement = ~__security_cookie;
}

/* 0x00401A69 (SEH frame: __try / __except(_XcptFilter(...)) around the body) */
int __tmainCRTStartup(void)
{
    STARTUPINFOW startupInfo;
    wchar_t* lpszCommandLine;
    int inDoubleQuote = FALSE;
    void* fiberId;
    int nested = FALSE;

    GetStartupInfoW(&startupInfo);

    /* Serialise concurrent CRT init (__native_startup_lock @ 0x00403398). */
    fiberId = ((PNT_TIB)NtCurrentTeb())->StackBase;
    for (;;) {
        void* owner = InterlockedCompareExchangePointer(&__native_startup_lock, fiberId, NULL);
        if (owner == NULL) break;
        if (owner == fiberId) { nested = TRUE; break; }
        Sleep(1000);
    }

    if (__native_startup_state == __initializing) {
        _amsg_exit(_RT_CRT_INIT_CONFLICT);                 /* 31 */
    } else if (__native_startup_state == __uninitialized) {
        __native_startup_state = __initializing;
        /* .CRT$XI: pre_c_init (0x004019C0), __CxxSetUnhandledExceptionFilter (0x00401D50) */
        if (_initterm_e(__xi_a, __xi_z) != 0)              /* 0x00401C49 */
            return 255;
    } else {
        has_cctor = 1;
    }

    if (__native_startup_state == __initializing) {
        /* .CRT$XC: pre_cpp_init (0x00401A30) -> __wgetmainargs */
        _initterm(__xc_a, __xc_z);
        __native_startup_state = __initialized;
    }

    if (!nested)
        InterlockedExchangePointer(&__native_startup_lock, NULL);

    if (__dyn_tls_init_callback != NULL && _IsNonwritableInCurrentImage(&__dyn_tls_init_callback))
        __dyn_tls_init_callback(NULL, DLL_THREAD_ATTACH, NULL);       /* none in this image */

    lpszCommandLine = _wcmdln;                             /* msvcrt: GetCommandLineW() */
    if (lpszCommandLine == NULL)
        return 255;

    /* Skip the program name (quotes respected), then the separating blanks. */
    while (*lpszCommandLine > L' ' || (*lpszCommandLine && inDoubleQuote)) {
        if (*lpszCommandLine == L'"')
            inDoubleQuote = !inDoubleQuote;
        ++lpszCommandLine;
    }
    while (*lpszCommandLine && *lpszCommandLine <= L' ')
        ++lpszCommandLine;

    mainret = wWinMain((HINSTANCE)&__ImageBase, NULL, lpszCommandLine,
                       (startupInfo.dwFlags & STARTF_USESHOWWINDOW) ? startupInfo.wShowWindow
                                                                   : SW_SHOWDEFAULT);

    if (!managedapp)                                       /* check_managed_app() @ 0x00401C80: no CLR header */
        exit(mainret);
    if (!has_cctor)
        _cexit();
    return mainret;
}

/* 0x004019C0, .CRT$XIAA */
static int __cdecl pre_c_init(void)
{
    managedapp = check_managed_app();
    __set_app_type(_get_app_type() /* 0x00401DE4: GUI subsystem -> _GUI_APP */);
    __onexitbegin = __onexitend = (_PVFV*)-1;
    *__p__fmode() = _fmode;
    *__p__commode() = _commode;
    _RTC_Initialize();                                     /* 0x00401E40: empty */
    if (!__defaultmatherr)
        __setusermatherr(_matherr);
    _setdefaultprecision();                                /* _controlfp(_PC_53, _MCW_PC) */
    return 0;
}

/* 0x00401A30, .CRT$XCAA */
static void __cdecl pre_cpp_init(void)
{
    startinfo.newmode = _newmode;
    argret = __wgetmainargs(&argc, &argv, &envp, _dowildcard, &startinfo);
}

/* 0x00401D50, .CRT$XIY */
static int __cdecl __CxxSetUnhandledExceptionFilter(void)
{
    SetUnhandledExceptionFilter(__CxxUnhandledExceptionFilter);
    return 0;
}

/* 0x00401D00: terminate() on an unhandled C++ exception, else keep searching */
static LONG WINAPI __CxxUnhandledExceptionFilter(EXCEPTION_POINTERS* pExPtrs)
{
    EXCEPTION_RECORD* rec = pExPtrs->ExceptionRecord;
    if (rec->ExceptionCode == 0xE06D7363 && rec->NumberParameters == 3 &&
        (rec->ExceptionInformation[0] == 0x19930520 || rec->ExceptionInformation[0] == 0x19930521 ||
         rec->ExceptionInformation[0] == 0x19930522 || rec->ExceptionInformation[0] == 0x01994000))
        terminate();
    return EXCEPTION_CONTINUE_SEARCH;
}

/* 0x00401810 __security_check_cookie, 0x00401826 __report_gsfailure (raises
 * STATUS_STACK_BUFFER_OVERRUN via UnhandledExceptionFilter/TerminateProcess),
 * 0x00401E50/0x00401EA0/0x00401F70 _IsNonwritableInCurrentImage helpers,
 * 0x00401FD0/0x00402015 __SEH_prolog4/__SEH_epilog4, 0x00402030 _except_handler4,
 * 0x00402070 _guard_check_icall_nop ("ret 0"): standard CRT library code. */
