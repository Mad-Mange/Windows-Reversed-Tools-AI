[Back to the project overview](../README.md)

# aicalc — calc.exe rewritten in Rust

`aicalc.exe` is a Rust translation of the Windows 11 `calc.exe`
(10.0.26100.8521, x86, SHA-256 `AD2B108A…510C57`), produced without source
code by decompiling the binary and translating it function by function.

## What calc.exe actually is

Since Windows 10, `System32\calc.exe` is not the calculator: it is a 26 KB
launcher. Its whole job, recovered from the disassembly:

1. **CRT startup** (msvcrt `wWinMainCRTStartup`): seed the `/GS` cookie,
   skip the program name in the command line, pick `nShowCmd`, call `wWinMain`.
2. **`wWinMain`**:
   - register the TraceLogging provider **MicrosoftCalculator**
     `{0905CA09-610E-401E-B650-2F212980B9E0}` (Microsoft telemetry group);
   - if a trace session enabled it at level ≥ 5 with keyword
     `0x0002000000000000`, write the event **CalculatorWinMain** with the
     ANSI field `"CalculatorStarted"`;
   - `ShellExecuteW(NULL, NULL, L"ms-calculator:", NULL, NULL, SW_SHOWNORMAL)`,
     which starts the packaged Calculator app;
   - return 0, without unregistering the provider.
3. Exit with code 0.

The window you see is the Calculator app (`CalculatorApp.exe`) in both cases,
so a faithful launcher produces a pixel-identical result.

## Layout

| Path | Contents |
|------|----------|
| `calc.exe` | Local test reference; supply your own matching binary. Excluded from the public repository. |
| `decompiled/calc_decompiled.c` | Intermediate representation: the reconstructed C source, annotated with original addresses. |
| `decompiled/calc.text.disasm.txt`, `calc.headers.txt` | Raw `dumpbin` disassembly and header and import dumps it was built from. |
| `src/startup.rs` | CRT startup: `__security_init_cookie`, `__tmainCRTStartup` (command-line tail, `nShowCmd`). |
| `src/calc.rs` | `wWinMain`, the provider and event definitions and their metadata blobs. |
| `src/tracelogging.rs` | TraceLogging runtime: `TraceLoggingRegister`, `_tlgEnableCallback`, `_tlgWriteTransfer_EventWriteTransfer`, `ETW0` header and end marker. |
| `src/win32.rs` | Win32/ETW FFI (raw-dylib, same DLLs as the original) plus recording mocks for tests. |
| `src/loadcfg.rs` | `_load_config_used`: security cookie, CFG check pointer, guard tables. |
| `src/main.rs` | `no_std` image entry point. |
| `res/` | Resources extracted from the original: icon, manifest, version info (`aicalc.rc`). |
| `build.rs` | Compiles resources (`rc.exe`) and sets linker options to match the original PE header. |
| `tests/test_equivalence.py` | Binary-vs-binary equivalence suite. |
| `src/tests.rs` | Unit tests of the translated logic against mocked APIs. |

## Build

Needs Rust with the `i686-pc-windows-msvc` target, MSVC Build Tools and the
Windows SDK (for `rc.exe`).

```powershell
rustup target add i686-pc-windows-msvc
cargo build --release      # -> target\i686-pc-windows-msvc\release\aicalc.exe
```

The project builds for x86 by default (`.cargo/config.toml`), like the
original, with Control Flow Guard enabled.

## Test

```powershell
.\run_tests.ps1            # build, copy .\aicalc.exe, unit tests, equivalence tests
.\run_tests.ps1 -SkipGui   # without launching Calculator
```

- **Unit tests** (`cargo test --lib`, 22 tests). They run the translated code
  against mocks that behave like ETW, including invoking the enable callback
  synchronously inside `EventRegister`. Covered: the exact API call sequence
  and arguments, event descriptor and payload bytes, level and keyword
  filtering, disable and capture-state handling, `HRESULT` mapping, the
  fail-fast on double registration, command-line parsing, `nShowCmd`, cookie
  generation, and that the metadata blobs equal the original's bytes.
- **Equivalence tests** (`tests/test_equivalence.py`):
  - PE header fields, mitigations (ASLR, DEP, CFG with identical guard flags),
    load config, checksum and imports.
  - Resources: icons, group icon, manifest and version block are
    byte-identical.
  - The `ETW0…end` TraceLogging metadata run is byte-identical.
  - Icons are rendered at 14 sizes on 3 backgrounds, plus the shell's
    large and small icons, all pixel-identical.
  - Both executables are launched with and without arguments: exit code 0,
    and a Calculator window opens.
  - Screenshots of the Calculator window opened by each executable are
    compared pixel by pixel and saved to `tests/artifacts/`.
  - Real ETW capture with `logman`/`tracerpt` compares the emitted events.
    This test needs an elevated prompt and is skipped otherwise.

## Known, intentional differences

| Difference | Why it doesn't change behaviour |
|------------|---------------------------------|
| No msvcrt.dll import; `GetCommandLineW` and `ExitProcess` come from KERNEL32 | The Rust image has no C runtime. msvcrt's `_wcmdln` is the `GetCommandLineW()` buffer, and `exit()` ends in `ExitProcess`. The other msvcrt calls (`__set_app_type`, `_fmode`, `__wgetmainargs`, `_controlfp`, …) only configure msvcrt's own state, which nothing uses. |
| `IMAGE_DLLCHARACTERISTICS_NO_SEH` set | The original's SEH handlers belong to its CRT (`__try/__except` in startup). The Rust image registers none, and its unhandled-exception outcome (WER) is the same. |
| Version resource is 896 bytes, not 900 | The `VS_VERSIONINFO` block (`wLength` = 896) is identical. The original carries 4 trailing zero bytes of padding from Microsoft's build. |
| Section layout, import order, debug directory, PDB name, timestamp | Linker artefacts that are not observable at run time. |

## Finding worth knowing

An x86 image with subsystem version **10.0** (as calc.exe has) **must have a
load configuration with a security cookie**. Without one, process creation
fails with `STATUS_INVALID_IMAGE_FORMAT` (0xC000007B). A `no_std` Rust image
has no CRT to provide `_load_config_used`, so `src/loadcfg.rs` defines it.
That definition also carries the CFG metadata. CFG matters beyond this image:
Windows only enforces CFG on the DLLs a process loads when the main EXE is
CFG-enabled.
