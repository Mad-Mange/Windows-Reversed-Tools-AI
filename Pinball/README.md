# aipinball

`aipinball.exe` runs the supplied Windows XP **3D Pinball — Space Cadet** game
through a Rust implementation of its recovered instruction semantics. The input
is `PINBALL.EXE` (281,088 bytes; SHA-256
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`).
No upstream game source code was used. The calculator project is unchanged.

## Run

Build from your local reference files using the steps below, then open
**aipinball.exe in this folder**. Keep `PINBALL.DAT`, `FONT.DAT`, the WAV/MIDI
files, `table.bmp`, and `wavemix.inf` alongside it. `PINBALL.EXE` is needed to
regenerate the translation and run reference comparisons, but is **not needed
to run aipinball.exe**.

The original menus and controls are retained: F2 starts a game, F3 pauses, Space
operates the plunger, and Z and / operate the flippers (subject to the game's
saved control settings).

## What was translated

This is a **machine-level translation with an interpreted intermediate
representation**, not a recovered, hand-written Rust version of the original
C++ class hierarchy. `tools/lift.py` disassembles the supplied PE using Capstone
and emits address-indexed instruction records. Rust implements register access,
integer arithmetic and flags, control flow, calls, stack operations, and memory
operations. The game rules, rendering, physics, data loading, and sound logic
follow the original instruction sequence.

The x87 operations use small generated Rust inline-assembly expressions to
preserve the original floating-point stack, precision, rounding and status
bits. A small assembly bridge implements the native Windows calling convention
and callback entry; it saves and restores the host stack and TEB stack bounds.
These are the only assembly parts of the execution engine.

The original game instructions are **never executed as native machine code**.
Their bytes and data occupy a writable, non-executable `.guest` section. Rust's
compiled code occupies separate executable sections. The program does not start
or load the original executable at runtime. Windows APIs and the system C
runtime provide the same imported services used by the reference.

The PE layout step reserves the original fixed addresses, moves Rust's compiled
sections above them, and updates relocations, imports, resources, TLS-related
addresses, SafeSEH/CFG tables, and volatile metadata. Matching the original OS
and subsystem versions is necessary for identical nonclient sizing on Windows.

## Build

Requirements: Windows, Rust with `i686-pc-windows-msvc`, MSVC Build Tools, Python,
and the packages in `requirements.txt`. No additional Rust crates are needed.

The public repository excludes original executables, game data, generated binary
images and prebuilt executables. Place your matching `PINBALL.EXE` and its game
data in this folder before running the commands below. Git ignores these files.

```powershell
python -m pip install -r requirements.txt
rustup target add i686-pc-windows-msvc
python tools/lift.py
python tools/check.py build --release
```

Use the resulting **Pinball/aipinball.exe**. The intermediate executable under
`target/` has not received the required PE layout transformation and should not
be launched directly. `cargo run` is therefore not the launch command.

## Verification

```powershell
.\run_tests.ps1             # build, unit/math, GUI and independent-run tests
.\run_tests.ps1 -SkipGui    # build and arithmetic/math checks without UI
```

The checks cover:

- Exhaustive byte addition/subtraction, including carry/borrow and overflow;
  register/IR layout and 32-bit boundary cases.
- Seven cases of the recovered vector-normalization routine at `0x01008ae9`,
  checking exact float bits, returned lengths and stack cleanup.
- All 33 original resource leaves, compared byte for byte.
- Non-executable reference data, separate native Rust code, DEP, PE checksum,
  import tables and matching compatibility versions.
- Identical menus and a 600 × 416 pixel comparison at a reset, paused game
  checkpoint. Both processes receive the same focus notifications so background
  test execution does not silently disable the game update loop.
- Pixel comparisons of Player Controls and High Scores dialogs; new-game,
  launch, flipper and demo commands; visible table animation; clean exit.
- A separate run from `artifacts/standalone/`, containing the new executable and
  game assets **without PINBALL.EXE**.

Results and screenshots are in `artifacts/`. Live gameplay screenshots are not
expected to match frame for frame: OS message timing, clock values and random
state differ between two separately launched processes. The strict screenshot
checks use the same reset, paused state and matching dialogs.

Recorded results are published in [`../docs/verification/`](../docs/verification/),
with selected screenshots in [`../docs/images/`](../docs/images/).

## Files

| Path | Purpose |
| --- | --- |
| `src/cpu.rs` | Rust semantics engine and arithmetic tests |
| `src/host.rs`, `src/bridge.s` | Native API calls, stack switching and callbacks |
| `src/core_checks.rs` | Checks of recovered game math |
| `generated/pinball.disasm.txt` | Address-annotated disassembly |
| `generated/metadata.rs`, `generated/fpu.rs` | Generated instruction definitions, imports and x87 operations |
| `generated/manifest.json` | Reference hash, resource hashes and decoding metadata |
| `tools/lift.py` | Reproducible binary-to-IR/resource extraction |
| `tools/layout.py` | Final PE memory-layout transformation |
| `tools/gui_test.py`, `tools/binary_tests.py` | Reference and standalone integration checks |

## Limits

Passing these checks demonstrates the tested game paths and images, rather than
an exhaustive proof of every possible play sequence. Exceptional paths involving
native faults and the original C runtime's SEH handlers are not translated into
host exception handlers. The engine traps unsupported instructions if a new
execution path reaches one. The reference's old WinHelp integration and installed
audio/MIDI services remain dependent on the host Windows installation.

Diagnostics: `python tools/check.py smoke --api-trace`,
`python tools/check.py debug`, and `python tools/check.py disasm --address 0x1008ae9`.
