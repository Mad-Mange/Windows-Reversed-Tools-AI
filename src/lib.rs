//! aicalc: Rust translation of Windows `calc.exe` 10.0.26100.8521 (x86).
//!
//! The original is a ~26 KB launcher written in C:
//!
//! 1. msvcrt startup computes `lpCmdLine`/`nShowCmd` and calls `wWinMain`
//!    ([`startup`]).
//! 2. `wWinMain` registers the "MicrosoftCalculator" TraceLogging provider,
//!    writes a `CalculatorWinMain` event if a trace session wants it, and
//!    launches the Calculator app via `ShellExecuteW(L"ms-calculator:")`
//!    ([`calc`], [`tracelogging`]).
//! 3. The process exits with code 0.
//!
//! See `decompiled/` for the reconstructed C and the disassembly this
//! translation was made from.

#![cfg_attr(not(test), no_std)]

pub mod calc;
pub mod startup;
pub mod tracelogging;
pub mod win32;

#[cfg(test)]
mod tests;
