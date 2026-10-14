# Builds aicalc.exe and runs every test: Rust unit tests, then the
# binary-vs-binary equivalence suite against the original calc.exe.
#
#   .\run_tests.ps1            # everything (opens and closes Calculator windows)
#   .\run_tests.ps1 -SkipGui   # static checks only
#
# Run from an elevated prompt to also exercise the ETW capture tests.
param([switch]$SkipGui)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if ((Test-Path $cargoBin) -and -not ($env:PATH -split ';' -contains $cargoBin)) {
    $env:PATH = "$cargoBin;$env:PATH"
}

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    Write-Host "==> $Name" -ForegroundColor Cyan
    # cargo reports progress on stderr; judge success by exit code only.
    $ErrorActionPreference = 'Continue'
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit $LASTEXITCODE)" }
}

Invoke-Step 'cargo build --release' { cargo build --release }
Copy-Item 'target\i686-pc-windows-msvc\release\aicalc.exe' '.\aicalc.exe' -Force
$env:AICALC_EXE = (Resolve-Path '.\aicalc.exe').Path

Invoke-Step 'cargo test (unit tests, i686)' { cargo test --lib }

Invoke-Step 'python test dependencies' { python -m pip install --quiet --disable-pip-version-check -r tests\requirements.txt }

if ($SkipGui) { $env:AICALC_SKIP_GUI = '1' } else { Remove-Item Env:\AICALC_SKIP_GUI -ErrorAction SilentlyContinue }
Invoke-Step 'equivalence tests (calc.exe vs aicalc.exe)' { python -m unittest tests.test_equivalence -v }

Write-Host 'All tests passed.' -ForegroundColor Green
