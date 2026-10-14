param([switch]$SkipGui)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    python tools/lift.py
    if ($LASTEXITCODE) { throw 'Lifting failed' }
    python tools/check.py build --release
    if ($LASTEXITCODE) { throw 'Build failed' }
    python tools/check.py test --release
    if ($LASTEXITCODE) { throw 'Rust unit tests failed' }
    python tools/check.py core
    if ($LASTEXITCODE) { throw 'Recovered game math tests failed' }
    if (-not $SkipGui) {
        python tools/check.py gui
        if ($LASTEXITCODE) { throw 'GUI equivalence tests failed' }
        python tools/check.py binary
        if ($LASTEXITCODE) { throw 'Binary/standalone equivalence tests failed' }
    }
} finally { Pop-Location }
