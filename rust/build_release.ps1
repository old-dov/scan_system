param(
    [string]$Version = '1.1.1',
    [string]$OutputSuffix = '',
    [string]$IsccPath = '',
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $PSScriptRoot
try {
    cargo build --release --locked -p scan-system-gui -p scan-system-cli
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

foreach ($name in @('scan-system-gui.exe', 'scan-system-cli.exe')) {
    $binary = Join-Path $PSScriptRoot "target\release\$name"
    if (-not (Test-Path -LiteralPath $binary)) { throw "Missing Rust binary: $binary" }
}

if ($SkipInstaller) {
    Write-Output 'Rust release binaries built.'
    return
}

$iscc = if ($IsccPath) {
    (Resolve-Path -LiteralPath $IsccPath -ErrorAction Stop).Path
} else {
    @(
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
}
if (-not $iscc) { throw 'Stable Inno Setup 6 is required; pass -IsccPath for another stable compiler.' }

Push-Location $repoRoot
try {
    # Compile without output first so preview/beta compilers cannot create a
    # distributable artifact by mistake. The local 7.0 preview says not to use
    # its output in production.
    $probeOutput = & $iscc '/O-' "/DMyAppVersion=$Version" 'installer_rust.iss' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup validation failed ($LASTEXITCODE): $probeOutput" }
    if (($probeOutput | Out-String) -match 'Compiler engine version:.*-(preview|beta)') {
        throw 'A preview/beta Inno Setup compiler cannot build a distributable installer.'
    }
    & $iscc "/DMyAppVersion=$Version" "/DMyOutputSuffix=$OutputSuffix" 'installer_rust.iss'
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

Write-Output (Join-Path $PSScriptRoot "installer_output\ScanSystemRustSetup-$Version$OutputSuffix.exe")
