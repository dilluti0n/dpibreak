# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the single-file DPIBreak Panel: dpibreak.exe and the WinDivert
# driver files are embedded into dpibreak-gui.exe.
#
# Usage (from anywhere):  powershell -ExecutionPolicy Bypass -File gui\build-bundle.ps1
# Output:                 dist\DPIBreak-Panel.exe

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# cargo may not be on PATH yet in a shell opened before rustup ran.
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:PATH = "$cargoBin;$env:PATH"
    } else {
        throw 'cargo not found. Install Rust from https://rustup.rs and try again.'
    }
}

function Invoke-Checked([string]$what, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$what failed with exit code $LASTEXITCODE" }
}

$stage = $env:DPIBREAK_BUNDLE_DIR
if ($stage) {
    $stage = (Resolve-Path $stage).Path
    foreach ($name in @('dpibreak.exe', 'WinDivert.dll', 'WinDivert64.sys')) {
        if (-not (Test-Path (Join-Path $stage $name))) {
            throw "Missing released file: $name"
        }
    }
} else {
    # WinDivert, verified against the same hash as CI.
    $wd = Join-Path $root 'WinDivert-2.2.2-A\x64'
    if (-not (Test-Path (Join-Path $wd 'WinDivert64.sys'))) {
        Write-Host 'Downloading WinDivert 2.2.2...'
        $zip = Join-Path $env:TEMP "WinDivert-2.2.2-A-$PID.zip"
        Invoke-WebRequest -UseBasicParsing -OutFile $zip `
            -Uri 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
        $hash = (Get-FileHash -Algorithm SHA256 $zip).Hash
        if ($hash -ne '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15') {
            Remove-Item $zip
            throw "WinDivert.zip sha256 mismatch: $hash"
        }
        Expand-Archive -Path $zip -DestinationPath $root -Force
        Remove-Item $zip
    }

    Write-Host 'Building dpibreak.exe...'
    Invoke-Checked 'cargo build dpibreak' { cargo build --release --locked -p dpibreak }

    $stage = Join-Path $root 'target\bundle'
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item -Force (Join-Path $root 'target\release\dpibreak.exe') $stage
    Copy-Item -Force (Join-Path $wd 'WinDivert.dll') $stage
    Copy-Item -Force (Join-Path $wd 'WinDivert64.sys') $stage
}

# 4. The panel with everything embedded.
Write-Host 'Building DPIBreak Panel...'
$env:DPIBREAK_BUNDLE_DIR = $stage
Invoke-Checked 'cargo build dpibreak-gui' { cargo build --release --locked --manifest-path (Join-Path $root 'gui\Cargo.toml') }

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$out = Join-Path $dist 'DPIBreak-Panel.exe'
Copy-Item -Force (Join-Path $root 'gui\target\release\dpibreak-gui.exe') $out

$size = '{0:N1} MB' -f ((Get-Item $out).Length / 1MB)
$sha = (Get-FileHash -Algorithm SHA256 $out).Hash
$checksumPath = "$out.sha256"
$checksumLine = "$($sha.ToLowerInvariant())  $(Split-Path -Leaf $out)" + [Environment]::NewLine
[IO.File]::WriteAllText($checksumPath, $checksumLine, [Text.Encoding]::ASCII)
Write-Host "Done: $out ($size)"
Write-Host "SHA256: $sha"
Write-Host "Checksum: $checksumPath"
