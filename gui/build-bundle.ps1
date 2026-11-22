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

function Invoke-Checked([string]$what, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$what failed with exit code $LASTEXITCODE" }
}

# 1. WinDivert, verified against the same hash as CI.
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

# 2. dpibreak.exe from this checkout.
Write-Host 'Building dpibreak.exe...'
Invoke-Checked 'cargo build dpibreak' { cargo build --release --locked -p dpibreak }

# 3. Stage the files to embed.
$stage = Join-Path $root 'target\bundle'
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item -Force (Join-Path $root 'target\release\dpibreak.exe') $stage
Copy-Item -Force (Join-Path $wd 'WinDivert.dll') $stage
Copy-Item -Force (Join-Path $wd 'WinDivert64.sys') $stage

# 4. The panel with everything embedded.
Write-Host 'Building DPIBreak Panel...'
$env:DPIBREAK_BUNDLE_DIR = $stage
try {
    Invoke-Checked 'cargo build dpibreak-gui' { cargo build --release --locked -p dpibreak-gui }
} finally {
    Remove-Item Env:DPIBREAK_BUNDLE_DIR
}

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$out = Join-Path $dist 'DPIBreak-Panel.exe'
Copy-Item -Force (Join-Path $root 'target\release\dpibreak-gui.exe') $out

$size = '{0:N1} MB' -f ((Get-Item $out).Length / 1MB)
$sha = (Get-FileHash -Algorithm SHA256 $out).Hash
Write-Host "Done: $out ($size)"
Write-Host "SHA256: $sha"
