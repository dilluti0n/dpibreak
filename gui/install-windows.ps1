# SPDX-License-Identifier: GPL-3.0-or-later
# Download, verify, install for the current user, and launch the latest panel.

$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'The DPIBreak Panel release currently supports x64 Windows only.'
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is not set; cannot install the panel for this user.'
}

$assetName = 'DPIBreak-Panel.exe'
$releaseUrl = 'https://api.github.com/repos/siimsek/dpibreak/releases/latest'
$headers = @{
    Accept = 'application/vnd.github+json'
    'User-Agent' = 'DPIBreak-Panel-Installer'
}
$release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers
$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
if ($null -eq $asset) {
    throw "The latest release does not contain $assetName."
}

$expectedHash = ''
if ($asset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
    $expectedHash = $Matches[1].ToLowerInvariant()
} else {
    $checksumUrl = "$($asset.browser_download_url).sha256"
    $checksum = (Invoke-WebRequest -UseBasicParsing -Uri $checksumUrl).Content
    $expectedHash = ($checksum -split '\s+')[0].ToLowerInvariant()
}
if ($expectedHash -notmatch '^[0-9a-f]{64}$') {
    throw 'The release does not provide a valid SHA-256 checksum for the panel.'
}

$installDir = Join-Path $env:LOCALAPPDATA 'Programs\DPIBreakPanel'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$fileName = "DPIBreak-Panel-$($expectedHash.Substring(0, 16)).exe"
$target = Join-Path $installDir $fileName

if (Test-Path -LiteralPath $target) {
    $existingHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
    if ($existingHash -ne $expectedHash) {
        Remove-Item -Force -LiteralPath $target
    }
}

if (-not (Test-Path -LiteralPath $target)) {
    $temporary = Join-Path $installDir ".$fileName.$PID.download"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $temporary
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            throw 'SHA-256 verification failed; the panel was not installed.'
        }
        Move-Item -Force -LiteralPath $temporary -Destination $target
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -Force -LiteralPath $temporary
        }
    }
}

Write-Host "Launching verified DPIBreak Panel from $target"
Start-Process -FilePath $target
