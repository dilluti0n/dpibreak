$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$ProjectName = "DPIBreak"
$ProgramName = "dpibreak"
$BuildTarget = "x86_64-pc-windows-msvc"

$ReleaseDir = Join-Path $PSScriptRoot "target" $BuildTarget "release"
$WinDivertDir = Join-Path $PSScriptRoot "WinDivert-2.2.2-A" "x64"

$ProjectVersion = (cargo metadata --format-version=1 --no-deps | ConvertFrom-Json).packages `
    | Where-Object { $_.name -eq $ProgramName } `
    | Select-Object -ExpandProperty version
$SourceDateEpoch = git log -1 --format=%ct

$DistDir = Join-Path $PSScriptRoot "dist"
$DistName = "$($ProgramName)-$($ProjectVersion)"
$Archive = "$($ProgramName)-$($ProjectVersion)-$($BuildTarget)"
$DistPath = Join-Path $DistDir $DistName
$ManualUrl = "https://git.dilluti0n.com/dpibreak.git/about/dpibreak.1?h=v$($ProjectVersion)%5E%7Bcommit%7D"
$ZipBallPath = Join-Path $DistDir "$($Archive).zip"
$Sha256Path = "$($ZipBallPath).sha256"
$BuildInfoPath = Join-Path $DistDir "$($Archive).buildinfo"

$DistElems = @(
    (Join-Path $ReleaseDir "$($ProgramName).exe"),
    (Join-Path $WinDivertDir "WinDivert.dll"),
    (Join-Path $WinDivertDir "WinDivert64.sys"),
    "README.md",
    "CHANGELOG.md",
    "COPYING",
    "WINDOWS_GUIDE.txt"
)

& (Join-Path $PSScriptRoot "scripts" "fetch-windivert.ps1")

cargo build --release --locked --target "$BuildTarget"
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed with exit code $LASTEXITCODE"
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
if (Test-Path $DistPath) {
    Remove-Item -Recurse -Force -Path $DistPath
}
New-Item -ItemType Directory -Path $DistPath | Out-Null

foreach ($src in $DistElems) {
    if (-not (Test-Path $src)) {
        throw "Source file not found: $src"
    }

    $fileName = Split-Path $src -Leaf
    if ($fileName -eq "COPYING") {
        $fileName = "COPYING.txt"
    }
    $dst = Join-Path $DistPath $fileName

    if ($fileName -eq "WINDOWS_GUIDE.txt") {
        $guide = [System.IO.File]::ReadAllText((Resolve-Path $src).Path).Replace("@MANUAL_URL@", $ManualUrl)
        [System.IO.File]::WriteAllText($dst, $guide, [System.Text.UTF8Encoding]::new($false))
    } else {
        Copy-Item -Path $src -Destination $dst
    }
}

Copy-Item (Join-Path $PSScriptRoot "res\windows_bats\*") -Destination $DistPath -Recurse -Force

Push-Location -Path $DistDir
Compress-Archive -Path $DistName -DestinationPath $ZipBallPath -Force
Pop-Location

$fileHash = Get-FileHash -Algorithm SHA256 -Path $ZipBallPath
"$($fileHash.Hash.ToLower()) `*$($ZipBallPath | Split-Path -Leaf)" | Set-Content -Path $Sha256Path

$gitCommit = git rev-parse HEAD
$rustcVersion = rustc --version
$cargoVersion = cargo --version
$buildDate = Get-Date -UnixTimeSeconds $SourceDateEpoch -Format "yyyy-MM-ddTHH:mm:ssZ"
$osInfo = (Get-ComputerInfo).OsName + " / " + (Get-CimInstance Win32_OperatingSystem).Version

@"
Name:         $ProjectName
Version:      $ProjectVersion
Commit:       $gitCommit
Target:       $BuildTarget
Rustc:        $rustcVersion
Cargo:        $cargoVersion
Date:         $buildDate
Host:         $osInfo
libc:         N/A (Windows/MSVC)
"@ | Set-Content -Path $BuildInfoPath

Write-Host "Created $ZipBallPath"
