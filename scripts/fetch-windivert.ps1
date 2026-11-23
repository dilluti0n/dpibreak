# Download WinDivert into the repository root, where .cargo/config.toml
# points WINDIVERT_PATH. Does nothing if it is already there.

$ErrorActionPreference = "Stop"

$Name = "WinDivert-2.2.2-A"
$Url = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/$Name.zip"
$Sha256 = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15"

$Root = Split-Path $PSScriptRoot -Parent
if (Test-Path (Join-Path $Root $Name "x64" "WinDivert.dll")) {
    return
}

$zip = Join-Path ([System.IO.Path]::GetTempPath()) "$Name-$PID.zip"
try {
    Invoke-WebRequest -Uri $Url -OutFile $zip
    $hash = (Get-FileHash -Algorithm SHA256 $zip).Hash
    if ($hash -ne $Sha256) {
        throw "$Name.zip sha256 mismatch: $hash"
    }
    Expand-Archive -Path $zip -DestinationPath $Root -Force
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $zip
}
