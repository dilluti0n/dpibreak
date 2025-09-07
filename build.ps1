<#
.SYNOPSIS
    A PowerShell script for building Windows releases of the DPIBreak project.
.DESCRIPTION
    This script builds the Rust project, creates a ZIP archive for release,
    and generates associated build information and checksum files. It mirrors the functionality
    of the original Makefile for a Windows environment.
.EXAMPLE
    # Creates the release ZIP file and associated info files.
    .\build.ps1 zipball

.EXAMPLE
    # Builds the project in release mode.
    .\build.ps1 build

.EXAMPLE
    # Deletes build artifacts and the distribution directory.
    .\build.ps1 clean

.EXAMPLE
    # Shows the list of available commands.
    .\build.ps1 help
#>

# --- Script Configuration ---
# Set the default encoding to UTF-8 to prevent garbled output.
$OutputEncoding = [System.Text.Encoding]::UTF8

# Stop the script immediately if an error occurs.
$ErrorActionPreference = "Stop"

# --- Project Variables ---
$ProjectName = "DPIBreak"
$ProgramName = "dpibreak"
# $ManPage is removed as it's not relevant for Windows releases.
$BuildTarget = "x86_64-pc-windows-msvc" # A common 64-bit Windows target.

# --- Path Variables ---
$ScriptRoot = $PSScriptRoot # The directory where the script is located.
$TargetDir = Join-Path $ScriptRoot "target"
$ReleaseDir = Join-Path $TargetDir $BuildTarget "release"

# --- Distribution Variables ---
# Get version info from cargo metadata. No jq needed.
try {
    $ProjectVersion = (cargo metadata --format-version=1 --no-deps | ConvertFrom-Json).packages[0].version
}
catch {
    Write-Error "Failed to run cargo metadata. Ensure Rust and Cargo are installed and in your PATH."
    exit 1
}

# Get the last commit time from Git (Unix timestamp).
$SourceDateEpoch = git log -1 --format=%ct

$DistDir = Join-Path $ScriptRoot "dist"
$DistName = "$($ProjectName)-$($ProjectVersion)-$($BuildTarget)"
$DistPath = Join-Path $DistDir $DistName
$ZipBallPath = Join-Path $DistDir "$($DistName).zip"
$Sha256Path = "$($ZipBallPath).sha256"
$BuildInfoPath = Join-Path $DistDir "$($DistName).buildinfo"

# List of files to include in the distribution archive.
# Note: Renaming for COPYING and CHANGELOG is handled during the copy process.
$DistElems = @(
    (Join-Path $ReleaseDir "$($ProgramName).exe"),
    "README.md",
    "dpibreak.1.md"
    "CHANGELOG",
    "COPYING"
)

# --- Function Definitions ---

# Displays the help message.
function Show-Help {
    Write-Host @"
Usage: .\build.ps1 [target]

Targets:
    build       Build the release binary
    zipball     Create a distributable zip archive
    clean       Remove build artifacts
    help        Show this help message
"@
}

# Builds the project in release mode.
function Invoke-Build {
    Write-Host "Building project for target '$BuildTarget'..."
    try {
        cargo build --release --locked --target "$BuildTarget"
        Write-Host -ForegroundColor Green "Build completed successfully."
    }
    catch {
        Write-Error "Cargo build failed."
        exit 1
    }
}

# Creates the release ZIP archive.
function New-ReleaseZip {
    # 1. Run the build
    Invoke-Build

    Write-Host "Creating release zipball..."

    # 2. Create distribution directories
    if (-not (Test-Path $DistDir)) {
        New-Item -ItemType Directory -Path $DistDir | Out-Null
    }
    if (Test-Path $DistPath) {
        Remove-Item -Recurse -Force -Path $DistPath
    }
    New-Item -ItemType Directory -Path $DistPath | Out-Null

    # 2.5. Find local WinDivert dependency
    $winDivertPath = "./WinDivert-2.2.2-A/x64"

    # 3. Copy distribution files
    Write-Host "Copying distribution files..."
    $filesToPackage = $DistElems + "$winDivertPath/WinDivert.dll" + "$winDivertPath/WinDivert64.sys"

    foreach ($elem in $filesToPackage) {
        $sourcePath = $elem # The path is already absolute for the exe and the DLL
        if (-not (Test-Path $sourcePath)) {
            Write-Warning "Source file not found and will be skipped: $sourcePath"
            continue
        }

        $fileName = Split-Path $sourcePath -Leaf
        $destinationPath = Join-Path $DistPath $fileName

        # Handle file renaming
        if ($fileName -eq "COPYING") {
            $destinationPath = Join-Path $DistPath "COPYING.txt"
        } elseif ($fileName -eq "CHANGELOG") {
            $destinationPath = Join-Path $DistPath "CHANGELOG.txt"
        }
        
        Copy-Item -Path $sourcePath -Destination $destinationPath
    }

    # 4. Compress files into a ZIP archive
    Write-Host "Compressing files into '$ZipBallPath'..."
    Compress-Archive -Path (Join-Path $DistPath "*") -DestinationPath $ZipBallPath -Force

    # 5. Generate SHA256 checksum
    Write-Host "Generating SHA256 checksum..."
    $fileHash = Get-FileHash -Algorithm SHA256 -Path $ZipBallPath
    # Output in a format similar to the sha256sum command: "hash *filename"
    "$($fileHash.Hash.ToLower()) `*$($ZipBallPath | Split-Path -Leaf)" | Set-Content -Path $Sha256Path

    # 6. Generate build information file
    Write-Host "Generating build information file..."
    $gitCommit = git rev-parse HEAD
    $rustcVersion = rustc --version
    $cargoVersion = cargo --version
    $buildDate = Get-Date -UnixTimeSeconds $SourceDateEpoch -Format "yyyy-MM-ddTHH:mm:ssZ"
    $osInfo = (Get-ComputerInfo).OsName + " / " + (Get-CimInstance Win32_OperatingSystem).Version

    $buildInfoContent = @"
Name:         $ProjectName
Version:      $ProjectVersion
Commit:       $gitCommit
Target:       $BuildTarget
Rustc:        $rustcVersion
Cargo:        $cargoVersion
Date:         $buildDate
Host:         $osInfo
libc:         N/A (Windows/MSVC)
"@
    $buildInfoContent | Set-Content -Path $BuildInfoPath

    Write-Host -ForegroundColor Green "Release zipball created successfully at '$ZipBallPath'."
}

# Cleans up build artifacts.
function Clear-Artifacts {
    Write-Host "Cleaning up build artifacts..."
    
    # Run cargo clean
    cargo clean

    # Delete the dist directory
    if (Test-Path $DistDir) {
        Remove-Item -Recurse -Force -Path $DistDir
        Write-Host "Removed directory: $DistDir"
    }

    Write-Host -ForegroundColor Green "Cleanup complete."
}


# --- Main Execution Logic ---

# Store the first argument passed to the script in the $command variable.
$command = $args[0]

# Execute the corresponding function based on the argument.
switch ($command) {
    "build"     { Invoke-Build }
    "zipball"   { New-ReleaseZip }
    "clean"     { Clear-Artifacts }
    "help"      { Show-Help }
    default     { Show-Help }
}

