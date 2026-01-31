@REM SPDX-FileCopyrightText: 2025-2026 Dilluti0n <hskimse1@gmail.com>
@REM SPDX-License-Identifier: GPL-3.0-or-later

@echo off

set "ARGS=--fake --fake-ttl 8 --fake-autottl"
set "EXE=%~dp0dpibreak.exe"
set "BAT=%0"

pushd "%~dp0"
start "" %EXE% %ARGS%
popd >nul

exit /b 0
