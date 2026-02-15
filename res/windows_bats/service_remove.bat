@REM SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
@REM SPDX-License-Identifier: GPL-3.0-or-later

@echo Please run this script with administrator privileges.
@echo Right click, select "Run as administrator".
@echo.
@echo Press any key if you are running this as administrator.
@pause

@set "SERVNAME=dpibreak"

sc stop %SERVNAME%
sc delete %SERVNAME%
@if %ERRORLEVEL% equ 0 (
    @echo.
    @echo Service %SERVNAME% removed successfully.
    @sc stop windivert >nul 2>&1
) else (
    @echo.
    @echo Service %SERVNAME% not found or already removed.
)
@pause
