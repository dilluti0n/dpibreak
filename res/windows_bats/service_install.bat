@REM SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
@REM SPDX-License-Identifier: GPL-3.0-or-later

@echo Please run this script with administrator privileges.
@echo Right click, select "Run as administrator".
@echo.
@echo Press any key if you are running this as administrator.
@pause

set "ARGS=-D --fake-ttl 8 --fake-autottl"
set "EXE=%~dp0dpibreak.exe"

sc stop dpibreak
sc delete dpibreak
sc create dpibreak binPath= "\"%EXE%\" %ARGS%" start= auto
sc description dpibreak "Simple and efficient DPI circumvention tool in Rust."
sc start dpibreak
@pause
