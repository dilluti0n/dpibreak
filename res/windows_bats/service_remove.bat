@REM SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
@REM SPDX-License-Identifier: GPL-3.0-or-later

@echo Please run this script with administrator privileges.
@echo Right click, select "Run as administrator".
@echo.
@echo Press any key if you are running this as administrator.
@pause

sc stop dpibreak
sc delete dpibreak
sc stop windivert
@pause
