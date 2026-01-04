@echo off
setlocal EnableExtensions

set "ARGS=--fake --fake-ttl 8"

set "EXE=%~dp0dpibreak.exe"
set "BAT=%0"

if not exist "%EXE%" (
  echo [ERROR] "%EXE%" not found.
  pause
  exit /b 1
)

net session >nul 2>&1
if %errorlevel%==0 goto :run

echo Requesting administrator privileges...
powershell -NoProfile -ExecutionPolicy Bypass ^
  -Command "Start-Process -FilePath '%~f0' -ArgumentList 'ELEVATED' -Verb RunAs"
exit /b

:run

rem ===Admin===

if /I "%~1"=="ELEVATED" shift

echo Running: "%EXE%" %ARGS%
echo Note: If you want to change args (like --fake-ttl) modify ARGS= line of %BAT%.
echo(

pushd "%~dp0"
"%EXE%" %ARGS%
set "RC=%ERRORLEVEL%"
popd

echo Exit code: %RC%
pause
exit /b %RC%
