# dpibreak-gui

A small Windows control panel for DPIBreak. It does not change how
`dpibreak.exe` works: it manages it as a Windows service and starts
it temporarily to test configurations.

## Layout

Everything is on one screen:

- **Protection** (top left): whether this PC is protected, with a
  one-click Start / Stop (or Install) button; chips for the service
  state, auto-start and the WinDivert driver; any dpibreak.exe running
  outside the service, with Terminate. Refreshed every 2 seconds.
- **Service** (bottom left): program path, settings (arguments),
  start with Windows; Apply settings (restarts the service if
  running), Restart, Uninstall, open the service log folder. A
  "Not applied" tag shows when the edited settings differ from what
  the service runs.
- **Connection test** (top right): probes the listed HTTPS sites (14
  by default: control sites plus sites often blocked by DPI) with the
  current setup, in two columns: response time when reachable, or DNS,
  DNS redirect, IP block, timeout, TLS cut, reset. Hover a result for
  an explanation.
- **Find working settings** (bottom right): pauses the service, tests
  without DPIBreak, then starts dpibreak.exe with each listed setting
  in turn. Each setting gets a row with one dot per site and a score;
  the best one is marked and **Use** copies it to the Service card.
  The service is restored afterwards.
- **Activity** (bottom): what the panel is doing, with Cancel.

Sites, configurations, the `dpibreak.exe` path and the service
arguments are saved in `%APPDATA%\DPIBreak-GUI\settings.json`.

## Single-file download

Latest release:
<https://github.com/siimsek/dpibreak/releases/latest/download/DPIBreak-Panel.exe>

`DPIBreak-Panel.exe` is all a user needs. It embeds `dpibreak.exe`,
`WinDivert.dll` and `WinDivert64.sys`, writes them to
`%ProgramData%\DPIBreak\bin` on start, and installs the service from
there. When a newer panel ships a newer `dpibreak.exe`, the files are
updated on start (the service is stopped and restarted if it runs the
built-in copy).

That folder is restricted to SYSTEM and Administrators (Users can read
and run), because the service runs `dpibreak.exe` from it as SYSTEM.

## Behavior notes

- Only one panel runs at a time; opening it again brings the existing
  window to the front.
- Test copies of `dpibreak.exe` started by the settings search always
  end with the panel, even if it crashes or is killed.
- If the window is closed while the service is paused for a search, a
  restart or an update, the service is started again.
- If the service stops right after starting, the panel says so at
  once; usually the settings are invalid for that dpibreak version.

## Requirements

- Windows 10 1803 or later (uses the bundled `curl.exe` and `sc.exe`).
- Administrator rights (the executable requests them on start).

## Build

Single file (downloads and verifies WinDivert if needed):

```powershell
powershell -ExecutionPolicy Bypass -File gui\build-bundle.ps1
```

The result is `dist\DPIBreak-Panel.exe`. The `DPIBreak Panel` GitHub
workflow builds the same file on every push to `feature/gui` and
uploads it as an artifact; releases are published from that artifact.

Development build without embedded files (then `dpibreak.exe` must be
next to the panel, on `PATH`, or set in the Service card):

```powershell
cargo build --release -p dpibreak-gui
```

On other platforms the binary builds but only prints that it is
Windows only.
