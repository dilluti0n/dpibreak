# dpibreak-gui

A small Windows control panel for DPIBreak. It does not change how
`dpibreak.exe` works: it manages it as a Windows service and starts
it temporarily to test configurations.

## Layout

Everything is on one screen:

- **Status** (top left): whether protection is on, the service state
  and start type, the settings it runs with, the WinDivert driver, and
  any dpibreak.exe running outside the service (with a Terminate
  button). Refreshed every 2 seconds.
- **Service** (bottom left): program path, settings (arguments),
  start with Windows; Install and start, Start/Stop, Apply settings
  (restarts the service if running), Restart, Uninstall, open the
  service log folder. A "Not applied" tag shows when the edited
  settings differ from what the service runs.
- **Connection test** (top right): probes the listed HTTPS sites with
  the current setup and shows each result as Reachable, DNS blocked,
  DNS redirected, IP blocked, or Blocked (timeout, TLS, reset). Hover
  a result for an explanation.
- **Find working settings** (bottom right): pauses the service, tests
  without DPIBreak, then starts dpibreak.exe with each listed setting
  in turn. Each setting gets a row with one dot per site and a score;
  the best one is marked and **Use** copies it to the Service card.
  The service is restored afterwards.
- **Activity** (bottom): what the panel is doing, with Cancel.

Sites, configurations, the `dpibreak.exe` path and the service
arguments are saved in `%APPDATA%\DPIBreak-GUI\settings.json`.

## Requirements

- Windows 10 1803 or later (uses the bundled `curl.exe` and `sc.exe`).
- Administrator rights (the executable requests them on start).
- `dpibreak.exe` next to `dpibreak-gui.exe`, on `PATH`, or set on the
  Service tab. The path of an already installed service is detected.

## Build

```powershell
cargo build --release -p dpibreak-gui
```

The executable is `target\release\dpibreak-gui.exe`. On other
platforms the binary builds but only prints that it is Windows only.
