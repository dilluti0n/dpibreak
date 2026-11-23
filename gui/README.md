# DPIBreak Panel

The `dpibreak-gui` crate provides a control panel for Windows and Linux.
It shows protection status, tests connections, compares settings and
manages the platform service.

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

Sites, configurations and service arguments are saved in the user's
settings file. On Windows this is
`%APPDATA%\DPIBreak-GUI\settings.json`; on Linux it is
`$XDG_CONFIG_HOME/dpibreak-gui/settings.json`, or
`~/.config/dpibreak-gui/settings.json` when `XDG_CONFIG_HOME` is unset.

## Linux single-file download

Download the x86-64 panel:

<https://github.com/siimsek/dpibreak/releases/latest/download/DPIBreak-Panel-linux-x86_64>

## One-command install and launch

On Windows, run this in PowerShell:

```powershell
irm https://raw.githubusercontent.com/siimsek/dpibreak/master/gui/install-windows.ps1 | iex
```

The script downloads the latest Windows panel, verifies its SHA-256
digest, stores a per-user copy under `%LOCALAPPDATA%`, and launches it.
The panel may show a Windows administrator prompt when it starts.

On Linux, run:

```sh
curl -fsSL https://raw.githubusercontent.com/siimsek/dpibreak/master/gui/install-linux.sh | sh
```

The script checks for x86-64, downloads the Linux panel and its `.sha256`
file, verifies the binary, installs it under `~/.local/bin`, and launches
it as the current desktop user. Do not run it as root. It requires a
glibc-based x86-64 desktop with the X11 or Wayland and OpenGL libraries
listed below; Alpine/musl and ARM are not supported by this release.
The first Linux panel release must include both the executable and its
checksum file. Re-running the command downloads and launches the latest
release.

These commands execute the installer script from the project repository.
Download the script first if you want to inspect it before running it.

The executable embeds a static `dpibreak` binary. The panel itself uses
the system glibc and the desktop's X11 or Wayland and OpenGL libraries.
The release build runs on Ubuntu 22.04 to keep its glibc requirement
compatible with Debian 12 and newer and Ubuntu 22.04 and newer. Arch
Linux and Arch-based distributions provide a newer glibc.

Run the panel as your desktop user, never with `sudo`:

```sh
chmod +x DPIBreak-Panel-linux-x86_64
./DPIBreak-Panel-linux-x86_64
```

The panel uses `pkexec` when an operation needs administrator access.
It starts the same executable with `--helper` and sends a restricted
JSON-lines protocol over stdin/stdout; the helper accepts known service
and process operations and uses argument vectors instead of a shell.
The helper stays connected for the panel session, so later privileged
actions reuse it instead of opening another password prompt. Closing the
panel closes the helper. If a connection search had paused the service,
the helper restores it when its input closes.

Installing the service writes
`/etc/systemd/system/dpibreak.service` and installs the embedded binary
at `/usr/local/lib/dpibreak/dpibreak`. **Start at boot** enables or
disables the systemd unit. Service logs are read from the systemd
journal and shown in the panel.

The runtime needs systemd, polkit (`pkexec` and a desktop authentication
agent), a graphical X11 or Wayland session with OpenGL support, and
nftables (or iptables) plus kernel NFQUEUE support for DPIBreak's
default rules. On Arch Linux, the `polkit` and `nftables` packages
provide the privileged helper and default firewall command. On Debian,
install `policykit-1` and `nftables`; Debian's `policykit-1` package
provides `pkexec`. The GUI does not need to run as root. A desktop-menu
entry can be installed for the current user from a source checkout:

On a minimal Debian 12 or Ubuntu 22.04 desktop, install the shared GUI
libraries if they are not already present:

```sh
sudo apt install libx11-6 libxcursor1 libxrandr2 libxi6 libxkbcommon0 \
  libwayland-client0 libwayland-cursor0 libwayland-egl1 libgl1 libegl1
```

```sh
sh gui/linux/install-desktop.sh
```

Pass a downloaded panel path to the script when it is not at the default
`dist/` location:

```sh
sh gui/linux/install-desktop.sh ./DPIBreak-Panel-linux-x86_64
```

### Build on Arch Linux or Debian-based systems

Install the native GUI and musl build dependencies, then add the Rust
target used for the embedded `dpibreak` binary.

On Arch Linux:

```sh
sudo pacman -S --needed base-devel pkgconf musl libx11 libxcursor \
  libxrandr libxi libxkbcommon wayland libglvnd
rustup target add x86_64-unknown-linux-musl
sh gui/build-bundle.sh
```

On Debian 12 or Ubuntu 22.04 and newer:

```sh
sudo apt install build-essential pkg-config musl-tools libx11-dev \
  libxcursor-dev libxrandr-dev libxi-dev libxkbcommon-dev \
  libwayland-dev libgl1-mesa-dev libegl1-mesa-dev
rustup target add x86_64-unknown-linux-musl
sh gui/build-bundle.sh
```

The result is `dist/DPIBreak-Panel-linux-x86_64` and its
`DPIBreak-Panel-linux-x86_64.sha256` checksum file. The build script
replaces that file atomically, so an already-open panel can finish using
the previous executable while new launches use the rebuilt one.
Local builds use the host's glibc baseline, so a bundle built on Arch or
a newer Ubuntu may need a glibc version newer than Debian 12 or Ubuntu
22.04. For one binary across those distributions, build on Ubuntu 22.04
(e.g. in a container); the result requires at most `GLIBC_2.35`.

## Single-file download

### Windows

Latest release:
<https://github.com/siimsek/dpibreak/releases/latest/download/DPIBreak-Panel.exe>

The Windows bundle build also writes `DPIBreak-Panel.exe.sha256`. Attach
the executable and checksum file when manually creating a panel release.

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

The result is `dist\DPIBreak-Panel.exe`. Releases are published
manually from the bundle builds.

Development build without embedded files (then `dpibreak.exe` must be
next to the panel, on `PATH`, or set in the Service card):

```powershell
cargo build --release --manifest-path gui/Cargo.toml
```

`gui/` is its own Cargo workspace with its own `Cargo.lock` and
`target/`, so it does not touch the dpibreak workspace. On platforms
other than Windows and Linux the binary builds but only prints that it
is unsupported.
