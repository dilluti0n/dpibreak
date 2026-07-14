Mostly fixes and internal stabilization.

On Windows, to make `WinDivert64.sys` available for deletion after the program terminates, the WinDivert service is now stopped on dpibreak termination. This prevents the [error](https://github.com/dilluti0n/dpibreak/issues/29) during `winget update --all`. (#21, #30)

On Linux, there was a lot of internal refactoring, including possible fixes for memory ordering and packet buffer offset calculation in the rxring module.

Other fixes:
- Windows: keep the console window open on error so the message stays readable.
- Windows: race condition and dangling pointer in the `windivert` crate. (#30)
- Linux: iptables rules were not cleaned up on startup.
- Linux: signal handling now uses signalfd integrated into the existing poll loop instead of a handler and a global flag.

## Installation
### Windows
Via winget:
```powershell
winget install dpibreak
```
(Full package ID: `Dilluti0n.DPIBreak`)
Run `dpibreak` on powershell or start (`Windows+R`). If error occurs on update, see [#29](https://github.com/dilluti0n/dpibreak/issues/29).

Portable download:
1. Download the `.zip` from the below and extract it.
2. Double-click `dpibreak.exe` to run, or `start_fake.bat` for [fake](https://github.com/dilluti0n/dpibreak#fake) mode.
3. To run automatically on boot, run `service_install.bat` as administrator.

See `WINDOWS_GUIDE.txt` in the zip for more details. If you have trouble deleting the previous version's folder when updating, see [#21](https://github.com/dilluti0n/dpibreak/issues/21).

> [!NOTE]
> On first run, Windows SmartScreen may block the binary. Double-click `dpibreak.exe` (or run it from `cmd`), then click **More info -> Run anyway**. After that, `dpibreak` works from any terminal including PowerShell. See [#25](https://github.com/dilluti0n/dpibreak/issues/25) for details.

### Linux
One-liner install:
```
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh
```

Or download the tarball from the assets below:
```
tar -xf dpibreak-*.tar.gz
cd dpibreak-*/
sudo make install
```

Also available via Arch [AUR](https://aur.archlinux.org/packages/dpibreak), Gentoo [GURU](https://gitweb.gentoo.org/repo/proj/guru.git/tree/net-misc/dpibreak) and [crates.io](https://crates.io/crates/dpibreak). See [README.md](https://github.com/dilluti0n/dpibreak/blob/master/README.md#Installation) for details.
