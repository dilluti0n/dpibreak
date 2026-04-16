Maintenance release, due to winget release on windows.

- Windows: wait for keypress before exit on `--help'
- Fix `-D` deprecation warning never firing (was checking wrong condition)
- Linux: drain AF_PACKET rx ring before nfqueue in the poll loop to reduce the race window where HopTab lookup could miss a hop value whose SYN/ACK had already arrived in the same wakeup

## Installation
### Windows
Via winget:
```powershell
winget install dpibreak
```
(Full package ID: `Dilluti0n.DPIBreak`)
Run `dpibreak` on powershell or start (`Windows+R`).

Portable download:
1. Download the `.zip` from the below and extract it.
2. Double-click `dpibreak.exe` to run, or `start_fake.bat` for [fake](https://github.com/Dilluti0n/DPIBreak#fake) mode.
3. To run automatically on boot, run `service_install.bat` as administrator.

See `WINDOWS_GUIDE.txt` in the zip for more details. If you have trouble deleting the previous version's folder when updating, see [#21](https://github.com/Dilluti0n/DPIBreak/issues/21).

> [!NOTE]
> On first run, Windows SmartScreen may block the binary. Double-click `dpibreak.exe` (or run it from `cmd`), then click **More info -> Run anyway**. After that, `dpibreak` works from any terminal including PowerShell. See [#25](https://github.com/dilluti0n/dpibreak/issues/25) for details.

### Linux
One-liner install:
```
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh
```

Or download the tarball from the assets below:
```
tar -xf DPIBreak-*.tar.gz
cd DPIBreak-*/
sudo make install
```

Also available via Arch [AUR](https://aur.archlinux.org/packages/dpibreak), Gentoo [GURU](https://gitweb.gentoo.org/repo/proj/guru.git/tree/net-misc/dpibreak) and [crates.io](https://crates.io/crates/dpibreak). See [README.md](https://github.com/dilluti0n/dpibreak/blob/master/README.md#Installation) for details.
