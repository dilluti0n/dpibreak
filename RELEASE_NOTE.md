Bugfix release:
- Linux: fix IPv6 SYN/ACK BPF filter (previously only matched IPv4)
- Linux: fix SYN/ACK rules installed on iptables
- Windows: remove unneeded IP checksum calculation

## Installation
### Windows
1. Download the `.zip` from the below and extract it.
2. Double-click `dpibreak.exe` to run, or `start_fake.bat` for [fake](https://github.com/Dilluti0n/DPIBreak#fake) mode.
3. To run automatically on boot, run `service_install.bat` as administrator.

See `WINDOWS_GUIDE.txt` in the zip for more details. If you have trouble deleting the previous version's folder when updating, see [#21](https://github.com/Dilluti0n/DPIBreak/issues/21).

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
