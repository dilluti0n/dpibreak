Configurable segmentation order for the TLS ClientHello split.

The split behavior can now be controlled via `-o, --segment-order`. The argument is a comma-separated list of byte offsets defining segment boundaries and transmission order. For example, `--segment-order 5,1,3,0` splits the payload at bytes 1, 3, and 5, then sends them out of order. See [dpibreak](https://github.com/dilluti0n/dpibreak/blob/master/dpibreak.1.md)(1) for the full specification and [#20](https://github.com/dilluti0n/dpibreak/issues/20) for examples.

> [!NOTE]
> Some servers may return a connection error with the default `0,1` split (first byte sent separately). If this happens, try `--segment-order 0,5`. See [#23](https://github.com/Dilluti0n/DPIBreak/issues/23) for details.

Other changes:
- New short options: `-d` for `--daemon`, `-t` for `--fake-ttl`, `-a` for `--fake-autottl`.
- `-D` is deprecated in favor of `-d` (will be removed on v1.0.0).
- Renamed "fragment" to "segmentation" in documentation.

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
