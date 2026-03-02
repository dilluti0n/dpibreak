On Linux, SYN/ACK sniffing for `--fake-autottl` now uses AF_PACKET RxRing instead of nftables-based filtering. This removes the extra nftables rules that were needed for SYN/ACK capture and should be more efficient. On Windows, WinDivert is now opened as separate recv/send/sniff handles, and the sniff thread is only spawned when `--fake-autottl` is actually enabled.

Other changes: Windows exits immediately on Ctrl-C instead of waiting for cleanup, logging defers `local_time()` until the log level check passes, and `infer_hops` now correctly uses 128 (was 126). Various internal refactoring for consistency.

## Installation
### Windows
1. Download the `.zip` from the below and extract it.
2. Double-click `dpibreak.exe` to run, or `start_fake.bat` for [fake](https://github.com/Dilluti0n/DPIBreak#fake) mode.
3. To run automatically on boot, run `service_install.bat` as administrator.

See `WINDOWS_GUIDE.txt` in the zip for more details.

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

Also available via [Gentoo GURU](https://gitweb.gentoo.org/repo/proj/guru.git/tree/net-misc/dpibreak) and [crates.io](https://crates.io/crates/dpibreak).
