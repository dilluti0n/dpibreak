Performance improvement due to packet sniffing backend changes.

On Linux, SYN/ACK sniffing for `--fake-autottl` now uses AF_PACKET RxRing instead of nftables-based filtering. Packets are read via mmap'd ring buffer with zero copy from kernel to userspace, replacing the extra nftables rules that were needed for SYN/ACK capture.

On Windows, packet handling is now multi-threaded with separate recv/send/sniff paths, while sniff thread is only spawned when `--fake-autottl` is actually enabled.

Other changes:
- Windows exits immediately on Ctrl-C instead of waiting for cleanup.
- Logging defers `local_time()` until the log level check passes.
- `infer_hops` now correctly uses 128 (was 126).
- Various internal refactoring for consistency.
- Windows: service_install.bat no longer enables fake options by
  default. Add `--fake-autottl` to ARGS manually if needed.

## Installation
### Windows
1. Download the `.zip` from the below and extract it.
2. Double-click `dpibreak.exe` to run, or `start_fake.bat` for
   [fake](https://github.com/Dilluti0n/DPIBreak#fake) mode.
3. To run automatically on boot, run `service_install.bat` as administrator.

See `WINDOWS_GUIDE.txt` in the zip for more details. If you have
trouble deleting the previous version's folder when updating, see
[#21](https://github.com/Dilluti0n/DPIBreak/issues/21).

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
