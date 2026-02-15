## [DPIBreak v0.4.2] - 2026-02-16
Hotfix from [v0.4.1](https://github.com/dilluti0n/dpibreak/releases/tag/v0.4.0). Linux only — Windows users do not need to update from v0.4.0 or v0.4.1.

**Upgrading from v0.4.0/v0.4.1:** Stop any running dpibreak instance (`sudo pkill dpibreak`) before upgrading. The PID file path has changed, so the new binary won't detect the old instance.

- Move PID file to `/run/dpibreak.pid` and daemon log file to `/var/log/dpibreak.log`. (Fixes #16)
- Add root privilege check on startup. (#16)
- Fix log file being truncated when daemonize fails. (#17)

For new features added on 0.4 (which introduce windows service and daemonize on linux), see [v0.4.0](https://github.com/dilluti0n/dpibreak/releases/tag/v0.4.0) release note.

## [DPIBreak v0.4.1] - 2026-02-15
Linux only hotfix:

Fixed issue where running dpibreak again while a daemon instance was active would silently delete nftables rules and then fail with nfqueue binding error. Non-daemon mode now also acquires PID file lock to ensure only one dpibreak instance runs on the system at a time, whether daemon or non-daemon.
- TL;DR: Enforce single `dpibreak` instance per system on Linux.

For new features added on 0.4 (which introduce windows service and daemonize on linux), see [v0.4.0](https://github.com/dilluti0n/dpibreak/releases/tag/v0.4.0) release note.

## [DPIBreak v0.4.0] - 2026-02-15
Added background execution support for both platforms. On Linux, run `dpibreak -D` to start as a daemon. On Windows, run service_install.bat as administrator to install and start a Windows service that also runs automatically on boot.
- Add option `-D, --daemon`.
  - linux: run as a background daemon.
  - windows: run as Windows service entry point.
- windows: add `service_install.bat`, `service_remove.bat` for Windows service management.
- windows: add `WINDOWS_GUIDE.txt` with Korean translation.

## [DPIBreak v0.3.0] - 2026-01-31
Feature addition.
- Add `--fake-autottl`: Dynamically infer the hop count to the destination by analyzing inbound SYN/ACK packets.
- `--fake-*` options (`--fake-ttl`, `--fake-autottl`, `--fake-badsum`) now implicitly enable the `--fake`. Manual activation of `--fake` is no longer required when using this options.

## [DPIBreak v0.2.2] - 2026-01-17
Maintenance release; reduce binary size (on Linux, ~2.2M -> ~700K). No behavior changed.
- linux: drop iptables crate (regex dep) to reduce binary size
- Enable LTO and panic=abort to reduce binary size

## [DPIBreak v0.2.1] - 2026-01-16
Hotfix from v0.2.0:
- Fix default log level to `warn` in release builds. (v0.2.0 silently changed it).
- Fix unused import warnings in release builds.

## [DPIBreak v0.2.0] - 2026-01-16
- Add option `--fake-badsum` to inject packets with incorrect TCP checksums.
- Deprecate `--loglevel` in favor of `--log-level`.
- windows: prevent `start_fake.bat` comments from being echoed on startup.

## [DPIBreak v0.1.1] - 2026-01-11
Possible bug fix for certain windows system.
- windows: simplify start_fake.bat (#9)

## [DPIBreak v0.1.0] - 2026-01-05
- Initial minor release.
- Fix `fake` enabled by default regardless option `--flag`.

## [DPIBreak v0.0.7] - 2026-01-04
- Introduce feature `fake`, fake ClientHello packet injection.
- Enabled by option `--fake`, the default behavior is unchanged.
- Add options `--fake` and `--fake-ttl`.

## [DPIBreak v0.0.6] - 2025-12-28
- Fixed dependencies to allow installation via cargo install dpibreak.

## [DPIBreak v0.0.5] - 2025-12-22
- linux: properly suppress cleanup warning logs on startup.
- linux: keep error logs on cleanup failure during shutdown.

## [DPIBreak v0.0.4] - 2025-10-29
- linux: add `--nft-command` option to override default nft command.
- linux: silence verbose nftables log on start.

## [DPIBreak v0.0.3] - 2025-10-06
- linux: support nftables backend for default, leaving the existing iptables/ip6tables + xt_u32 as a fallback.
- windows: only divert clienthello packet to userspace.
- windows: close windivert handle on termination.

## [DPIBreak v0.0.2] - 2025-09-11
- Remove unnecessary allocations per packet handling.
- Fix: make install fail on Linux release tarball. (#4)

## [DPIBreak v0.0.1] - 2025-09-07
- Initial release.
- Filter/fragment TCP packet containing SNI field with nfqueue or WinDivert.
