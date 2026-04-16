## [DPIBreak v0.6.1] - 2026-04-16
### Changed
- Windows: wait for keypress before exit on `--help'

### Fixed
- Fix `-D` deprecation warning never firing (was checking wrong
  condition)
- Linux: drain AF_PACKET rx ring before nfqueue in the poll loop to
  reduce the race window where HopTab lookup could miss a hop value
  whose SYN/ACK had already arrived in the same wakeup

## [DPIBreak v0.6.0] - 2026-04-05
### Added
- Option `-o, --segment-order`: configure segment boundaries and
  transmission order of the TLS ClientHello. (#20)
- Short option `-t` and `-a` for `--fake-ttl` and `--fake-autottl`,
  respectively.
- Short option `-d` for `--daemon`, deprecating `-D` (will be removed
  on v1.0.0).

### Changed
- Renamed "fragment" to "segmentation" in `README.md`.

## [DPIBreak v0.5.1] - 2026-03-10
### Fixed
- Linux: fix BPF filter to match IPv6 SYN/ACK also (previously only
  matched IPv4)
- Linux: fix SYN/ACK rules installed on iptables
- Windows: remove unneeded IP checksum calculation

## [DPIBreak v0.5.0] - 2026-03-02
### Added
- Linux: AF_PACKET RxRing for SYN/ACK sniffing (replaces
  nftables-based filtering)
- Windows: separate WinDivert handles for recv/send/sniff
- Windows: SYN/ACK sniff thread spawned only when `--fake-autottl` is
  enabled

### Changed
- Linux: replaced serde_json with nft text syntax for nftables rules
- Linux: removed unnecessary Mutex from RAW4/RAW6 (Socket is already
  Sync)
- Refactored send_to_raw to remove in-place packet reparsing
- Windows: simplified packet handling with `recv_loop` macro
- Windows: exit immediately on Ctrl-C
- Deferred `local_time()` call until log level check passes
- Various internal renames for consistency (drop `_0` suffixes, swap
  naming conventions)
- Refactored platform cleanup/trap_exit/RUNNING into platform modules
- Windows: service_install.bat no longer enables fake options by
  default. Add `--fake-autottl` to ARGS manually if needed.

### Fixed
- `infer_hops`: use 128, not 126

## [DPIBreak v0.4.3] - 2026-02-16
Documentation fix from v0.4.2 and add timestamp on log.
- docs: fix incorrect pathes in manual (`/tmp/dpibreak.pid` ->
  `/run/dpibreak.pid`, `/tmp/dpibreak.log` -> `/var/log/dpibreak.log`)
- log: print timestamp on log output
- windows: fix regression introduced on v0.4.2 on service mode

## [DPIBreak v0.4.2] - 2026-02-16
- Move PID file to `/run/dpibreak.pid` and daemon log file to
  `/var/log/dpibreak.log`. (Fixes #16)
- Add root privilege check on startup. (#16)
- Fix log file being truncated when daemonize fails. (#17)

## [DPIBreak v0.4.1] - 2026-02-15
Linux only hotfix:

Fixed issue where running dpibreak again while a daemon instance was
active would silently delete nftables rules and then fail with nfqueue
binding error. Non-daemon mode now also acquires PID file lock to
ensure only one dpibreak instance runs on the system at a time,
whether daemon or non-daemon.
- TL;DR: Enforce single `dpibreak` instance per system on Linux.

## [DPIBreak v0.4.0] - 2026-02-15
Added background execution support for both platforms. On Linux, run
`dpibreak -D` to start as a daemon. On Windows, run
service_install.bat as administrator to install and start a Windows
service that also runs automatically on boot.
- Add option `-D, --daemon`.
  - linux: run as a background daemon.
  - windows: run as Windows service entry point.
- windows: add `service_install.bat`, `service_remove.bat` for Windows
  service management.
- windows: add `WINDOWS_GUIDE.txt` with Korean translation.

## [DPIBreak v0.3.0] - 2026-01-31
Feature addition.
- Add `--fake-autottl`: Dynamically infer the hop count to the
  destination by analyzing inbound SYN/ACK packets.
- `--fake-*` options (`--fake-ttl`, `--fake-autottl`, `--fake-badsum`)
  now implicitly enable the `--fake`. Manual activation of `--fake` is
  no longer required when using this options.

## [DPIBreak v0.2.2] - 2026-01-17
Maintenance release; reduce binary size (on Linux, ~2.2M -> ~700K). No
behavior changed.
- linux: drop iptables crate (regex dep) to reduce binary size
- Enable LTO and panic=abort to reduce binary size

## [DPIBreak v0.2.1] - 2026-01-16
Hotfix from v0.2.0:
- Fix default log level to `warn` in release builds. (v0.2.0 silently
  changed it).
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
