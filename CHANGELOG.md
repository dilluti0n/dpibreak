## [DPIBreak v0.3.0]
Feature addition.
- Add `--fake-autottl`: Dynamically infer the hop count to the
  destination by analyzing inbound SYN/ACK packets.
- `--fake-*` options (`--fake-ttl`, `--fake-autottl`, `--fake-badsum`)
  now implicitly enable the `--fake`. Manual activation of `--fake` is
  no longer required when using this options.

## [DPIBreak v0.2.2]
Maintenance release; reduce binary size (on Linux, ~2.2M -> ~700K). No
behavior changed.
- linux: drop iptables crate (regex dep) to reduce binary size
- Enable LTO and panic=abort to reduce binary size

## [DPIBreak v0.2.1]
Hotfix from v0.2.0:
- Fix default log level to `warn` in release builds. (v0.2.0 silently
  changed it).
- Fix unused import warnings in release builds.

## [DPIBreak v0.2.0]
- Add option `--fake-badsum` to inject packets with incorrect TCP
  checksums.
- Deprecate `--loglevel` in favor of `--log-level`.
- windows: prevent `start_fake.bat` comments from being echoed on startup.

## [DPIBreak v0.1.1]
Possible bug fix for certain windows system.
- windows: simplify start_fake.bat (#9)

## [DPIBreak v0.1.0]
- Initial minor release.
- Fix `fake` enabled by default regardless option `--flag`.

## [DPIBreak v0.0.7]
- Introduce feature `fake`, fake ClientHello packet injection.
- Enabled by option `--fake`, the default behavior is unchanged.
- Add options `--fake` and `--fake-ttl`.

## [DPIBreak v0.0.6]
- Fixed dependencies to allow installation via cargo install dpibreak.

## [DPIBreak v0.0.5]
- linux: properly suppress cleanup warning logs on startup.
- linux: keep error logs on cleanup failure during shutdown.

## [DPIBreak v0.0.4]
- linux: add `--nft-command` option to override default nft command.
- linux: silence verbose nftables log on start.

## [DPIBreak v0.0.3]
- linux: support nftables backend for default, leaving the existing
  iptables/ip6tables + xt_u32 as a fallback.
- windows: only divert clienthello packet to userspace.
- windows: close windivert handle on termination.

## [DPIBreak v0.0.2]
- Remove unnecessary allocations per packet handling.
- Fix: make install fail on Linux release tarball. (#4)

## [DPIBreak v0.0.1]
- Initial release.
- Filter/fragment TCP packet containing SNI field with nfqueue or
  WinDivert.
