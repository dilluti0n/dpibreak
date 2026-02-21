[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./COPYING)
[![GitHub Release](https://img.shields.io/github/v/release/Dilluti0n/DPIBreak)](https://github.com/Dilluti0n/DPIBreak/releases)
[![Gentoo GURU](https://img.shields.io/badge/Gentoo-GURU-purple.svg)](https://gitweb.gentoo.org/repo/proj/guru.git/tree/net-misc/dpibreak)
[![Crates.io](https://img.shields.io/crates/v/dpibreak)](https://crates.io/crates/dpibreak)

# <img src="./res/icon_origin.png" alt="" width=32> DPIBreak

Fast and easy-to-use tool for circumventing [Deep Packet Inspection
(DPI)](https://en.wikipedia.org/wiki/Deep_packet_inspection) on HTTPS
connections. While your actual data is encrypted over HTTPS, there is
a limitation: the [TLS
ClientHello](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2)
packet - which contains the destination domain
(aka [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication)) - must
be sent in plaintext during the initial handshake. DPI equipment
inspects it at intermediate routers and drops the connection if its
SNI is on their *blacklist*.

The goal of DPIBreak is to manipulate outgoing TLS ClientHello packets
in a standards-compliant way, so that DPI equipment can no longer
detect the destination domain while the actual server still can.

- Unlike VPNs, it requires no external server. All processing happens
entirely on your machine.
- It takes effect immediately on all HTTPS connections when launched,
and reverts automatically when stopped.
- Only the small packets needed for this manipulation are touched. All
other data packets (e.g., video streaming) pass through without
**any** processing, resulting in very low overhead, which is itself
negligible compared to typical internet latency.

> Oh, and if it matters to you: it is built in Rust, which eliminates
> the class of memory vulnerabilities that are particularly important to
> privileged network tools.

**TL;DR:** this tool lets you access ISP-blocked sites at virtually
the same speed as an unrestricted connection, with minimal setup.

## Features
For more information, please refer to
[dpibreak(1)](./dpibreak.1.md). (Though you probably won't need it. :)

### fragment (default)
Split the TLS ClientHello into smaller pieces so that DPI equipment
cannot read the SNI from a single packet. The server reassembles them
normally.

### fake
Enable fake ClientHello packet (with SNI `www.microsoft.com`)
injection before sending each packet fragmented. For typical usage,
use `--fake-autottl`.

I live in South Korea, and Korean ISP-level DPI was bypassable without
this feature. However, the internal DPI at my university was not. With
this feature enabled, the university's DPI was also successfully
bypassed, so I expect it to be helpful in many other use cases as
well.

## Quickstart
Latest release can be downloaded from
<https://github.com/dilluti0n/dpibreak/releases/latest>.
### Windows
- Double-click `dpibreak.exe` or `start_fake.bat` (To use
[fake](#fake)).
- Run `service_install.bat` with administrator privileges to
  automatically run per boot (To remove, run `service_remove.bat`).
- See `WINDOWS_GUIDE.txt` for more information (This file includes a
  Korean translation!).

### Linux
Copy this to your terminal and press ENTER.
```bash
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh
```

This script automates the [manual installation](#manual)
process. [View
source](https://github.com/dilluti0n/dpibreak/blob/master/install.sh).

Usage:
```bash
sudo dpibreak
sudo dpibreak -D                  # run as daemon
sudo pkill dpibreak               # to stop daemon
sudo dpibreak --fake-autottl      # enable fake packet injection
sudo dpibreak -D --fake-autottl
dpibreak --help
man 1 dpibreak                    # manual
```

That's it. For manual installation, removal, and package managers, see
[Installation](#installation).

## Installation
### Manual
```bash
tar -xf DPIBreak-X.Y.Z-x86_64-unknown-linux-musl.tar.gz
cd DPIBreak-X.Y.Z-x86_64-unknown-linux-musl
sudo make install
```
To uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh -s -- uninstall

# Or if you have extracted tarball:
sudo make uninstall
```

### Gentoo
Available in the [GURU](https://wiki.gentoo.org/wiki/Project:GURU)
repository.

```bash
sudo eselect repository enable guru
sudo emaint sync -r guru
echo 'net-misc/dpibreak ~amd64' | sudo tee -a /etc/portage/package.accept_keywords/dpibreak
sudo emerge --ask net-misc/dpibreak
```

### For rust developers (crates.io)
Requirements: `libnetfilter_queue` development files
(e.g.,`libnetfilter-queue-dev` on Ubuntu/Debian).

```bash
cargo install dpibreak
```
Note: cargo installs to user directory, so sudo might not see
it. Use full path or link it:
```bash
# Option 1: Run with full path
sudo ~/.cargo/bin/dpibreak

# Option 2: Symlink to system bin (Recommended)
sudo ln -s ~/.cargo/bin/dpibreak /usr/local/bin/dpibreak
sudo dpibreak
```

## Issue tab
> [!TIP]
> All issues go here: <https://github.com/dilluti0n/dpibreak/issues>

- See [dpibreak(1)#BUGS](./dpibreak.1.md#BUGS) (or unsee it and use
[issue tab](https://github.com/dilluti0n/dpibreak/issues) like reddit
thread).
- You can also search and find workaround for known issues from here.

## To produce release zip/tarball
Release builds and deployments are automated via GitHub Actions. See
[.github/workflows/release.yml](.github/workflows/release.yml) for
details. Compilation requires Rust toolchain. See
<https://www.rust-lang.org/learn/get-started>.

Windows:
1. Download `WinDivert`:
```ps
Invoke-WebRequest -Uri "https://reqrypt.org/download/WinDivert-2.2.2-A.zip" -OutFile WinDivert.zip
Expand-Archive -Path WinDivert.zip -DestinationPath .\
Remove-Item .\WinDivert.zip
```
2. `.\build.ps1 zipball`

Linux: `make tarball`

Release zip/tarball should be ready on directory `dist`.

## Built upon
- [Netfilter-queue](https://netfilter.org/)
- [WinDivert](https://reqrypt.org/windivert.html)
- And many crates. (See [Cargo.lock](./Cargo.lock) for credit)

## Thanks
- [GoodByeDPI](https://github.com/ValdikSS/GoodbyeDPI) by ValdikSS:
  For its design which shaped the project's UX.

For introducing the circumvention idea:
- [zapret](https://github.com/bol-van/zapret) by bol-van
- [SpoofDPI](https://github.com/xvzc/SpoofDPI) by xzvc

## See more
<details>
<summary>alternative tools & useful links</summary>

#### Alternative tools:
- [Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel) by
  SadeghHayeri (for MacOS, Linux and Windows)
- [DPI Tunnel CLI](https://github.com/nomoresat/DPITunnel-cli) by
  zhenyolka (for Linux and routers)
- [DPI Tunnel for
  Android](https://github.com/nomoresat/DPITunnel-android) by
  zhenyolka (for Android)
- [PowerTunnel](https://github.com/krlvm/PowerTunnel) by krlvm (for
  Windows, MacOS and Linux)
- [PowerTunnel for
  Android](https://github.com/krlvm/PowerTunnel-Android) by krlvm (for
  Android)
- [GhosTCP](https://github.com/macronut/ghostcp) by macronut (for
  Windows)
- [ByeDPI](https://github.com/hufrea/byedpi) for Linux/Windows
- [ByeDPIAndroid](https://github.com/dovecoteescapee/ByeDPIAndroid/)
  for Android (no root)
- [ByeByeDPI](https://github.com/romanvht/ByeByeDPI) for Android
- [youtubeUnblock](https://github.com/Waujito/youtubeUnblock/) by
  Waujito (for OpenWRT/Entware routers and Linux)
- [NoDPI](https://github.com/GVCoder09/NoDPI/) for Windows and Linux

#### Useful links:
- <https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf>
- <https://github.com/bol-van/zapret/blob/master/docs/readme.en.md>
- <https://deepwiki.com/bol-van/zapret/3-dpi-circumvention-techniques>
- <https://www.ias.edu/security/deep-packet-inspection-dead-and-heres-why>
- <https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/>
</details>

## Notice
Copyright 2025-2026 Dilluti0n.

Licensed under GPL-3.0-or-later.

![License-logo](./res/gplv3-with-text-136x68.png)
