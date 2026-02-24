[![GitHub Release](https://img.shields.io/github/v/release/Dilluti0n/DPIBreak)](https://github.com/Dilluti0n/DPIBreak/releases)
[![Gentoo GURU](https://img.shields.io/badge/Gentoo-GURU-purple.svg)](https://gitweb.gentoo.org/repo/proj/guru.git/tree/net-misc/dpibreak)
[![Crates.io](https://img.shields.io/crates/v/dpibreak)](https://crates.io/crates/dpibreak)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./COPYING)

# <img src="./res/icon_origin.png" alt="" width=32> DPIBreak

> Curious why I made this? See [Afterword](#Afterword).

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
in a standards-compliant way on Linux and Windows, so that DPI
equipment can no longer detect the destination domain while the actual
server still can.

- Unlike VPNs, it requires no external server. All processing happens
  entirely on your machine.
- It takes effect immediately on all HTTPS connections when launched,
  and reverts automatically when stopped.
- Only the small packets needed for this manipulation are touched. All
  other data packets (e.g., video streaming) pass through without
  **any** processing, resulting in very low overhead, which is itself
  negligible compared to typical internet latency.

> Oh, and if it matters to you: it is built in Rust. Fast and
> lightweight as a native binary, without the memory vulnerabilities
> that are important to privileged network tools.

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
Choose your platform:

### Windows
- Download [latest
  release](https://github.com/dilluti0n/dpibreak/releases/latest) and
  unzip it.
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
Download latest release tarball from
[here](https://github.com/dilluti0n/dpibreak/releases/latest).

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

## See more
<details>
<summary><strong>Alternative tools</strong></summary>
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
</details>

<details>
<summary><strong>Useful links</strong></summary>
- <https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf>
- <https://github.com/bol-van/zapret/blob/master/docs/readme.en.md>
- <https://deepwiki.com/bol-van/zapret/3-dpi-circumvention-techniques>
- <https://www.ias.edu/security/deep-packet-inspection-dead-and-heres-why>
- <https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/>
</details>

## Afterword
Why did I build DPIBreak? There are plenty of alternative tools out
there, anyway.

At first, I was looking for a Linux equivalent of
[GoodByeDPI](https://github.com/ValdikSS/GoodbyeDPI). Something that
activates globally on launch and exits cleanly, with no other setup
needed.

I found [zapret](https://github.com/bol-van/zapret) first, but the
configuration was too involved for what I needed at the time. It's
powerful and comprehensive, supports not only HTTPS but also UDP
packets for discord/wireguard and more. But that breadth might be
overkill if all you need is HTTPS bypass.

[SpoofDPI](https://github.com/xvzc/spoofdpi) was easier to get
running, but there was a problem: it operates as a local proxy,
meaning you need to connect each application to it explicitly. An
alias helped avoid retyping the proxy address every time, but the real
issue was downloading large files with CLI tools like curl or
yt-dlp. Every invocation needed a proxy flag, and every traffic — not
just the handshake, but every byte of the actual download — routes
through the local SOCKS proxy in userspace before re-entering the
kernel stack.

> This should not be taken as a criticism of SpoofDPI's
> approach. Operating as a proxy makes the tool easily portable to
> Android and macOS (which SpoofDPI primarily targets), and unlike the
> low-level packet manipulation used by DPIBreak and zapret, it's
> considerably safer to run.

So I built DPIBreak to bring GoodByeDPI experience to Linux: launch
it, works globally, no per-app configuration, no proxy flags,
and without having to think twice about overhead on large
downloads. Only handshake packets are intercepted via
`netfilter_queue`, and everything else passes through the kernel
untouched.

The initial implementation reused SpoofDPI's bypass method, which
was proven to work for my setup. It held up well, until I hit a
stricter DPI environment on my university network. That's when I added
`fake` support for stricter DPI environments (referencing zapret's
approach), and built [HopTab](./src/pkt/hoptab.rs) — a 128-entry
IP-hop cache — to make `--fake-autottl` viable without measurable
overhead.

I use this as my daily driver. Hopefully it's useful to you too.

## Notice
Copyright 2025-2026 Dilluti0n.

This program is free software, released under the GNU General Public
License, version 3 or later.
