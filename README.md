[![GitHub Release](https://img.shields.io/github/v/release/Dilluti0n/DPIBreak)](https://github.com/Dilluti0n/DPIBreak/releases)
[![winget](https://img.shields.io/badge/winget-DPIBreak-blue?logo=windows)](https://github.com/microsoft/winget-pkgs/tree/master/manifests/d/Dilluti0n/DPIBreak)
[![AUR version](https://img.shields.io/aur/version/dpibreak)](https://aur.archlinux.org/packages/dpibreak)
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
- It supports both Linux and Windows with the same circumvention
  logic.

> Oh, and if it matters to you: it is built in Rust. Fast and
> lightweight as a native binary, without the memory vulnerabilities
> that are important to privileged network tools.

**TL;DR:** this tool lets you access ISP-blocked sites at virtually
the same speed as an unrestricted connection, with minimal setup.

## Quickstart
### Windows
Open PowerShell and run:
```powershell
winget install dpibreak
```
(Full package ID: `Dilluti0n.DPIBreak`)

Run `dpibreak` from PowerShell, cmd.exe, or via `Win+R`, `dpibreak -h`
for options list.

> [!TIP]
> If the upgrade fails, run the following command in administrator
> cmd: `sc stop windivert` and rerun the upgrade command. (See
> [#21](https://github.com/dilluti0n/dpibreak/issues/21))

If you prefer portable download:
- Download [latest
  release](https://github.com/dilluti0n/dpibreak/releases/latest) and
  unzip it.
- Double-click `dpibreak.exe` (or `start_fake.bat` to use
  [fake](#fake)).
- Run `service_install.bat` as administrator to automatically run per
  boot (Run `service_remove.bat` to remove).
- See `WINDOWS_GUIDE.txt` for more information (includes a Korean
  translation).

### Linux
Run this command:
```bash
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh
```

This installs the [official
release](https://github.com/dilluti0n/dpibreak/releases/latest) to
`/usr/local/bin/dpibreak` and `/usr/local/share/man/man1/dpibreak.1`.
[View
source](https://github.com/dilluti0n/dpibreak/blob/master/install.sh).
See [Installation](#installation) for tarball, AUR, Gentoo, and
crates.io options.

Usage:
```bash
sudo dpibreak
sudo dpibreak -d                  # run as daemon
sudo pkill dpibreak               # to stop daemon
sudo dpibreak -o 0,5 -d           # typical usage

dpibreak --help
man dpibreak                      # manual
```

## Features
For more information, please refer to
[dpibreak(1)](./dpibreak.1.md). (Though you probably won't need it. :)

### Segmentation (default)
Split the TLS ClientHello into smaller pieces so that DPI equipment
cannot read the SNI from a single packet. The server reassembles them
normally.

It can be configured via `-o, --segment-order`. (`-o 0,1` is default)
See [#14](https://github.com/dilluti0n/dpibreak/issues/14) for
examples that help illustrate the rules.

> [!NOTE]
> Some servers may return a connection error with the default `0,1`
> split (first byte sent seperately). If this happens, try `-o
> 0,5`. See [#23](https://github.com/dilluti0n/dpibreak/issues/23) for
> details.

### Fake
Enable fake ClientHello packet (with SNI `www.microsoft.com`)
injection before sending each packet fragmented. For typical usage,
use `-a, --fake-autottl`.

I live in South Korea, and Korean ISP-level DPI was bypassable without
this feature. However, the internal DPI at my university was not. With
this feature enabled, the university's DPI was also successfully
bypassed, so I expect it to be helpful in many other use cases as
well.

> [!NOTE]
> `--fake-autottl` may not work correctly for servers with
> non-standard default TTL values. See
> [#20](https://github.com/dilluti0n/dpibreak/issues/20) for details
> and workarounds.

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

### Arch Linux
Available in the AUR as
[`dpibreak`](https://aur.archlinux.org/packages/dpibreak) (stable) and
[`dpibreak-git`](https://aur.archlinux.org/packages/dpibreak-git) (latest commit).

#### Using an AUR helper (e.g., [yay](https://github.com/Jguer/yay))
If `yay` is not installed, set it up first:
```bash
sudo pacman -S --needed base-devel git
git clone https://aur.archlinux.org/yay.git
cd yay && makepkg -si
```
Then install `dpibreak`:
```bash
yay -S dpibreak
```
#### Manual
```bash
git clone https://aur.archlinux.org/dpibreak.git && cd dpibreak && makepkg -si
```

### Gentoo Linux
Available in the [GURU](https://wiki.gentoo.org/wiki/Project:GURU)
repository.

```bash
sudo eselect repository enable guru
sudo emaint sync -r guru
echo 'net-misc/dpibreak ~amd64' | sudo tee -a /etc/portage/package.accept_keywords/dpibreak
sudo emerge --ask net-misc/dpibreak
```

### crates.io
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

## Afterword
Why did I build DPIBreak? There are plenty of alternative tools out
there, anyway.

At first, I was looking for a Linux equivalent of
[GoodByeDPI](https://github.com/ValdikSS/GoodbyeDPI). Something that
activates globally on launch and exits cleanly, with no other setup
needed.

I found [zapret](https://github.com/bol-van/zapret) first. It's
powerful and comprehensive, supports not only HTTPS but also UDP
packets for discord/wireguard and more. But that breadth might be
overkill if all you need is HTTPS bypass. At the time, I just wanted
quick access to blocked sites, and a Windows desktop was the easier
way out. So the whole process of downloading, setting it up, and
learning how to use it felt like too much hassle. In the end, I gave
up on it.

[SpoofDPI](https://github.com/xvzc/spoofdpi) was easier to understand,
as it operates as a local proxy. Operating as a proxy makes the tool
easily portable to Android and macOS (which SpoofDPI primarily
targets). Also, unlike the low-level packet manipulation used by
DPIBreak and zapret, it's considerably safer to run.

However, it means you need to connect each application to the local
proxy explicitly. Though aliasing each tool - digging through docs for
Chromium, curl, yt-dlp and others to set up proxy flags - solved the
repetitive typing, some unnecessary overhead still bothered me. Every
byte of traffic, not just the handshake but also the actual downloaded
data, routes through the local proxy in userspace before re-entering
the kernel stack. And that's why I did not consider adding TPROXY
rules on my firewall to route every 443 packet to SpoofDPI over
aliasing each application.

So I built DPIBreak to bring GoodByeDPI experience to Linux: launch
it, works globally, no per-app configuration, no proxy flags, and
without having to think twice about overhead on large downloads. Only
handshake packets are intercepted via `netfilter_queue`, and
everything else passes through the kernel untouched.

The initial implementation adopted the bypass approach [once described
in SpoofDPI's
README](https://github.com/xvzc/SpoofDPI/tree/65d7aae2766a0d64747dd3b01430698005f566bd?tab=readme-ov-file#how-it-works),
which was proven to work for my ISP's DPI. It held up well, until I
hit a stricter DPI environment on my university network. That's when I
added [fake](#fake) support (referencing zapret's approach), and built
[HopTab](./src/pkt/hoptab.rs) - a 128-entry IP-hop cache - to make
`--fake-autottl` viable without measurable overhead.

I use this as my daily driver. Hopefully it's useful to you too.

## See also
- <https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf>
- <https://github.com/bol-van/zapret/blob/master/docs/readme.en.md>
- <https://www.ias.edu/security/deep-packet-inspection-dead-and-heres-why>

---
Copyright 2025-2026 Dilluti0n.

This program is free software, released under the GNU General Public
License, version 3 or later.
