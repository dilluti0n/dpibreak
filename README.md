# <img src="https://dilluti0n.com/dpibreak/icon_origin.png" alt="" width=32> DPIBreak

[![GitHub Release](https://img.shields.io/github/v/release/dilluti0n/dpibreak)](https://github.com/dilluti0n/dpibreak/releases)

DPIBreak allows you to access blocked HTTPS sites by manipulating a
tiny bit of outgoing packets.

The goal is to provide system-wide circumvention with the minimal
configuration interface.

All you have to do is just start the program, and it will start
working. If the bypass doesn't work, you can try applying other flags
like `-o 0,5 -a`.

```powershell
winget install dpibreak  # Windows
```

```sh
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh   # Linux
```

Press `Win`+`R` and type `dpibreak` on Windows, `sudo dpibreak` on
Linux.  `dpibreak -h` for options.

[![Packaging status](https://repology.org/badge/vertical-allrepos/dpibreak.svg)](https://repology.org/project/dpibreak/versions)

- Other install methods: <https://dilluti0n.com/dpibreak>
- Latest release: <https://github.com/dilluti0n/dpibreak/releases/latest>
- Build from source: [HACKING.md](./HACKING.md)
- Git repository: <https://git.dilluti0n.com/dpibreak.git>
- Issue tracker: <https://github.com/dilluti0n/dpibreak/issues>

## Usage

```bash
dpibreak
dpibreak -d               # run as daemon
dpibreak -o 0,5           # if a site breaks that worked before
dpibreak -a               # if bypass does not work
dpibreak -o 0,5 -a        # combined

dpibreak --help
```

See [dpibreak(1)](./dpibreak.1.md) for full manual. If site still
blocked, don't hesitate to [open an
issue](https://github.com/dilluti0n/dpibreak/issues/new).

## Features

### Segmentation (default)

Split the TLS ClientHello into smaller pieces so that stateless DPI
equipment cannot classify.

Configured via `-o, --segment-order`. (Default: `-o 0,1`)

Out-of-order splits like `-o 5,0` are also available.

See [#14](https://github.com/dilluti0n/dpibreak/issues/14) for
examples that help illustrate the rules.

### Fake

Enable fake ClientHello packet (with SNI `www.microsoft.com`)
injection to fool stateful DPI equipment.

For typical usage, use `-a, --fake-autottl`.

I live in South Korea, and Korean ISP-level DPI was bypassable without
this feature. However, the internal DPI at my university was not. With
this feature enabled, the university's DPI was also successfully
bypassed, so I expect it to be helpful in many other use cases as
well.

## Troubleshooting

### Winget upgrade fails ([#21](https://github.com/dilluti0n/dpibreak/issues/21))

Run the following command in administrator `cmd.exe`: `sc stop
windivert` and rerun the upgrade command.

### A site that worked before stops working with dpibreak ([#23](https://github.com/dilluti0n/dpibreak/issues/23))

Try `-o 0,5`.

### `-a, --fake-autottl` make things worse ([#20](https://github.com/dilluti0n/dpibreak/issues/20))

Try `--fake-ttl 6`, if that fails, see the workaround on issue.

## Built upon

- the kernel's NFQUEUE target, via
  [nfq-updated](https://crates.io/crates/nfq-updated) (all credit goes
  to [nfq.rs](https://github.com/nbdd0121/nfq.rs))
- the Windows Filtering Platform, via
  [WinDivert](https://reqrypt.org/windivert.html)
- [etherparse](https://github.com/JulianSchmid/etherparse) for packet
  parsing and construction
- and many crates - see [Cargo.lock](./Cargo.lock) for credit

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
[HopTab](https://git.dilluti0n.com/dpibreak.git/tree/src/pkt/hoptab.rs) -
a 128-entry IP-hop cache - to make `--fake-autottl` viable without
measurable overhead.

I use this as my daily driver. Hopefully it's useful to you too.

## See also
- <https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf>
- <https://www.ias.edu/security/deep-packet-inspection-dead-and-heres-why>

---
Copyright 2025-2026 Dilluti0n.

This program is free software, released under the GNU General Public
License, version 3 or later.
