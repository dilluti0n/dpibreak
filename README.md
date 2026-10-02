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
- Why DPIBreak?: <https://dilluti0n.com/dpibreak/why.html>

## Usage

```bash
dpibreak
dpibreak -d               # run as daemon
dpibreak -o 0,5           # if a site breaks that worked before
dpibreak -a               # if bypass does not work
dpibreak -o 0,5 -a        # combined

dpibreak --help
```

See
[dpibreak(1)](https://git.dilluti0n.com/dpibreak.git/about/dpibreak.1)
for full manual. If site still blocked, don't hesitate to [open an
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

Run `sc stop windivert` in administrator `cmd.exe` and rerun the
upgrade command.

### A site that worked before stops working with dpibreak ([#23](https://github.com/dilluti0n/dpibreak/issues/23))

Try `-o 0,5`.

### `-a, --fake-autottl` make things worse ([#20](https://github.com/dilluti0n/dpibreak/issues/20))

Try `--fake-ttl 6`, if that fails, see the workaround on issue.

### Traffic forwarded through a WireGuard/VPN server is not handled ([#31](https://github.com/dilluti0n/dpibreak/issues/31))

Run DPIBreak with the script in
[#31](https://github.com/dilluti0n/dpibreak/issues/31).

## Built upon

- the kernel's NFQUEUE target, via
  [nfq-updated](https://crates.io/crates/nfq-updated) (all credit goes
  to [nfq-rs](https://github.com/nbdd0121/nfq-rs))
- the Windows Filtering Platform, via
  [WinDivert](https://reqrypt.org/windivert.html)
- [etherparse](https://github.com/JulianSchmid/etherparse) for packet
  parsing and construction
- and many crates - see [Cargo.lock](./Cargo.lock) for credit

## See also
- [SpoofDPI](https://github.com/xvzc/SpoofDPI) by @xvzc
- <https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf>
- <https://www.ias.edu/security/deep-packet-inspection-dead-and-heres-why>

---
Copyright 2025-2026 Dilluti0n.

This program is free software, released under the GNU General Public
License, version 3 or later.
