# DPIBreak
![DPIBreak_logo](./res/logo.png)

> [!IMPORTANT]
>
> Please make sure your usage complies with applicable laws and
> regulations. This software is provided "AS IS", WITHOUT ANY
> WARRANTY, to the extent permitted by applicable law; see `COPYING`
> (GPLv3 §§15–17).

Simple and efficient tool for circumventing [Deep Packet Inspection
(DPI)](https://en.wikipedia.org/wiki/Deep_packet_inspection) on HTTPS
connections. It fragments the
[TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
packet carrying the [TLS
ClientHello](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2)
so that certain DPI devices cannot extract the [Server Name Indication
(SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) field and
identify the destination site.

It only applies to the packets carrying TLS ClientHello; Other traffic
is not even queued to userspace and passes through the kernel
normally, unmodified. So, it is fast and **does not affect** core
performance (e.g., video streaming speed) users may be concerned
about.

## Features
### fragment (default)
Fragment the packet carrying TLS Clienthello.

### fake
Enable fake ClientHello packet injection before sending each packet
fragmented. For typical usage, use `--fake-autottl`. (See `--fake`
section on [dpibreak(1)](./dpibreak.1.md#OPTIONS) for more
information.)

## Quickstart
Download the release from
<https://github.com/dilluti0n/dpibreak/releases/latest>.
### Windows
- Double-click `dpibreak.exe` or `start_fake.bat` (To use
[fake](#fake)).
- Run `service_install.bat` with administrator privileges to
  automatically run per boot (To remove, run `service_remove.bat`).
- See `WINDOWS_GUIDE.txt` for more information.

### Linux
1. Extract and install:
```bash
tar -xf DPIBreak-X.Y.Z-x86_64-unknown-linux-musl.tar.gz
cd DPIBreak-X.Y.Z-x86_64-unknown-linux-musl
sudo make install
```
2. To run:
```bash
sudo dpibreak
sudo dpibreak -D                  # run as daemon
sudo dpibreak --fake-autottl      # enable fake packet injection
sudo dpibreak -D --fake-autottl
dpibreak --help
man 1 dpibreak                    # manual
```
3. To uninstall:
```bash
sudo make uninstall
```

### Gentoo Linux
Available in the [GURU](https://wiki.gentoo.org/wiki/Project:GURU)
repository.

```bash
sudo eselect repository enable guru
sudo emaint sync -r guru
echo 'net-misc/dpibreak ~amd64' | sudo tee /etc/portage/package.accept_keywords/dpibreak
sudo emerge --ask net-misc/dpibreak
```

### For rust developers (crates.io)
```bash
cargo install dpibreak
```

- Requirements: `libnetfilter_queue` development files (e.g.,
`libnetfilter-queue-dev` on Ubuntu/Debian).
- Note: Since cargo installs to user directory, sudo might not see
it. Use full path or link it:
```bash
# Option 1: Run with full path
sudo ~/.cargo/bin/dpibreak

# Option 2: Symlink to system bin (Recommended)
sudo ln -s ~/.cargo/bin/dpibreak /usr/local/bin/dpibreak
sudo dpibreak
```

## How to use
Simply running the program should work without any issues. It requires
administrator privileges to run:

- On Linux, you must run it with root privileges (e.g., `sudo
  dpibreak`).
- On Windows, double-clicking `dpibreak.exe` or `start_fake.bat` will
  automatically prompt for administrator permission. After it starts,
  a console window will open. You must keep this window open while
  using the program.

To stop using the program, press Ctrl+C or close the window;
it will exit without leaving any global state behind. For more
detailed information, please refer to [dpibreak(1)](./dpibreak.1.md).

## Reporting issues
See [dpibreak(1)#BUGS](./dpibreak.1.md#BUGS).
Report bugs at <https://github.com/dilluti0n/dpibreak/issues>.

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

## Notice
Copyright 2025-2026 Dilluti0n.

Licensed under GPL-3.0-or-later.

![License-logo](./res/gplv3-with-text-136x68.png)

<details>
<summary>See more (alternative tools & useful links)</summary>

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
