# DPIBreak
![DPIBreak_logo](./res/logo.png)

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

## Quickstart
### Windows
1. Download and unzip the release from
   <https://github.com/dilluti0n/dpibreak/releases/latest>.
2. Double-click `dpibreak.exe`.

### Linux
1. Download release tarball from
   <https://github.com/dilluti0n/dpibreak/releases/latest>.
2. Extract it.
```bash
tar -xf DPIBreak-X.Y.Z-x86_64-unknown-linux-musl.tar.gz
cd DPIBreak-X.Y.Z-x86_64-unknown-linux-musl
sudo make install
```
3. Run:
```bash
sudo dpibreak
man 1 dpibreak # manual
```
4. To uninstall:
```bash
sudo make uninstall
```

### Linux with Cargo (crates.io)
Install Rust toolchain from
<https://www.rust-lang.org/learn/get-started>.

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
sudo ln -s ~/.cargo/bin/dpibreak /usr/bin/dpibreak
sudo dpibreak
```

## How to use
Simply running the program should work without any issues. It requires
administrator privileges to run:

- On Linux, you must run it with root privileges (e.g., `sudo
  dpibreak`).
- On Windows, double-clicking `dpibreak.exe` will automatically prompt
  for administrator permission. After it starts, a console window will
  open. You must keep this window open while using the program.

To stop using the program, press Ctrl+C or close the window;
it will exit without leaving any global state behind. For more
detailed information, please refer to [dpibreak(1)](./dpibreak.1.md).

## Reporting issues
Although the program works reliably in the author's region and ISP,
different regions, ISPs, or organizations may deploy different DPI
equipment. In such cases, there is a chance that `dpibreak` does not
function as expected.

If you encounter such issue, please report symptoms and, if possible,
packet capture logs (e.g., collected with Wireshark) or hints such as
cases where alternative tools like GoodByeDPI succeed with specific
settings to the [project issue
tab](https://github.com/dilluti0n/dpibreak/issues). This will helps
improve future versions.

When sharing packet capture logs, please make sure they do not contain
sensitive personal information (e.g., passwords or session cookies).
It is usually enough to capture only the initial handshake packets
showing the issue, rather than full sessions.

Any other problems not covered above are also appreciated on the issue
tab.

## To build
1. Install Rust toolchain from
   <https://www.rust-lang.org/learn/get-started>.
2. Clone this repo.
```bash
git clone https://github.com/dilluti0n/dpibreak.git
```
3. (Windows) Download
[WinDivert-2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)
and unzip it to the project root. Make sure `WinDivert.dll` and
`WinDivert64.sys` are located in `.../dpibreak/WinDivert-2.2.2-A/x64`.
4. Build it.
```bash
cargo build --release
```
5. The binary will be available at `./target/release/dpibreak(.exe)`.
6. (Windows) Make sure `WinDivert.dll` and `WinDivert64.sys` are in
   the same folder as `dpibreak.exe`. (Copy them from
   `WinDivert-2.2.2-A/x64`)

## Disclaimer
This tool was created for technical research and educational purposes.
Please make sure your usage complies with the laws of your country.
The authors are not responsible for any misuse.

## Built with
DPIBreak is built upon these powerful packet handling frameworks:

- [Netfilter-queue](https://netfilter.org/) - The user-space packet
  queuing system for Linux.
- [WinDivert](https://reqrypt.org/windivert.html) - A user-mode packet
  interception library for Windows.

## Thanks
This project's creation was inspired by these great free softwares:

- [GoodByeDPI](https://github.com/ValdikSS/GoodbyeDPI) by ValdikSS:
  For its design which shaped the project's UX.
- [SpoofDPI](https://github.com/xvzc/SpoofDPI) by xzvc: For
  introducing the circumvention idea.

## See more

Alternative tools:
- [zapret](https://github.com/bol-van/zapret) by bol-van (for MacOS,
  Linux and Windows)
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
- [GhosTCP](https://github.com/macronut/ghostcp) by @macronut (for
  Windows)
- [ByeDPI](https://github.com/hufrea/byedpi) for Linux/Windows
- [ByeDPIAndroid](https://github.com/dovecoteescapee/ByeDPIAndroid/)
  for Android (no root)
- [ByeByeDPI](https://github.com/romanvht/ByeByeDPI) for Android
- [youtubeUnblock](https://github.com/Waujito/youtubeUnblock/) by
  @Waujito (for OpenWRT/Entware routers and Linux)
- [NoDPI](https://github.com/GVCoder09/NoDPI/) for Windows and Linux

Useful links:
- <https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf>
- <https://github.com/bol-van/zapret/blob/master/docs/readme.en.md>
- <https://deepwiki.com/bol-van/zapret/3-dpi-circumvention-techniques>
- <https://www.ias.edu/security/deep-packet-inspection-dead-and-heres-why>
- <https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/>

## Notice
Copyright © 2025 Dilluti0n.

Licensed under GPL-3.0-or-later.

![License-logo](./res/gplv3-with-text-136x68.png)
