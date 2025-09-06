# DPIBreak
![DPIBreak_logo](./res/logo.png)

Simple and efficient tool for circumventing Deep
Packet Inspection (DPI), especially on HTTPS connections. It fragments
the TCP packet carrying the TLS ClientHello so that certain DPI devices
cannot extract the Server Name Indication (SNI) field and identify the
destination site.

It only applies to the first outbound segment that carries the TLS
ClientHello; Other traffic is not queued to userspace and passes
through the kernel normally, unmodified. So, it is generally fast and
**does not affect** core performance (e.g., video streaming speed)
users may be concerned about.

## How to use
In general, simply run the program and it will work without any
issues. The program requires administrator privileges to run:

- On Linux, you must run it with root privileges (e.g., `sudo
  ./dpibreak`).
- On Windows, it will automatically prompt for administrator
  permission when you run it.

To stop using the program, press Ctrl+C or close the window;
it will exit without leaving any global state behind. For more
detailed information, please refer to [dpibreak(1)](./dpibreak.1.md).

## Reporting issues
Although the program works reliably in the developer's region and ISP,
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
1. Install Rust toolchain from <https://www.rust-lang.org/learn/get-started>.
2. Clone this repo.
```bash
git clone https://github.com/dilluti0n/dpibreak.git
```
3. (Windows) Install
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
This project's creation was inspired by these great open-source projects:

- [GoodByeDPI](https://github.com/ValdikSS/GoodbyeDPI) by ValdikSS:
  For its user-friendly design which shaped the project's UX.
- [SpoofDPI](https://github.com/xvzc/SpoofDPI) by xzvc: For
  introducing the circumvention idea that guided this project.

## Notice
Copyright © 2025 Dilluti0n. Licensed under GPL-3.0-or-later.

![License-logo](./res/gplv3-with-text-136x68.png)
