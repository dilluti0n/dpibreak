## NAME

dpibreak - simple and efficient DPI circumvention tool in Rust.

## SYNOPSIS

**dpibreak** \[*OPTIONS*\]

## DESCRIPTION

**DPIBreak** is a simple and efficient tool for circumventing Deep
Packet Inspection (DPI), especially on HTTPS connections. It fragments
the TCP packet carrying the TLS ClientHello so that certain DPI devices
cannot extract the Server Name Indication (SNI) field and identify the
destination site.

It only applies to the first outbound segment that carries the TLS
ClientHello; Other packets are not queued to userspace and pass through
the kernel normally, unmodified. UDP/QUIC (HTTP/3) is not affected.

This program is cross-platform and runs the same way on both Linux and
Windows. No manual firewall configuration is required: starting the
program enables it system-wide; stopping it disables it.

## REQUIREMENTS

**Linux**  
Root privileges (or capabilities **CAP_NET_ADMIN** and **CAP_NET_RAW**)
are required to install rules and attach to NFQUEUE. The **nft** command
should be available. If it is not, **dpibreak** try to fallback
**iptables** and **ip6tables** Kernel support for **nfnetlink_queue**
and **xt_u32** (when **nft** is not available) is required. (these
modules are typically auto-loaded)

<!-- -->

**Windows**  
Administrator privilege is required to open the WinDivert driver; the
program opens the driver automatically at startup.

## OPTIONS

**--delay-ms *u64***  
Delay in milliseconds to apply between fragmented pieces of the
ClientHello. Typical values are 0–1000; larger values may increase
handshake latency. (default: 0)

**--queue-num *u16***  

NFQUEUE number to attach to. The same queue number is used for IPv4 and
IPv6. (default: 1)

**--loglevel *debug\|info\|warning\|error***  
Set the logging level (default: **warning**). Aliases: **warn** -\>
**warning**, **err** -\> **error**.

**--no-splash**  
Disable splash messages at startup.

**-h , --help**  
Show usage information and exit.

## EXAMPLES

Run with default options:

> **dpibreak**

Run with a 10 ms delay and verbose logging:

> **dpibreak --delay-ms 10 --loglevel debug**

Use a custom NFQUEUE on Linux:

> **dpibreak --queue-num 3**

## BUGS

Although the program works reliably in the author's region and ISP,
different regions, ISPs, or organizations may deploy different DPI
equipment. In such cases, there is a chance that **dpibreak** does not
function as expected. If you encounter such issue, please report
symptoms and, if possible, packet capture logs (e.g., collected with
Wireshark) or hints such as cases where alternative tools like
GoodByeDPI succeed with specific settings to the bug tracker listed
below.

When sharing packet capture logs, please make sure they do not contain
sensitive personal information (e.g., passwords or session cookies). It
is usually enough to capture only the initial handshake packets showing
the issue, rather than full sessions.

Any other problems not covered above are also appreciated.

Report bugs at \<https://github.com/dilluti0n/dpibreak/issues\>.

## SECURITY AND PRIVACY

The program does not store or transmit your traffic. Fragmentation is
performed locally on the host; no external proxy or relay is used.

## EXIT STATUS

Normally, **dpibreak** runs continuously until interrupted by the user
(e.g. with Ctrl+c) or the system. In such cases it exits with status 0.
Non-zero exit codes are returned if the program fails to start (for
example, due to insufficient privileges, missing iptables/WinDivert, or
invalid options).

## SEE ALSO

**nft**(8), **iptables**(8), **ip6tables**(8), **tcpdump**(1),
**wireshark**(1)

GoodByeDPI \<https://github.com/ValdikSS/GoodbyeDPI\>

## AUTHOR

Written by Dilluti0n \<hskimse1@gmail.com\>.
