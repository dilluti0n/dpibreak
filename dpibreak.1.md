## NAME

dpibreak - fast and easy-to-use DPI circumvention tool in Rust.

## SYNOPSIS

**dpibreak** \[*OPTIONS*\]

## DESCRIPTION

**DPIBreak** is a tool for circumventing Deep Packet Inspection (DPI) on
HTTPS connections. It is only applied locally and no other external
connection is needed.

Mainly it fragments the TCP packet carrying the TLS ClientHello so that
certain DPI devices cannot extract the Server Name Indication (SNI)
field and identify the destination site. Other method can also be used
along with it, and it is described in the **OPTIONS** section.

DPIBreak registers firewall rules (nftables/WinDivert) to handle inbound
and outbound packets. The rules are automatically added on startup and
removed on exit, making it effective system-wide without manual
intervention.

Firewall rule cleanup relies on SIGTERM/SIGINT. If the process is killed
with SIGKILL, cleanup will not occur. However, the registered nfqueue
rules simply pass packets through when no process is consuming the
queue, so this is not a concern in practice. In that case, restarting
and gracefully stopping DPIBreak will clean up the leftover rules.

This only applies to HTTP/2 (Commonly known as HTTPS). UDP/QUIC (HTTP/3)
is not affected.

## REQUIREMENTS

**Linux**  
Root privilege required to install rules and attach to NFQUEUE. The
**nft** command should be available. If it is not, **DPIBreak** try to
fallback **iptables** and **ip6tables** along with **xt_u32** kernel
module (which is typically auto-loaded). Kernel support for
**nfnetlink_queue** is required.

<!-- -->

**Windows**  
Administrator privilege is required to open the WinDivert driver.
WinDivert64.sys and WinDivert.dll should be in same directory with
dpibreak.exe

## OPTIONS

**-D**, **--daemon**  
Run as a background daemon. Logs are written to
**/var/log/dpibreak.log.** If a daemon is already running, it will fail
with "unable to lock pid file". To stop it, run **kill \`cat
/run/dpibreak.pid\`** as root.

On Windows, this option enters the service controller entry point.
Example: **sc create dpibreak binPath= "dpibreak.exe -D" start= auto; sc
start dpibreak**

**--delay-ms *\<u64\>***  
Delay in milliseconds to apply between fragmented pieces of the
ClientHello. Typical values are 0–1000; larger values may increase
handshake latency. (Default: 0)

**--fake**  
Enable **fake** ClientHello packet injection before sending each packet
fragmented. TCP/IP header fields follow the original packet unless you
override it using the **--fake-\*** options described below. Packets are
transmitted in an interleaved order: (fake 1), (orig 1), (fake 2), (orig
2), ...

**--fake-ttl *\<u8\>***  
Override ttl (IPv4) / hop_limit (IPv6) of **fake** packet. Implicitly
enables **--fake**. (Default: 8)

**--fake-autottl**  
Automatically infer the hop count (TTL/Hop Limit) to the destination by
analyzing the SYN/ACK packet. It assumes the server's initial TTL is
either 64, 128, or 255. The inferred value is used for **fake** packet
transmission to ensure they reach the censor but not the destination. By
default, it uses a delta of 1. If the hop count cannot be determined, it
falls back to the value specified by **--fake-ttl**. Implicitly enables
**--fake**.

**--fake-badsum**  
Corrupts the TCP checksum of **fake** packets. When enabled, **fake**
packets cannot pass through most routers and will not behave as
expected. It can be useful if your router/firewall provides an option to
disable TCP checksum verification. Implicitly enables **--fake**.

**--queue-num *\<u16\>***  

NFQUEUE number to attach to. The same queue number is used for IPv4 and
IPv6. (Default: 1)

**--nft-command *\<string\>***  

Custom nftables command to be executed. (Default: nft)

**--log-level *\<debug\|info\|warning\|error\>***  
Set the logging level (Default: warning). Aliases: **warn** -\>
**warning**, **err** -\> **error**.

**--no-splash**  
Disable splash messages at startup.

**-h**, **--help**  
Show usage information and exit.

## EXIT STATUS

**0**  
Successfully terminated.

**non-zero**  
The program encountered an error during initialization or runtime,
resulting in an abnormal exit.

## EXAMPLES

Run with default options:

> **dpibreak**

Run as daemon with fake ClientHello injection:

> **dpibreak -D --fake-autottl**

Run with a 10 ms delay between fragmanted packets and verbose logging:

> **dpibreak --delay-ms 10 --log-level debug**

Use a custom NFQUEUE on Linux:

> **dpibreak --queue-num 3**

## FILES

*/run/dpibreak.pid*  
Whether running as a daemon or not, DPIBreak will fail through this file
if another instance is already running on the system.

*/var/log/dpibreak.log*  
Only for daemon. log goes here.

## BUGS

There are two types of bugs:

> a\. DPIBreak does not work as described in the manual.  
> b. It works as described but fails to bypass the DPI.

Reporting both cases to the bug tracker helps improve the program. For
case (b), it would be helpful if you could include information such as
your region and ISP.

Any other minor improvements or suggestions are also welcome.

You can view the known bugs list and submit reports at:  
*https://github.com/dilluti0n/dpibreak/issues*

## SEE ALSO

**nft**(8), **iptables**(8), **ip6tables**(8)

## AUTHOR

Written by Dilluti0n \<hskimse1@gmail.com\>.
