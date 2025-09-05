// Copyright 2025 Dillution <hskimse1@gmail.com>.
//
// This file is part of DPIBreak.
//
// DPIBreak is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// DPIBreak is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License
// along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

use anyhow::{Result, anyhow, Context};
use std::sync::{
    atomic::{Ordering, AtomicBool},
    OnceLock,
};

mod platform;
mod pkt;
mod tls;
mod log;

use log::LogLevel;

const PROJECT_NAME: &str = "DPIBreak";
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const PKG_HOMEPAGE: &str = env!("CARGO_PKG_HOMEPAGE");

static RUNNING: AtomicBool = AtomicBool::new(true);

static DELAY_MS: OnceLock<u64> = OnceLock::new();
static NO_SPLASH: OnceLock<bool> = OnceLock::new();

fn delay_ms() -> u64 {
    *DELAY_MS.get().expect("DELAY_MS not initialized")
}

fn split_packet(pkt: &pkt::PktView, start: u32, end: Option<u32>,
                out_buf: &mut Vec<u8>) -> Result<()> {
    use etherparse::*;

    let ip = &pkt.ip;
    let tcp = &pkt.tcp;
    let payload = tcp.payload();

    let end = end.unwrap_or(payload.len().try_into()?);

    if start > end || payload.len() < end as usize {
        return Err(anyhow!("invalid index"));
    }

    let opts = tcp.options();
    let mut tcp_hdr = tcp.to_header();
    tcp_hdr.sequence_number += start;

    // TODO: refactor this to reuse IP header with no copy
    let builder = match ip {
            IpSlice::Ipv4(hdr) =>
                PacketBuilder::ip(IpHeaders::Ipv4(
                    hdr.header().to_header(),
                    hdr.extensions().to_header()
                )),

            IpSlice::Ipv6(hdr) =>
                PacketBuilder::ip(IpHeaders::Ipv6(
                    hdr.header().to_header(),
                    Default::default()
                ))
    }.tcp_header(tcp_hdr).options_raw(opts)?;

    let payload = &payload[start as usize..end as usize];

    out_buf.clear();
    builder.write(out_buf, payload)?;

    Ok(())
}

/// Return Ok(true) if packet is handled
fn handle_packet(pkt: &[u8]) -> Result<bool> {
    use platform::send_to_raw;

    #[cfg(target_os = "linux")]
    let is_filtered = platform::IS_U32_SUPPORTED.load(Ordering::Relaxed);

    #[cfg(windows)]
    let is_filtered = false;

    let view = pkt::PktView::from_raw(pkt)?;

    if !is_filtered && !tls::is_client_hello(view.tcp.payload()) {
        return Ok(false);
    }

    // TODO: if clienthello packet has been (unlikely) fragmented,
    // we should find the second part and drop, reassemble it here.

    let mut buf = Vec::<u8>::with_capacity(2048);

    split_packet(&view, 0, Some(1), &mut buf)?;
    send_to_raw(&buf)?;

    std::thread::sleep(std::time::Duration::from_millis(delay_ms()));

    split_packet(&view, 1, None, &mut buf)?;
    send_to_raw(&buf)?;

    #[cfg(debug_assertions)]
    log_println!(LogLevel::Debug, "packet is handled, len={}", pkt.len());

    Ok(true)
}

#[macro_export]
macro_rules! handle_packet {
    ($bytes:expr, handled => $on_handled:expr, rejected => $on_rejected:expr $(,)?) => {{
        match handle_packet($bytes) {
            Ok(true) => { $on_handled }
            Ok(false) => { $on_rejected }
            Err(e) => {
                log_println!(LogLevel::Warning, "handle_packet: {e}");
                $on_rejected
            }
        }
    }};
}

fn take_value<T, I>(args: &mut I, arg_name: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    I: Iterator<Item = String>,
{
    let raw = args
        .next()
        .ok_or_else(|| anyhow!("argument: missing value after {}", arg_name))?;
    raw.parse::<T>()
        .with_context(|| format!("argument {}: invalid value '{}'", arg_name, raw))
}

fn usage() {
    println!(
        r#"Usage: dpibreak [OPTIONS]

Options:
  --delay-ms  <u64>                       (default: 0)
  --queue-num <u16>                       (linux only, default: 1)
  --loglevel  <debug|info|warning|error>  (default: warning)
  --no-splash                             Do not print splash messages
  -h, --help                              Show this help"#
    );
}

fn splash() {
    println!(
        r#"{PROJECT_NAME} v{PKG_VERSION} - {PKG_DESCRIPTION}
{PKG_HOMEPAGE}

Press Ctrl+c (or close this window) to stop."#
    );
}

fn parse_args_1() -> Result<()> {
    let mut delay_ms: u64 = 0;
    let mut log_level: Option<log::LogLevel> = None;
    let mut no_splash: bool = false;

    #[cfg(target_os = "linux")]
    let mut queue_num: u16 = 1;

    let mut args = std::env::args().skip(1); // program name

    while let Some(arg) = args.next() {
        let argv = arg.as_str();

        match argv {
            "-h" | "--help" => { usage(); std::process::exit(0); }
            "--delay-ms" => { delay_ms = take_value(&mut args, argv)?; }
            "--loglevel" => { log_level = Some(take_value(&mut args, argv)?); }
            "--no-splash" => { no_splash = true; }

            #[cfg(target_os = "linux")]
            "--queue-num" => { queue_num = take_value(&mut args, argv)?; }

            _ => { return Err(anyhow!("argument: unknown: {}", arg)); }
        }
    }

    DELAY_MS.set(delay_ms).map_err(|_| anyhow!("DELAY_MS already initialized"))?;
    NO_SPLASH.set(no_splash).map_err(|_| anyhow!("NO_SPLASH already initialized"))?;

    if let Some(lvl) = log_level {
        log::set_log_level(lvl).map_err(|_| anyhow!("LOG_LEVEL already initialized"))?;
    }

    #[cfg(target_os = "linux")]
    platform::QUEUE_NUM.set(queue_num).map_err(|_| anyhow!("QUEUE_NUM already initialized"))?;

    Ok(())
}

fn parse_args() {
    if let Err(e) = parse_args_1() {
        log_println!(LogLevel::Error, "{e}");
        usage();
        std::process::exit(1);
    }
}

fn trap_exit() -> Result<()> {
    ctrlc::set_handler(|| {
        RUNNING.store(false, Ordering::SeqCst);
    }).context("handler: ")?;

    Ok(())
}

/// Drop with calling platform::cleanup()
struct EnsureCleanup;

impl Drop for EnsureCleanup {
    fn drop(&mut self) {
        if let Err(e) = platform::cleanup() {
            log_println!(LogLevel::Error, "cleanup failed: {e}");
        }
    }
}

fn main_0() -> Result<()> {
    trap_exit()?;
    parse_args();

    if !NO_SPLASH.get().expect("NO_SPLASH not initialized.") {
        splash();
    }

    let _guard = EnsureCleanup;

    platform::bootstrap()?;
    platform::run()?;

    Ok(())
}

fn main() {
    let code = match main_0() {
        Ok(()) => 0,
        Err(e) => {
            log_println!(LogLevel::Error, "{e}");

            for (i, cause) in e.chain().skip(1).enumerate() {
                log_println!(LogLevel::Error, "caused by[{i}]: {cause}");
            }
            1
        }
    };

    std::process::exit(code);
}
