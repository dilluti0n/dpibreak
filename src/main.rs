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
const MESSAGE_AT_RUN: &str = r#"DPIBreak is now running.
Press Ctrl+C or close this window to stop.
"#;
static RUNNING: AtomicBool = AtomicBool::new(true);
static OPT_DELAY_MS: OnceLock<u64> = OnceLock::new();

static OPT_FAKE: OnceLock<bool> = OnceLock::new();

fn opt_fake() -> bool {
    *crate::OPT_FAKE.get().expect("OPT_FAKE not initialized")
}

fn delay_ms() -> u64 {
    *OPT_DELAY_MS.get().expect("OPT_DELAY_MS not initialized")
}

fn split_packet(
    view: &pkt::PktView,
    start: u32,
    end: Option<u32>,
    out_buf: &mut Vec<u8>
) -> Result<()> {
    pkt::split_packet_0(view, start, end, out_buf, None, None)
}

fn send_segment(
    view: &pkt::PktView,
    start: u32,
    end: Option<u32>,
    buf: &mut Vec<u8>
) -> Result<()> {
    use platform::send_to_raw;

    if opt_fake() {
        pkt::fake_clienthello(view, start, end, buf)?;
        send_to_raw(buf)?;
    }
    split_packet(view, start, end, buf)?;
    send_to_raw(buf)?;

    Ok(())
}

fn split_packet_1(view: &pkt::PktView, order: &[u32], buf: &mut Vec<u8>) -> Result<()> {
    let mut it = order.iter().copied();

    let Some(mut first) = it.next() else {
        return Err(anyhow!("split_packet_1: invalid order array"));
    };

    for next in it {
        send_segment(view, first, Some(next), buf)?;
        std::thread::sleep(std::time::Duration::from_millis(delay_ms()));
        first = next;
    }

    send_segment(view, first, None, buf)?;

    Ok(())
}

/// Return Ok(true) if packet is handled
fn handle_packet(pkt: &[u8], buf: &mut Vec::<u8>) -> Result<bool> {
    #[cfg(target_os = "linux")]
    let is_filtered = platform::IS_U32_SUPPORTED.load(Ordering::Relaxed);

    #[cfg(windows)]
    let is_filtered = true;

    let view = pkt::PktView::from_raw(pkt)?;

    if !is_filtered && !tls::is_client_hello(view.tcp.payload()) {
        return Ok(false);
    }

    // TODO: if clienthello packet has been (unlikely) fragmented,
    // we should find the second part and drop, reassemble it here.

    split_packet_1(&view, &[0, 1], buf)?;

    #[cfg(debug_assertions)]
    log_println!(LogLevel::Debug, "packet is handled, len={}", pkt.len());

    Ok(true)
}

#[macro_export]
macro_rules! handle_packet {
    ($bytes:expr, $buf:expr, handled => $on_handled:expr, rejected => $on_rejected:expr $(,)?) => {{
        match handle_packet($bytes, $buf) {
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
  --delay-ms    <u64>                       (default: 0)
  --queue-num   <u16>                       (linux only, default: 1)
  --nft-command <string>                    (linux only, default: nft)
  --loglevel    <debug|info|warning|error>  (default: warning)
  --no-splash                             Do not print splash messages

  --fake                                  Enable fake clienthello injection
  --fake-ttl    <u8>                      Override ttl of fake clienthello (default: 8)
  --fake-badsum                           Modifies the TCP checksum of the fake packet to an invalid value.

  -h, --help                              Show this help"#
    );
}

fn set_opt<T: std::fmt::Display>(
    name: &str,
    cell: &OnceLock<T>,
    value: T,
) -> Result<()> {
    log_println!(LogLevel::Info, "{name}: {value}");
    cell.set(value).map_err(|_| anyhow!("{name} already initialized"))
}

fn splash_banner() {
    splash!("{PROJECT_NAME} v{PKG_VERSION} - {PKG_DESCRIPTION}");
    splash!("{PKG_HOMEPAGE}");
    splash!("");
}

fn parse_args_1() -> Result<()> {
    let mut delay_ms: u64 = 0;
    let mut no_splash: bool = false;
    let mut fake: bool = false;
    let mut fake_ttl: u8 = 8;
    let mut fake_badsum: bool = false;

    #[cfg(debug_assertions)]
    let mut log_level: log::LogLevel = LogLevel::Debug;
    #[cfg(not(debug_assertions))]
    let mut log_level: log::LogLevel = LogLevel::Warning;
    #[cfg(target_os = "linux")]
    let mut queue_num: u16 = 1;
    #[cfg(target_os = "linux")]
    let mut nft_command = String::from("nft");

    let mut args = std::env::args().skip(1); // program name

    while let Some(arg) = args.next() {
        let argv = arg.as_str();

        match argv {
            "-h" | "--help" => { usage(); std::process::exit(0); }
            "--delay-ms" => { delay_ms = take_value(&mut args, argv)?; }
            "--loglevel" => { log_level = take_value(&mut args, argv)?; }
            "--no-splash" => { no_splash = true; }

            "--fake" => { fake = true; }
            "--fake-ttl" => { fake_ttl = take_value(&mut args, argv)?; }
            "--fake-badsum" => { fake_badsum = true }

            #[cfg(target_os = "linux")]
            "--queue-num" => { queue_num = take_value(&mut args, argv)?; }

            #[cfg(target_os = "linux")]
            "--nft-command" => { nft_command = take_value(&mut args, argv)?; }

            _ => { return Err(anyhow!("argument: unknown: {}", arg)); }
        }
    }

    log::set_no_splash(no_splash).map_err(|e| anyhow!("{e}"))?;
    log::set_log_level(log_level).map_err(|e| anyhow!("{e}"))?;

    set_opt("OPT_DELAY_MS", &OPT_DELAY_MS, delay_ms)?;
    set_opt("OPT_FAKE", &OPT_FAKE, fake)?;
    set_opt("OPT_FAKE_TTL", &pkt::OPT_FAKE_TTL, fake_ttl)?;
    set_opt("OPT_FAKE_BADSUM", &pkt::OPT_FAKE_BADSUM, fake_badsum)?;

    #[cfg(target_os = "linux")] set_opt("OPT_QUEUE_NUM", &platform::OPT_QUEUE_NUM, queue_num)?;
    #[cfg(target_os = "linux")] set_opt("OPT_NFT_COMMAND", &platform::OPT_NFT_COMMAND, nft_command)?;

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
    splash_banner();

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
