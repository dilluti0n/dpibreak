// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Result, anyhow, Context};
use std::sync::OnceLock;

use crate::log_println;

use crate::log;

use log::LogLevel;

static OPT_LOG_LEVEL: OnceLock<LogLevel> = OnceLock::new();
static OPT_NO_SPLASH: OnceLock<bool> = OnceLock::new();

static OPT_FAKE: OnceLock<bool> = OnceLock::new();
static OPT_FAKE_TTL: OnceLock<u8> = OnceLock::new();
static OPT_FAKE_AUTOTTL: OnceLock<bool> = OnceLock::new();
static OPT_FAKE_BADSUM: OnceLock<bool> = OnceLock::new();

static OPT_DELAY_MS: OnceLock<u64> = OnceLock::new();

#[cfg(target_os = "linux")] static OPT_QUEUE_NUM: OnceLock<u16> = OnceLock::new();
#[cfg(target_os = "linux")] static OPT_NFT_COMMAND: OnceLock<String> = OnceLock::new();

#[cfg(debug_assertions)]      const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Debug;
#[cfg(not(debug_assertions))] const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Warning;
const DEFAULT_NO_SPLASH: bool = false;

const DEFAULT_FAKE: bool = false;
const DEFAULT_FAKE_TTL: u8 = 8;
const DEFAULT_FAKE_AUTOTTL: bool = false;
const DEFAULT_FAKE_BADSUM: bool = false;

const DEFAULT_DELAY_MS: u64 = 0;

#[cfg(target_os = "linux")] const DEFAULT_QUEUE_NUM: u16 = 1;
#[cfg(target_os = "linux")] const DEFAULT_NFT_COMMAND: &str = "nft";

pub fn no_splash() -> bool {
    *OPT_NO_SPLASH.get().unwrap_or(&DEFAULT_NO_SPLASH)
}

pub fn log_level() -> LogLevel {
    *OPT_LOG_LEVEL.get().unwrap_or(&DEFAULT_LOG_LEVEL)
}

pub fn fake() -> bool {
    *OPT_FAKE.get().unwrap_or(&DEFAULT_FAKE)
}

pub fn fake_ttl() -> u8 {
    *OPT_FAKE_TTL.get().unwrap_or(&DEFAULT_FAKE_TTL)
}

pub fn fake_autottl() -> bool {
    *OPT_FAKE_AUTOTTL.get().unwrap_or(&DEFAULT_FAKE_AUTOTTL)
}

pub fn fake_badsum() -> bool {
    *OPT_FAKE_BADSUM.get().unwrap_or(&DEFAULT_FAKE_BADSUM)
}

pub fn delay_ms() -> u64 {
    *OPT_DELAY_MS.get().unwrap_or(&DEFAULT_DELAY_MS)
}

#[cfg(target_os = "linux")]
pub fn queue_num() -> u16 {
    *OPT_QUEUE_NUM.get().unwrap_or(&DEFAULT_QUEUE_NUM)
}

#[cfg(target_os = "linux")]
pub fn nft_command() -> &'static str {
    OPT_NFT_COMMAND.get().map(String::as_str).unwrap_or(DEFAULT_NFT_COMMAND)
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
        .with_context(|| format!("argument: {}: invalid value '{}'", arg_name, raw))
}

fn usage() {
    println!("Usage: dpibreak [OPTIONS]\n");
    println!("Options:");
    println!("  --delay-ms    <u64>                       (default: {DEFAULT_DELAY_MS})");
    #[cfg(target_os = "linux")]
    println!("  --queue-num   <u16>                       (default: {DEFAULT_QUEUE_NUM})");
    #[cfg(target_os = "linux")]
    println!("  --nft-command <string>                    (default: {DEFAULT_NFT_COMMAND})");

    println!("  --log-level   <debug|info|warning|error>  (default: {DEFAULT_LOG_LEVEL})");
    println!("  --no-splash                             Do not print splash messages\n");

    println!("  --fake                                  Enable fake clienthello injection");
    println!("  --fake-ttl    <u8>                      Override ttl of fake clienthello (default: {DEFAULT_FAKE_TTL})");
    println!("  --fake-autottl                          Override ttl of fake clienthello automatically");
    println!("  --fake-badsum                           Modifies the TCP checksum of the fake packet to an invalid value.");
    println!("");

    println!("  -h, --help                              Show this help");
}

fn set_opt<T: std::fmt::Display>(
    name: &str,
    cell: &OnceLock<T>,
    value: T,
) -> Result<()> {
    cell.set(value).map_err(|_| anyhow!("{name} already initialized"))?;

    let v = cell.get().expect("just set; qed");
    log_println!(LogLevel::Info, "{name}: {v}");

    Ok(())
}

fn parse_args_1() -> Result<()> {
    let mut log_level    = DEFAULT_LOG_LEVEL;
    let mut delay_ms     = DEFAULT_DELAY_MS;
    let mut no_splash    = DEFAULT_NO_SPLASH;
    let mut fake         = DEFAULT_FAKE;
    let mut fake_ttl     = DEFAULT_FAKE_TTL;
    let mut fake_autottl = DEFAULT_FAKE_AUTOTTL;
    let mut fake_badsum  = DEFAULT_FAKE_BADSUM;

    #[cfg(target_os = "linux")]
    let mut queue_num: u16 = DEFAULT_QUEUE_NUM;
    #[cfg(target_os = "linux")]
    let mut nft_command = String::from(DEFAULT_NFT_COMMAND);

    let mut args = std::env::args().skip(1); // program name

    let mut warned_loglevel_deprecated = false;

    while let Some(arg) = args.next() {
        let argv = arg.as_str();

        match argv {
            "-h" | "--help" => { usage(); std::process::exit(0); }
            "--delay-ms" => { delay_ms = take_value(&mut args, argv)?; }
            "--log-level" | "--loglevel" => {
                if argv == "--loglevel" && !warned_loglevel_deprecated {
                    // FIXME(on release): remove this on v1.0.0
                    warned_loglevel_deprecated = true;
                    eprintln!("Note: `{arg}' has been deprecated since v0.1.1. \
Use `--log-level' instead.");
                }
                log_level = take_value(&mut args, argv)?;
            }
            "--no-splash" => { no_splash = true; }

            "--fake" => { fake = true; }
            "--fake-ttl" => { fake = true; fake_ttl = take_value(&mut args, argv)?; }
            "--fake-autottl" => { fake = true; fake_autottl = true }
            "--fake-badsum" => { fake = true; fake_badsum = true }

            #[cfg(target_os = "linux")]
            "--queue-num" => { queue_num = take_value(&mut args, argv)?; }

            #[cfg(target_os = "linux")]
            "--nft-command" => { nft_command = take_value(&mut args, argv)?; }

            _ => { return Err(anyhow!("argument: unknown: {}", arg)); }
        }
    }

    set_opt("OPT_LOG_LEVEL", &OPT_LOG_LEVEL, log_level)?;
    set_opt("OPT_NO_SPLASH", &OPT_NO_SPLASH, no_splash)?;

    set_opt("OPT_DELAY_MS", &OPT_DELAY_MS, delay_ms)?;
    set_opt("OPT_FAKE", &OPT_FAKE, fake)?;
    set_opt("OPT_FAKE_TTL", &OPT_FAKE_TTL, fake_ttl)?;
    set_opt("OPT_FAKE_AUTOTTL", &OPT_FAKE_AUTOTTL, fake_autottl)?;
    set_opt("OPT_FAKE_BADSUM", &OPT_FAKE_BADSUM, fake_badsum)?;

    #[cfg(target_os = "linux")] set_opt("OPT_QUEUE_NUM", &OPT_QUEUE_NUM, queue_num)?;
    #[cfg(target_os = "linux")] set_opt("OPT_NFT_COMMAND", &OPT_NFT_COMMAND, nft_command)?;

    Ok(())
}

pub fn parse_args() {
    if let Err(e) = parse_args_1() {
        log_println!(LogLevel::Error, "{e}");
        usage();
        std::process::exit(1);
    }
}
