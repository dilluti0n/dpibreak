// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Result, anyhow, Context};
use std::sync::OnceLock;

use crate::log_println;

use crate::log;

use log::LogLevel;

static OPT_NO_SPLASH: OnceLock<bool> = OnceLock::new();
static OPT_LOG_LEVEL: OnceLock<LogLevel> = OnceLock::new();

static OPT_FAKE_TTL: OnceLock<u8> = OnceLock::new();
static OPT_FAKE_BADSUM: OnceLock<bool> = OnceLock::new();
static OPT_FAKE: OnceLock<bool> = OnceLock::new();

static OPT_DELAY_MS: OnceLock<u64> = OnceLock::new();

#[cfg(target_os = "linux")] static OPT_QUEUE_NUM: OnceLock<u16> = OnceLock::new();
#[cfg(target_os = "linux")] static OPT_NFT_COMMAND: OnceLock<String> = OnceLock::new();

pub fn no_splash() -> bool {
    *OPT_NO_SPLASH.get().expect("OPT_NO_SPLASH not initialized")
}

#[cfg(debug_assertions)]      const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Debug;
#[cfg(not(debug_assertions))] const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;

pub fn log_level() -> LogLevel {
    *OPT_LOG_LEVEL.get().unwrap_or(&DEFAULT_LOG_LEVEL)
}

pub fn fake() -> bool {
    *OPT_FAKE.get().expect("OPT_FAKE not initialized")
}

pub fn fake_ttl() -> u8 {
    *OPT_FAKE_TTL.get().expect("OPT_FAKE_TTL not initialized")
}

pub fn fake_badsum() -> bool {
    *OPT_FAKE_BADSUM.get().expect("OPT_FAKE_BADSUM not initialized")
}

pub fn delay_ms() -> u64 {
    *OPT_DELAY_MS.get().expect("OPT_DELAY_MS not initialized")
}

#[cfg(target_os = "linux")]
pub fn queue_num() -> u16 {
    *OPT_QUEUE_NUM.get().expect("OPT_QUEUE_NUM not initialized")
}

#[cfg(target_os = "linux")]
pub fn nft_command() -> &'static str {
    OPT_NFT_COMMAND.get().expect("OPT_NFT_COMMAND not initialized").as_str()
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
    cell.set(value).map_err(|_| anyhow!("{name} already initialized"))?;

    let v = cell.get().expect("just set; qed");
    log_println!(LogLevel::Info, "{name}: {v}");

    Ok(())
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

    set_opt("OPT_LOG_LEVEL", &OPT_LOG_LEVEL, log_level)?;
    set_opt("OPT_NO_SPLASH", &OPT_NO_SPLASH, no_splash)?;

    set_opt("OPT_DELAY_MS", &OPT_DELAY_MS, delay_ms)?;
    set_opt("OPT_FAKE", &OPT_FAKE, fake)?;
    set_opt("OPT_FAKE_TTL", &OPT_FAKE_TTL, fake_ttl)?;
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
