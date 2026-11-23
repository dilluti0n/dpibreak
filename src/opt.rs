// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result, anyhow};
use std::sync::OnceLock;

use crate::log;
use crate::platform;

use log::LogLevel;

#[derive(Copy, Clone)]
pub struct Segment(pub u32, pub u32);

impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let end = if self.1 == u32::MAX {
            "end".to_string()
        } else {
            self.1.to_string()
        };
        write!(f, "[{},{})", self.0, end)
    }
}

impl std::fmt::Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

pub struct SegmentOrder {
    raw: String,
    segments: Vec<Segment>,
}

impl SegmentOrder {
    /// Parse 5,1,0,3 to (5, u32::MAX), (1, 3), (0, 1), (3, 5).
    pub fn new(s: &str) -> Result<Self> {
        let mut points: Vec<u32> = s
            .split(',')
            .map(|x| x.trim().parse::<u32>())
            .collect::<std::result::Result<_, _>>()
            .with_context(|| format!("--segment-order: invalid value '{s}'"))?;

        if points.is_empty() {
            return Err(anyhow!("--segment-order: empty"));
        }

        let order = points.clone();
        points.sort_unstable();
        points.dedup();

        if !points.contains(&0) {
            return Err(anyhow!("--segment-order: must contain 0"));
        }

        let sorted_ranges: Vec<Segment> = points
            .windows(2)
            .map(|w| Segment(w[0], w[1]))
            .chain(std::iter::once(Segment(*points.last().unwrap(), u32::MAX)))
            .collect();

        let segments = order
            .iter()
            .map(|&p| {
                sorted_ranges
                    .iter()
                    .find(|&&Segment(start, _)| start == p)
                    .copied()
                    .ok_or_else(|| anyhow!("--segment-order: internal error"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            raw: s.to_string(),
            segments,
        })
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
}

impl std::fmt::Display for SegmentOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} (", self.raw)?;
        for (i, seg) in self.segments.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{seg}")?;
        }
        write!(f, ")")
    }
}

const DEFAULT_DAEMON: bool = false;
#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Debug;
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Warning;
const DEFAULT_NO_SPLASH: bool = false;
const DEFAULT_FAKE: bool = false;
const DEFAULT_FAKE_TTL: u8 = 8;
const DEFAULT_FAKE_AUTOTTL: bool = false;
const DEFAULT_FAKE_BADSUM: bool = false;
const DEFAULT_DELAY_MS: u64 = 0;
#[cfg(target_os = "linux")]
const DEFAULT_QUEUE_NUM: u16 = 1;
#[cfg(target_os = "linux")]
const DEFAULT_NFT_COMMAND: &str = "nft";
#[cfg(target_os = "linux")]
const DEFAULT_NO_RULES: bool = false;
const DEFAULT_SEGMENT_ORDER: &str = "0,1";

/// Defines [`Opt`] and, for each option, its global cell, getter,
/// [`Opt::set_opt`] entry and startup log line.
///
/// The rest of the crate reads an option through its getter, a free
/// function named after the entry: `copy fake: bool = ...;` exposes
/// `opt::fake() -> bool`. `main` fills the cells once with
/// `Opt::from_args()?.set_opt()?`, and the returned [`InitializedOpts`]
/// logs every option as `OPT_<NAME>: <value>`.
///
/// Each entry is `<kind> <name>: <type> = <default>;`:
/// - `copy`: getter returns the value; `<default>` is a constant used
///   until [`Opt::set_opt`] is called.
/// - `str`: a `String`; getter returns `&'static str`; `<default>` is
///   a `&'static str` constant.
/// - `ref`: getter returns `&'static <type>` and panics before
///   [`Opt::set_opt`]; `<default>` is any expression.
macro_rules! options {
    ($( $(#[$m:meta])* $kind:ident $name:ident: $ty:ty = $default:expr; )*) => {
        pub struct Opt {
            $( $(#[$m])* $name: $ty, )*
        }

        impl Default for Opt {
            fn default() -> Self {
                Self {
                    $( $(#[$m])* $name: options!(@init $kind $default), )*
                }
            }
        }

        struct Cells {
            $( $(#[$m])* $name: OnceLock<$ty>, )*
        }

        static CELLS: Cells = Cells {
            $( $(#[$m])* $name: OnceLock::new(), )*
        };

        impl Opt {
            pub fn set_opt(self) -> Result<InitializedOpts> {
                $(
                    $(#[$m])*
                    CELLS.$name.set(self.$name).map_err(|_| {
                        anyhow!("OPT_{} already initialized", stringify!($name).to_uppercase())
                    })?;
                )*
                Ok(InitializedOpts)
            }
        }

        impl InitializedOpts {
            pub fn log(&self) {
                $(
                    $(#[$m])*
                    crate::info!("OPT_{}: {}", stringify!($name).to_uppercase(), $name());
                )*
            }
        }

        $( options!(@getter $(#[$m])* $kind $name: $ty = $default); )*
    };

    (@init copy $default:expr) => { $default };
    (@init str $default:expr) => { String::from($default) };
    (@init ref $default:expr) => { $default };

    (@getter $(#[$m:meta])* copy $name:ident: $ty:ty = $default:expr) => {
        $(#[$m])*
        pub fn $name() -> $ty {
            *CELLS.$name.get().unwrap_or(&$default)
        }
    };
    (@getter $(#[$m:meta])* str $name:ident: $ty:ty = $default:expr) => {
        $(#[$m])*
        pub fn $name() -> &'static str {
            CELLS.$name.get().map(String::as_str).unwrap_or($default)
        }
    };
    (@getter $(#[$m:meta])* ref $name:ident: $ty:ty = $default:expr) => {
        $(#[$m])*
        pub fn $name() -> &'static $ty {
            CELLS.$name.get().expect(concat!("OPT_", stringify!($name), " not set"))
        }
    };
}

// To add an option, edit four places:
// 1. A `DEFAULT_<NAME>` constant above, on one line as
//    `const DEFAULT_<NAME>: <type> = <value>;`: build.rs substitutes it
//    for `{{DEFAULT_<NAME>}}` in dpibreak.1.in.
// 2. An entry here; see `options!` for which kind to use.
// 3. A match arm in `Opt::from_args` that sets `opt.<name>`.
// 4. A line in `usage`.
// A platform-specific option needs the same `#[cfg(...)]` on all four.
// Then document it in dpibreak.1.in and read it with `opt::<name>()`.
options! {
    copy daemon: bool = DEFAULT_DAEMON;
    copy no_splash: bool = DEFAULT_NO_SPLASH;
    copy log_level: LogLevel = DEFAULT_LOG_LEVEL;
    copy delay_ms: u64 = DEFAULT_DELAY_MS;
    copy fake: bool = DEFAULT_FAKE;
    copy fake_ttl: u8 = DEFAULT_FAKE_TTL;
    copy fake_autottl: bool = DEFAULT_FAKE_AUTOTTL;
    copy fake_badsum: bool = DEFAULT_FAKE_BADSUM;
    #[cfg(target_os = "linux")]
    copy queue_num: u16 = DEFAULT_QUEUE_NUM;
    #[cfg(target_os = "linux")]
    str nft_command: String = DEFAULT_NFT_COMMAND;
    #[cfg(target_os = "linux")]
    copy no_rules: bool = DEFAULT_NO_RULES;
    ref segment_order: SegmentOrder =
        SegmentOrder::new(DEFAULT_SEGMENT_ORDER).expect("DEFAULT_SEGMENT_ORDER is valid");
}

pub struct InitializedOpts;

impl Opt {
    pub fn from_args() -> Result<Self> {
        let mut opt = Opt::default();
        let mut args = std::env::args().skip(1); // program name

        let mut warned_loglevel_deprecated = false;
        let mut warned_daemon_deprecated = false;

        while let Some(arg) = args.next() {
            let argv = arg.as_str();

            match argv {
                "-h" | "--help" => {
                    usage();
                    platform::paexit(0);
                }
                "-d" | "-D" | "--daemon" => {
                    if argv == "-D" && !warned_daemon_deprecated {
                        // FIXME(on release): remove this on v1.0.0
                        warned_daemon_deprecated = true;
                        eprintln!(
                            "Note: `{arg}' has been deprecated since v0.6.0 and planned to be removed on v1.0.0. Use `-d' instead."
                        );
                    }
                    opt.no_splash = true;
                    // if it is unchanged explicitly by argument, set it to info
                    if opt.log_level == DEFAULT_LOG_LEVEL {
                        opt.log_level = LogLevel::Info;
                    }
                    opt.daemon = true;
                }
                "--delay-ms" => {
                    opt.delay_ms = take_value(&mut args, argv)?;
                }
                "--log-level" | "--loglevel" => {
                    if argv == "--loglevel" && !warned_loglevel_deprecated {
                        // FIXME(on release): remove this on v1.0.0
                        warned_loglevel_deprecated = true;
                        eprintln!(
                            "Note: `{arg}' has been deprecated since v0.1.1 and planned to be removed on v1.0.0. Use `--log-level' instead."
                        );
                    }
                    opt.log_level = take_value(&mut args, argv)?;
                }
                "--no-splash" => {
                    opt.no_splash = true;
                }

                "-o" | "--segment-order" => {
                    let s: String = take_value(&mut args, argv)?;
                    opt.segment_order = SegmentOrder::new(&s)?;
                }

                "--fake" => {
                    opt.fake = true;
                }
                "-t" | "--fake-ttl" => {
                    opt.fake = true;
                    opt.fake_ttl = take_value(&mut args, argv)?;
                }
                "-a" | "--fake-autottl" => {
                    opt.fake = true;
                    opt.fake_autottl = true;
                }
                "--fake-badsum" => {
                    opt.fake = true;
                    opt.fake_badsum = true;
                }

                #[cfg(target_os = "linux")]
                "--queue-num" => {
                    opt.queue_num = take_value(&mut args, argv)?;
                }

                #[cfg(target_os = "linux")]
                "--nft-command" => {
                    opt.nft_command = take_value(&mut args, argv)?;
                }

                #[cfg(target_os = "linux")]
                "--no-rules" => {
                    opt.no_rules = true;
                }

                _ => {
                    return Err(anyhow!("unknown argument: {}", arg));
                }
            }
        }

        Ok(opt)
    }
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
    println!("Usage: dpibreak [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -h, --help                              Show this help");
    println!(
        "  -d, --daemon                            Run as daemon. kill `pidof dpibreak` to stop"
    );
    println!(
        "  --delay-ms    <u64>                     Delay milliseconds between each segment packets (default: {DEFAULT_DELAY_MS})"
    );
    #[cfg(target_os = "linux")]
    println!(
        "  --queue-num   <u16>                     Netfilter queue number to bind (default: {DEFAULT_QUEUE_NUM})"
    );
    #[cfg(target_os = "linux")]
    println!("  --nft-command <string>                    (default: {DEFAULT_NFT_COMMAND})");
    #[cfg(target_os = "linux")]
    println!("  --no-rules                              Do not install nftables/iptables rules");
    println!("  --log-level <debug|info|warning|error>    (default: {DEFAULT_LOG_LEVEL})");
    println!("  --no-splash                             Do not print splash messages on startup");
    println!();
    println!("  --fake                                  Enable fake clienthello injection");
    println!(
        "  -t, --fake-ttl    <u8>                  Override ttl of fake clienthello (default: {DEFAULT_FAKE_TTL})"
    );
    println!(
        "  -a, --fake-autottl                      Infer ttl of fake clienthello automatically and override it"
    );
    println!(
        "  --fake-badsum                           Modifies the TCP checksum of the fake packet to an invalid value"
    );
    println!(
        "  -o, --segment-order <u32,u32,...>       Byte offsets defining segment boundaries and transmission order."
    );
    println!(
        "                                          Must include 0 (default: {DEFAULT_SEGMENT_ORDER})"
    );
    println!();
    println!("See dpibreak(1) for more information.");
}
