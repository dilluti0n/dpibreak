// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result, anyhow};
use std::sync::OnceLock;

use crate::log;
use crate::platform;

use log::LogLevel;

#[derive(Copy, Clone, PartialEq)]
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

#[derive(PartialEq)]
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

impl std::str::FromStr for SegmentOrder {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
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
/// The default documented in dpibreak.1; debug builds log everything.
const DEFAULT_LOG_LEVEL_RELEASE: LogLevel = LogLevel::Warning;
const DEFAULT_LOG_LEVEL: LogLevel = if cfg!(debug_assertions) {
    LogLevel::Debug
} else {
    DEFAULT_LOG_LEVEL_RELEASE
};
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

        /// Whether `value`, as written in dpibreak.1, parses to the
        /// default of field `name`. `None` if there is no such field.
        #[cfg(test)]
        fn is_default(name: &str, value: &str) -> Option<bool> {
            let default = Opt::default();
            $(
                $(#[$m])*
                if name == stringify!($name) {
                    return Some(value.parse::<$ty>().is_ok_and(|v| v == default.$name));
                }
            )*
            None
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
// 1. A `DEFAULT_<NAME>` constant above.
// 2. An entry here; see `options!` for which kind to use.
// 3. A match arm in `Opt::parse` that sets `opt.<name>`; options with a
//    value read it with `take_value`.
// 4. A line in `usage`.
// A platform-specific option needs the same `#[cfg(...)]` on all four.
// Then document it in dpibreak.1, with `(Default: <value>)` in the
// description if it takes a value (a test checks it against the
// default), and read it with `opt::<name>()`.
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
        Self::parse(lexopt::Parser::from_env())
    }

    fn parse(mut parser: lexopt::Parser) -> Result<Self> {
        let mut opt = Opt::default();

        let mut warned_loglevel_deprecated = false;
        let mut warned_daemon_deprecated = false;

        while let Some(arg) = parser.next()? {
            use lexopt::Arg::{Long, Short};

            // for messages: `-t`, `--fake-ttl`
            let name = match arg {
                Short(c) => format!("-{c}"),
                Long(l) => format!("--{l}"),
                lexopt::Arg::Value(_) => String::new(),
            };

            match arg {
                Short('h') | Long("help") => {
                    usage();
                    platform::paexit(0);
                }
                Short('d') | Short('D') | Long("daemon") => {
                    if arg == Short('D') && !warned_daemon_deprecated {
                        // FIXME(on release): remove this on v1.0.0
                        warned_daemon_deprecated = true;
                        eprintln!(
                            "Note: `{name}' has been deprecated since v0.6.0 and planned to be removed on v1.0.0. Use `-d' instead."
                        );
                    }
                    opt.no_splash = true;
                    // if it is unchanged explicitly by argument, set it to info
                    if opt.log_level == DEFAULT_LOG_LEVEL {
                        opt.log_level = LogLevel::Info;
                    }
                    opt.daemon = true;
                }
                Long("delay-ms") => {
                    opt.delay_ms = take_value(&mut parser, &name)?;
                }
                Long("log-level") | Long("loglevel") => {
                    if arg == Long("loglevel") && !warned_loglevel_deprecated {
                        // FIXME(on release): remove this on v1.0.0
                        warned_loglevel_deprecated = true;
                        eprintln!(
                            "Note: `{name}' has been deprecated since v0.1.1 and planned to be removed on v1.0.0. Use `--log-level' instead."
                        );
                    }
                    opt.log_level = take_value(&mut parser, &name)?;
                }
                Long("no-splash") => {
                    opt.no_splash = true;
                }

                Short('o') | Long("segment-order") => {
                    let s: String = take_value(&mut parser, &name)?;
                    opt.segment_order = SegmentOrder::new(&s)?;
                }

                Long("fake") => {
                    opt.fake = true;
                }
                Short('t') | Long("fake-ttl") => {
                    opt.fake = true;
                    opt.fake_ttl = take_value(&mut parser, &name)?;
                }
                Short('a') | Long("fake-autottl") => {
                    opt.fake = true;
                    opt.fake_autottl = true;
                }
                Long("fake-badsum") => {
                    opt.fake = true;
                    opt.fake_badsum = true;
                }

                #[cfg(target_os = "linux")]
                Long("queue-num") => {
                    opt.queue_num = take_value(&mut parser, &name)?;
                }

                #[cfg(target_os = "linux")]
                Long("nft-command") => {
                    opt.nft_command = take_value(&mut parser, &name)?;
                }

                #[cfg(target_os = "linux")]
                Long("no-rules") => {
                    opt.no_rules = true;
                }

                _ => {
                    return Err(arg.unexpected().into());
                }
            }
        }

        Ok(opt)
    }
}

/// Take the value of option `name`, given as `--name value`,
/// `--name=value` or `-nvalue`.
fn take_value<T>(parser: &mut lexopt::Parser, name: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = parser
        .value()?
        .into_string()
        .map_err(|v| anyhow!("argument: {name}: invalid value {v:?}"))?;
    raw.parse::<T>()
        .with_context(|| format!("argument: {name}: invalid value '{raw}'"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Opt> {
        Opt::parse(lexopt::Parser::from_args(args))
    }

    #[test]
    fn value_forms() {
        for args in [
            &["--fake-ttl", "3"][..],
            &["--fake-ttl=3"],
            &["-t", "3"],
            &["-t3"],
        ] {
            let opt = parse(args).unwrap();
            assert_eq!(opt.fake_ttl, 3, "{args:?}");
            assert!(opt.fake, "{args:?}");
        }
    }

    #[test]
    fn combined_short_flags() {
        let opt = parse(&["-ad"]).unwrap();
        assert!(opt.fake_autottl);
        assert!(opt.daemon);
    }

    #[test]
    fn rejects() {
        for args in [
            &["--bogus"][..],
            &["positional"],
            &["--fake=1"],
            &["--fake-ttl"],
            &["--fake-ttl=x"],
            &["--fake-ttl=256"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    const MANUAL: &str = include_str!("../dpibreak.1");

    /// `fake-ttl` from an option tag such as
    /// `.BR \-t ", " \-\-fake\-ttl " \fI<u8>\fR"`.
    fn long_option(tag: &str) -> Option<String> {
        let tag = tag.replace("\\-", "-");
        let (_, rest) = tag.split_once("--")?;
        Some(
            rest.chars()
                .take_while(|&c| c.is_ascii_alphanumeric() || c == '-')
                .collect(),
        )
    }

    #[test]
    fn manual_defaults() {
        let mut option = None;
        let mut after_tp = false;
        let mut checked = 0;

        for line in MANUAL.lines() {
            if after_tp {
                option = long_option(line);
            }
            after_tp = line == ".TP";
            if line.starts_with(".SH") {
                option = None;
            }

            let Some((_, rest)) = line.split_once("(Default: ") else {
                continue;
            };
            let (value, _) = rest.split_once(')').expect("unclosed (Default:");
            let name = option.as_deref().expect("(Default: outside an option");

            let field = name.replace('-', "_");
            let ok = if field == "log_level" {
                value.parse().ok() == Some(DEFAULT_LOG_LEVEL_RELEASE)
            } else {
                match is_default(&field, value) {
                    Some(ok) => ok,
                    // the manual also documents Linux-only options
                    None if !cfg!(target_os = "linux") => true,
                    None => panic!("dpibreak.1: --{name}: no such option"),
                }
            };
            assert!(ok, "dpibreak.1: --{name}: wrong default '{value}'");
            checked += 1;
        }

        assert!(checked > 0, "no (Default: ...) found in dpibreak.1");
    }

    #[test]
    fn manual_version() {
        let mut v = env!("CARGO_PKG_VERSION").split('.');
        let want = format!("\"DPIBreak v{}.{}\"", v.next().unwrap(), v.next().unwrap());
        let th = MANUAL.lines().find(|l| l.starts_with(".TH ")).unwrap();
        assert!(
            th.contains(&want),
            "dpibreak.1: .TH should contain {want}: {th}"
        );
    }
}
