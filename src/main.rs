use anyhow::{Result, anyhow, Context};
use std::sync::{
    atomic::{Ordering, AtomicBool},
    OnceLock,
};

mod platform;
mod pkt;
mod tls;

static RUNNING: AtomicBool = AtomicBool::new(true);

static DELAY_MS: OnceLock<u64> = OnceLock::new();

fn delay_ms() -> u64 {
    *DELAY_MS.get().expect("DELAY_MS not initialized")
}

fn is_client_hello(payload: &[u8]) -> bool {
    use tls::TLSMsg;

    let mut record = TLSMsg::new(payload);
    if record.get_uint(1) != Some(22) { // type
        return false;                   // not handshake
    }

    record.pass(2);                 // legacy_record_version
    record.pass(2);                 // length

    if record.get_ptr() >= payload.len() {
        return false;
    }

    let fragment = &record.payload[record.get_ptr()..]; // fragment
    if TLSMsg::new(fragment).get_uint(1) != Some(1) { // msg_type
        return false;                     // not clienthello
    }

    true
}

fn split_packet(pkt: &pkt::PktView, start: u32, end: Option<u32>,
                out_buf: &mut Vec<u8>) -> Result<()> {
    use etherparse::*;

    let ip = &pkt.ip;
    let tcp = &pkt.tcp;
    let payload = tcp.payload();

    let end = end.unwrap_or(payload.len().try_into()?);

    if start > end || payload.len() < end as usize {
        return Err(anyhow!("invaild index"));
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

    if !is_filtered && !is_client_hello(view.tcp.payload()) {
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
    println!("packet is handled, len={}", pkt.len());

    Ok(true)
}

#[macro_export]
macro_rules! handle_packet {
    ($bytes:expr, handled => $on_handled:expr, rejected => $on_rejected:expr $(,)?) => {{
        match handle_packet($bytes) {
            Ok(true) => { $on_handled }
            Ok(false) => { $on_rejected }
            Err(e) => {
                println!("warning: handle_packet: {e}");
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
  --delay-ms <u64>        (default: 0)
  --queue-num <u16>       (linux only, default: 1)
  -h, --help              Show this help"#
    );
}

fn parse_args_1() -> Result<()> {
    let mut delay_ms: u64 = 0;

    #[cfg(target_os = "linux")]
    let mut queue_num: u16 = 1;

    let mut args = std::env::args().skip(1); // program name

    while let Some(arg) = args.next() {
        let argv = arg.as_str();

        match argv {
            "-h" | "--help" => { usage(); std::process::exit(0); }
            "--delay-ms" => { delay_ms = take_value(&mut args, argv)?; }

            #[cfg(target_os = "linux")]
            "--queue-num" => { queue_num = take_value(&mut args, argv)?; }

            _ => { return Err(anyhow!("argument: unknown: {}", arg)); }
        }
    }

    DELAY_MS.set(delay_ms).map_err(|_| anyhow!("DELAY_MS already initialized"))?;

    #[cfg(target_os = "linux")]
    platform::QUEUE_NUM.set(queue_num).map_err(|_| anyhow!("QUEUE_NUM already initialized"))?;

    Ok(())
}

fn parse_args() {
    if let Err(e) = parse_args_1() {
        println!("Error: {e}");
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

fn main() -> Result<()> {
    trap_exit()?;
    parse_args();
    platform::bootstrap()?;
    platform::run()?;
    platform::cleanup()?;

    Ok(())
}
