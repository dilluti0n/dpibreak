use anyhow::{Result, anyhow};
use std::sync::atomic::Ordering;

mod platform;
use platform::*;

mod pkt;
mod tls;
use tls::TLSMsg;

fn is_client_hello(payload: &[u8]) -> bool {
    if TLSMsg::new({
        let mut record = TLSMsg::new(payload);
        if record.get_uint(1) != Some(22) { // type
            return false;                   // not handshake
        }

        record.pass(2);                 // legacy_record_version
        record.pass(2);                 // length

        if record.get_ptr() >= payload.len() {
            return false;
        }

        &record.payload[record.get_ptr()..] // fragment
    }).get_uint(1) != Some(1) { // msg_type
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
    let need = builder.size(payload.len());

    builder.write(out_buf, payload)?;
    out_buf.truncate(need);

    Ok(())
}

/// Return Ok(true) if packet is handled
fn handle_packet(pkt: &[u8]) -> Result<bool> {

    #[cfg(target_os = "linux")]
    let is_filtered = IS_U32_SUPPORTED.load(Ordering::Relaxed);

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
                eprintln!("warning: handle_packet: {e}");
                $on_rejected
            }
        }
    }};
}

fn main() -> Result<()> {
    use std::sync::{
        Arc,
        atomic::AtomicBool
    };

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); })?;
    }

    bootstrap()?;
    run(running)?;
    cleanup()?;

    Ok(())
}
