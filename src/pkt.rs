// Copyright 2025-2026 Dillution <hskimse1@gmail.com>.
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

use anyhow::Result;
use etherparse::{IpSlice, TcpSlice};
use anyhow::anyhow;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;


use crate::log_println;

use crate::log;
use crate::opt;
use crate::platform;
use crate::tls;

mod fake;
mod hoptab;

use log::LogLevel;

struct PktView<'a> {
    ip: IpSlice<'a>,
    tcp: TcpSlice<'a>
}

impl<'a> PktView<'a> {
    #[inline]
    fn from_raw(raw: &'a [u8]) -> Result<Self> {
        let ip = IpSlice::from_slice(raw)?;
        let tcp = TcpSlice::from_slice(ip.payload().payload)?;

        Ok(Self { ip, tcp })
    }

    #[inline]
    fn ttl(&self) -> u8 {
        use etherparse::IpSlice;

        match &self.ip {
            IpSlice::Ipv4(v4) => v4.header().ttl(),
            IpSlice::Ipv6(v6) => v6.header().hop_limit()
        }
    }

    #[inline]
    fn saddr(&self) -> std::net::IpAddr {
        self.ip.source_addr()
    }

    #[inline]
    fn daddr(&self) -> std::net::IpAddr {
        self.ip.destination_addr()
    }
}

/// Write TCP/IP packet (payload = view.tcp.payload[start..Some(end)])
/// to out_buf, explicitly clearing before.
///
/// If payload, ttl or tcp_checksum is given, override view's one.
fn build_packet(
    view: &PktView,
    start: u32,
    end: Option<u32>,
    out_buf: &mut Vec<u8>,
    payload: Option<&[u8]>,
    ttl: Option<u8>,
    tcp_checksum: Option<u16>
) -> Result<()> {
    use etherparse::*;

    let ip = &view.ip;
    let tcp = &view.tcp;
    let payload = payload.unwrap_or(tcp.payload());

    let end = end.unwrap_or(payload.len().try_into()?);

    if start > end || payload.len() < end as usize {
        return Err(anyhow!("invalid index"));
    }

    let opts = tcp.options();
    let mut tcp_hdr = tcp.to_header();
    tcp_hdr.sequence_number += start;

    let (builder, l3_len) = match ip {
        IpSlice::Ipv4(hdr) => {
            let mut ip_hdr = hdr.header().to_header();
            if let Some(t) = ttl { ip_hdr.time_to_live = t; };

            let exts = hdr.extensions().to_header();
            let l3_len = ip_hdr.header_len() + exts.header_len();

            (PacketBuilder::ip(IpHeaders::Ipv4(
                ip_hdr,
                hdr.extensions().to_header()
            )), l3_len)
        },

        IpSlice::Ipv6(hdr) => {
            let mut ip6_hdr = hdr.header().to_header();
            if let Some(t) = ttl { ip6_hdr.hop_limit = t; };

            let l3_len = Ipv6Header::LEN;

            (PacketBuilder::ip(IpHeaders::Ipv6(
                ip6_hdr,
                Default::default()
            )), l3_len)
        }
    };

    let builder = builder.tcp_header(tcp_hdr).options_raw(opts)?;

    let payload = &payload[start as usize..end as usize];

    out_buf.clear();
    builder.write(out_buf, payload)?;

    if let Some(cs) = tcp_checksum {
        let tcp_csum_off = l3_len + 16;

        if out_buf.len() < tcp_csum_off + 2 {
            return Err(anyhow!("packet too short for tcp checksum patch"));
        }
        out_buf[tcp_csum_off..tcp_csum_off + 2].copy_from_slice(&cs.to_be_bytes());
    }

    Ok(())
}

fn build_segment(
    view: &PktView,
    start: u32,
    end: Option<u32>,
    out_buf: &mut Vec<u8>
) -> Result<()> {
    build_packet(view, start, end, out_buf, None, None, None)
}

fn send_segment(
    view: &PktView,
    start: u32,
    end: Option<u32>,
    buf: &mut Vec<u8>
) -> Result<()> {
    use platform::send_to_raw;

    if opt::fake() {
        fake::fake_clienthello(view, start, end, buf)?;
        send_to_raw(buf, view.daddr())?;
    }
    build_segment(view, start, end, buf)?;
    send_to_raw(buf, view.daddr())?;

    Ok(())
}

fn send_split(view: &PktView, order: &[u32], buf: &mut Vec<u8>) -> Result<()> {
    let mut it = order.iter().copied();

    let Some(mut first) = it.next() else {
        return Err(anyhow!("send_split: invalid order array"));
    };

    for next in it {
        send_segment(view, first, Some(next), buf)?;
        std::thread::sleep(std::time::Duration::from_millis(opt::delay_ms()));
        first = next;
    }

    send_segment(view, first, None, buf)?;

    log_println!(
        LogLevel::Debug,
        "send_split: dst={} segments={:?} tcp_payload_len={}",
        view.daddr(),
        order,
        view.tcp.payload().len()
    );

    Ok(())
}

/// Crudely infer hop from ttl
///
/// Assume server initial TTL is one of: 64, 128, 255.
/// Pick the smallest origin that can produce the observed TTL (origin >= ttl),
/// then hops = origin - ttl.
fn infer_hops(ttl: u8) -> u8 {
    let origin = if ttl <= 64 {
        64u8
    } else if ttl <= 126 {
        128u8
    } else {
        255u8
    };

    origin - ttl
}

fn put_hop_1(pkt: &[u8]) -> Result<()> {
    let view = PktView::from_raw(pkt)?;

    hoptab::put(view.saddr(), infer_hops(view.ttl()));

    Ok(())
}

/// Read pkt and put ip,hop to [`HopTab`]
pub fn put_hop(pkt: &[u8]) {
    if let Err(e) = put_hop_1(pkt) {
        log_println!(LogLevel::Warning, "put_hop: {}", e);
    }
}

/// Return Ok(true) if packet is handled
pub fn handle_packet(pkt: &[u8], buf: &mut Vec::<u8>) -> Result<bool> {
    #[cfg(target_os = "linux")]
    let is_filtered = platform::IS_U32_SUPPORTED.load(Ordering::Relaxed);

    #[cfg(windows)]
    let is_filtered = true;

    let view = PktView::from_raw(pkt)?;

    if !is_filtered && !tls::is_client_hello(view.tcp.payload()) {
        return Ok(false);
    }

    // TODO: if clienthello packet has been (unlikely) fragmented,
    // we should find the second part and drop, reassemble it here.

    send_split(&view, &[0, 1], buf)?;

    Ok(true)
}

#[macro_export]
macro_rules! handle_packet {
    ($bytes:expr, $buf:expr, handled => $on_handled:expr, rejected => $on_rejected:expr $(,)?) => {{
        match crate::pkt::handle_packet($bytes, $buf) {
            Ok(true) => { $on_handled }
            Ok(false) => { $on_rejected }
            Err(e) => {
                log_println!(LogLevel::Warning, "handle_packet: {e}");
                $on_rejected
            }
        }
    }};
}
