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

use anyhow::Result;
use windivert::{
    WinDivert,
    layer::NetworkLayer
};
use std::sync::{atomic::Ordering, LazyLock};
use crate::{log::LogLevel, log_println, splash};

pub static WINDIVERT_HANDLE: LazyLock<WinDivert<NetworkLayer>> = LazyLock::new(|| {
    use windivert::*;

    const FILTER: &str = "outbound and tcp and tcp.DstPort == 443 \
                          and tcp.Payload[0] == 22 \
                          and tcp.Payload[5] == 1"; // handshake, clienthello

    match WinDivert::network(FILTER, 0, prelude::WinDivertFlags::new()) {
        Ok(h) => {
            log_println!(LogLevel::Info, "windivert: HANDLE constructed for {}", FILTER);

            h
        },
        Err(e) => { panic!("Err: {}", e); }
    }
});

pub fn bootstrap() -> Result<()> {
    Ok(())
}

pub fn cleanup() -> Result<()> {
    Ok(())
}

pub fn send_to_raw(pkt: &[u8]) -> Result<()> {
    use windivert::*;

    let mut p = unsafe { packet::WinDivertPacket::<NetworkLayer>::new(pkt.to_vec()) };

    p.address.set_outbound(true);
    p.address.set_ip_checksum(true);
    p.address.set_tcp_checksum(true);

    WINDIVERT_HANDLE.send(&p)?;

    Ok(())
}

pub fn run() -> Result<()> {
    use crate::{handle_packet, RUNNING, MESSAGE_AT_RUN};
    use super::PACKET_SIZE_CAP;

    let mut windivert_buf = vec![0u8; 65536];
    let mut buf = Vec::<u8>::with_capacity(PACKET_SIZE_CAP);

    splash!("{MESSAGE_AT_RUN}");

    while RUNNING.load(Ordering::SeqCst) {
        let pkt = WINDIVERT_HANDLE.recv(Some(&mut windivert_buf))?;

        handle_packet!(
            &pkt.data,
            &mut buf,
            handled => {},
            rejected => { WINDIVERT_HANDLE.send(&pkt)?; }
        );
    }

    Ok(())
}
