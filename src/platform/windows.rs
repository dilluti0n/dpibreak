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
use std::sync::{atomic::Ordering, LazyLock, Mutex, MutexGuard};
use crate::{log::LogLevel, log_println, splash};

pub static WINDIVERT_HANDLE: LazyLock<Mutex<WinDivert<NetworkLayer>>> = LazyLock::new(|| {
    use windivert::*;

    const FILTER: &str = "outbound and tcp and tcp.DstPort == 443 \
                          and tcp.Payload[0] == 22 \
                          and tcp.Payload[5] == 1"; // handshake, clienthello

    let h = match WinDivert::network(FILTER, 0, prelude::WinDivertFlags::new()) {
        Ok(h) => {
            log_println!(LogLevel::Info, "windivert: HANDLE constructed for {}", FILTER);
            h
        },
        Err(e) => {
            log_println!(LogLevel::Error, "windivert: {}", e);
            std::process::exit(1);
        }
    };
    Mutex::new(h)
});

fn lock_handle() -> MutexGuard<'static, WinDivert<NetworkLayer>> {
    WINDIVERT_HANDLE.lock().expect("mutex poisoned")
}

pub fn bootstrap() -> Result<()> {
    Ok(())
}

pub fn cleanup() -> Result<()> {
    lock_handle().close(windivert::CloseAction::Uninstall)?;
    log_println!(LogLevel::Info, "windivert: HANDLE closed and driver uninstalled");

    Ok(())
}

pub fn send_to_raw(pkt: &[u8]) -> Result<()> {
    use windivert::*;

    let mut p = unsafe { packet::WinDivertPacket::<NetworkLayer>::new(pkt.to_vec()) };

    p.address.set_outbound(true);
    p.address.set_ip_checksum(true);
    p.address.set_tcp_checksum(true);

    lock_handle().send(&p)?;

    Ok(())
}

pub fn run() -> Result<()> {
    use crate::{handle_packet, RUNNING, MESSAGE_AT_RUN};
    use super::PACKET_SIZE_CAP;

    let mut windivert_buf = vec![0u8; 65536];
    let mut buf = Vec::<u8>::with_capacity(PACKET_SIZE_CAP);

    splash!("{MESSAGE_AT_RUN}");

    while RUNNING.load(Ordering::SeqCst) {
        let pkt = lock_handle().recv(Some(&mut windivert_buf))?;

        handle_packet!(
            &pkt.data,
            &mut buf,
            handled => {},
            rejected => { lock_handle().send(&pkt)?; }
        );
    }

    Ok(())
}
