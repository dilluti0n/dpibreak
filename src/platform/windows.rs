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
use windivert::{
    WinDivert,
    layer::NetworkLayer
};
use std::sync::{atomic::Ordering, LazyLock, Mutex, MutexGuard};
use crate::{log::LogLevel, log_println, splash};
use crate::opt;

fn windivert_filter() -> String {
    let base = "(outbound and tcp and tcp.DstPort == 443 \
                 and tcp.Payload[0] == 22 \
                 and tcp.Payload[5] == 1)";

    if crate::opt::fake_autottl() {
        let synack = "(!outbound and tcp and tcp.SrcPort == 443 \
                      and tcp.Syn and tcp.Ack)";
        format!("({base} or {synack}) and !impostor")
    } else {
        format!("{base} and !impostor")
    }
}


pub static WINDIVERT_HANDLE: LazyLock<Mutex<WinDivert<NetworkLayer>>> = LazyLock::new(|| {
    use windivert::*;

    let filter = windivert_filter();

    let h = match WinDivert::network(&filter, 0, prelude::WinDivertFlags::new()) {
        Ok(h) => {
            log_println!(LogLevel::Info, "windivert: HANDLE constructed for {}", filter);
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
    if opt::daemon() {
        service_main();
    }

    Ok(())
}

pub fn cleanup() -> Result<()> {
    // FIXME: `CloseAction::Uninstall' fail with `ERR_INVALID_NAME' here.
    // (maybe crate windivert problem, which sending not-null-terminating
    // "WinDivert" string to `OpenServiceA' with "WinDivert".as_ptr())
    // So just closing the handle here instead.
    //
    // User might want to run `sc stop windivert' on administrator shell
    // after terminating the dpibreak.
    lock_handle().close(windivert::CloseAction::Nothing)?;
    log_println!(LogLevel::Info, "windivert: HANDLE closed");

    Ok(())
}

pub fn send_to_raw(pkt: &[u8]) -> Result<()> {
    use windivert::*;

    let mut p = unsafe { packet::WinDivertPacket::<NetworkLayer>::new(pkt.to_vec()) };

    p.address.set_outbound(true);
    p.address.set_ip_checksum(true); // TODO: test if this is needed
    p.address.set_tcp_checksum(false); // For badsum; anyway it is already calculated
    p.address.set_impostor(true); // to prevent inf loop

    lock_handle().send(&p)?;

    Ok(())
}

use crate::RUNNING;

pub fn run() -> Result<()> {
    use crate::{handle_packet, MESSAGE_AT_RUN};
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

fn service_run() -> Result<()> {
    let result = run();
    cleanup()?;

    result
}

fn service_run_1() {
    if service_run().is_err() {
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn service_main()  {
    use windows_services::Command;

    match windows_services::Service::new()
        .can_stop()
        .run(|_, command| {
            match command {
                Command::Start => {
                    std::thread::spawn(|| service_run_1());
                }
                Command::Stop => {
                    RUNNING.store(false, Ordering::SeqCst);
                }
                _ => {}
            }
        }) {
            Ok(_) => {}
            Err(e) => {
                println!("{e}");
                std::process::exit(1);
            }
        };
}
