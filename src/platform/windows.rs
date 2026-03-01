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
    layer::NetworkLayer,
    prelude,
    CloseAction
};
use std::sync::{LazyLock, Mutex, mpsc};
use std::thread;
use crate::{log::LogLevel, log_println, splash};
use crate::{opt, pkt};

fn open_handle(filter: &str, flags: prelude::WinDivertFlags) -> WinDivert<NetworkLayer> {
    use windivert::*;

    let h = match WinDivert::network(&filter, 0, flags) {
        Ok(h) => {
            log_println!(LogLevel::Info, "windivert: open: {}", filter);
            h
        },
        Err(e) => {
            log_println!(LogLevel::Error, "windivert: {}", e);
            log_println!(LogLevel::Error, "windivert: {}", filter);
            std::process::exit(1);
        }
    };
    h
}

pub fn bootstrap() -> Result<()> {
    if opt::daemon() {
        service_main();
    }

    Ok(())
}

static SEND_HANDLE: LazyLock<Mutex<WinDivert<NetworkLayer>>> = LazyLock::new(|| {
    let flags = prelude::WinDivertFlags::new()
        .set_send_only();

    Mutex::new(open_handle("false", flags))
});

fn send_to_raw_1(pkt: &[u8]) -> Result<()> {
    use windivert::*;

    let mut p = unsafe { packet::WinDivertPacket::<NetworkLayer>::new(pkt.to_vec()) };

    p.address.set_outbound(true);
    p.address.set_ip_checksum(true); // TODO: test if this is needed
    p.address.set_tcp_checksum(false); // For badsum; anyway it is already calculated
    p.address.set_impostor(true); // to prevent inf loop

    SEND_HANDLE.lock().expect("mutex poisoned").send(&p)?;

    Ok(())
}

pub fn send_to_raw(pkt: &[u8], _dst: std::net::IpAddr) -> Result<()> {
    send_to_raw_1(pkt)
}

enum Event {
    Divert(Vec<u8>),
    Sniff(Vec<u8>)
}

fn spawn_recv<F>(
    filter: &'static str,
    flags: prelude::WinDivertFlags,
    tx: mpsc::Sender<Event>,
    wrap: F,
) where
    F: Fn(Vec<u8>) -> Event + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let handle = open_handle(&filter, flags);

		loop {
            if let Ok(pkt) = handle.recv(Some(&mut buf)) {
                _ = tx.send(wrap(pkt.data.to_vec()));
            }
        }
    });
}

pub fn run() -> Result<()> {
    let mut buf = Vec::<u8>::with_capacity(super::PACKET_SIZE_CAP);
    let (tx, rx) = mpsc::channel();

    spawn_recv(
        concat!(
            "outbound and tcp and tcp.DstPort == 443",
            " ", "and tcp.Payload[0] == 22",
            " ", "and tcp.Payload[5] == 1 and !impostor"
        ),
        prelude::WinDivertFlags::new(), tx.clone(), Event::Divert
    );

    if opt::fake_autottl() {
        spawn_recv(
            "!outbound and tcp and tcp.SrcPort == 443 and tcp.Syn and tcp.Ack",
            prelude::WinDivertFlags::new().set_sniff(), tx, Event::Sniff
        );
    }

    splash!("{}", super::MESSAGE_AT_RUN);

    for event in rx {
        match event {
            Event::Divert(data) => {
                crate::handle_packet!(
                    &data,
                    &mut buf,
                    handled => {},
                    rejected => { send_to_raw_1(&data)?; }
                );
            }
            Event::Sniff(data) => { pkt::put_hop(&data); }
        }
    }

    // FIXME: `CloseAction::Uninstall' fail with `ERR_INVALID_NAME' here.
    // (maybe crate windivert problem, which sending not-null-terminating
    // "WinDivert" string to `OpenServiceA' with "WinDivert".as_ptr())
    // So just closing the handle here instead.
    //
    // User might want to run `sc stop windivert' on administrator shell
    // after terminating the dpibreak.
    SEND_HANDLE.lock().expect("mutex poisoned").close(CloseAction::Nothing)?;

    Ok(())
}

fn service_run() {
    if run().is_err() {
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
                    std::thread::spawn(|| service_run());
                }
                Command::Stop => {}
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
