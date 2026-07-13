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
use windivert::{WinDivert, layer::NetworkLayer, prelude};
use windivert::prelude::{WinDivertError, WinDivertRecvError, WinDivertShutdownMode};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use crate::{opt, pkt};
use super::paexit;

pub fn pause() {
    println!("Press any key to exit...");

    unsafe extern "C" { fn _getch() -> i32; }
    unsafe { _getch(); }
}

static RECV_HANDLES: LazyLock<Mutex<Vec<Arc<WinDivert<NetworkLayer>>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

fn open_recv_handle(filter: &str, flags: prelude::WinDivertFlags) -> Arc<WinDivert<NetworkLayer>> {
    let h = Arc::new(open_handle(filter, flags));
    RECV_HANDLES.lock().expect("mutex poisoned").push(h.clone());
    h
}

fn shutdown_all() {
    for h in RECV_HANDLES.lock().expect("mutex poisoned").iter() {
        if let Err(e) = h.shutdown(WinDivertShutdownMode::Both) {
            crate::warn!("windivert: shutdown: {e}");
        }
    }
}

fn open_handle(filter: &str, flags: prelude::WinDivertFlags) -> WinDivert<NetworkLayer> {
    use windivert::*;

    let h = match WinDivert::network(&filter, 0, flags) {
        Ok(h) => {
            crate::info!("windivert: open filter {filter}");
            h
        },
        Err(e) => {
            crate::error!("windivert: cannot open {filter}: {e}");
            paexit(1);
        }
    };
    h
}

pub fn bootstrap() -> Result<()> {
    if opt::daemon() {
        service_main();
    }

    install_ctrl_handler();

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
    p.address.set_ip_checksum(false);
    p.address.set_tcp_checksum(false); // For badsum; anyway it is already calculated
    p.address.set_impostor(true); // to prevent inf loop

    SEND_HANDLE.lock().expect("mutex poisoned").send(&p)?;

    Ok(())
}

pub fn send_to_raw(pkt: &[u8], _dst: std::net::IpAddr) -> Result<()> {
    send_to_raw_1(pkt)
}

macro_rules! recv_loop {
    ($handle:expr, $pkt:ident => $body:expr) => {
        let mut buf = vec![0u8; 65536];
        loop {
            match $handle.recv(Some(&mut buf)) {
                Ok($pkt) => { $body }
                // Check if it is shutdowned with WinDivertShutdown()
                Err(WinDivertError::Recv(WinDivertRecvError::NoData)) => {
                    crate::info!("windivert: recv shutdown");
                    break;
                }
                Err(e) => { crate::warn!("windivert: recv: {}", e); }
            }
        }
    };
}

fn install_ctrl_handler() {
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    unsafe extern "system" fn sighandler(ctrl_type: u32) -> i32 {
        // CTRL_C_EVENT=0, CTRL_BREAK_EVENT=1, CTRL_CLOSE_EVENT=2,
        // CTRL_LOGOFF_EVENT=5, CTRL_SHUTDOWN_EVENT=6
        match ctrl_type {
            0 | 1 | 2| 5 | 6 => { shutdown_all(); 1 }
            _ => 0,               // FALSE
        }
    }

    let ok = unsafe { SetConsoleCtrlHandler(Some(sighandler), 1) };
    if ok == 0 {
        crate::warn!("SetConsoleCtrlHandler() failed");
    }

    crate::info!("cleanup handler installed");
}

pub fn run() -> Result<()> {
    let mut buf = Vec::<u8>::with_capacity(super::PACKET_SIZE_CAP);

    if opt::fake_autottl() {
        let handle = open_recv_handle(
            "!outbound and tcp and tcp.SrcPort == 443 and tcp.Syn and tcp.Ack",
            prelude::WinDivertFlags::new().set_sniff()
        );
        thread::spawn(move || { recv_loop!(handle, pkt => pkt::put_hop(&pkt.data)); });
    }

    let divert = open_recv_handle(
        concat!(
            "outbound and tcp and tcp.DstPort == 443",
            " ", "and tcp.Payload[0] == 22",
            " ", "and tcp.Payload[5] == 1 and !impostor"
        ),
        prelude::WinDivertFlags::new()
    );

    crate::splash!("{}", super::MESSAGE_AT_RUN);

    recv_loop!(divert, pkt => {
        crate::handle_packet!(
            &pkt.data,
            &mut buf,
            handled => {},
            rejected => send_to_raw_1(&pkt.data)?
        )
    });

    Ok(())
}

fn service_run() {
    use std::process::exit;

    if run().is_err() {
        exit(1);
    }
    exit(0);
}

fn service_main()  {
    use windows_services::Command;

    match windows_services::Service::new()
        .can_stop()
        .run(|_, command| {
            match command {
                Command::Start => { std::thread::spawn(|| service_run()); }
                Command::Stop => { shutdown_all(); }
                _ => {}
            }
        }) {
            Ok(_) => {}
            Err(e) => {
                println!("{e}");
                paexit(1);
            }
        };
}

pub fn local_time() -> (i32, u8, u8, u8, u8, u8) {
    use std::mem::zeroed;
    #[repr(C)]
    struct SYSTEMTIME { y: u16, m: u16, _dow: u16, d: u16, h: u16, min: u16, s: u16, _ms: u16 }
    unsafe extern "system" { fn GetLocalTime(st: *mut SYSTEMTIME); }
    unsafe {
        let mut st: SYSTEMTIME = zeroed();
        GetLocalTime(&mut st);
        (st.y as i32, st.m as u8, st.d as u8, st.h as u8, st.min as u8, st.s as u8)
    }
}
