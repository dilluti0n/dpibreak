use anyhow::Result;
use windivert::{
    WinDivert,
    layer::NetworkLayer
};
use std::sync::{atomic::Ordering, LazyLock};
use crate::{log, log_println};

pub static WINDIVERT_HANDLE: LazyLock<WinDivert<NetworkLayer>> = LazyLock::new(|| {
    use windivert::*;

    const FILTER: &str = "outbound and tcp and tcp.DstPort == 443";

    match WinDivert::network(FILTER, 0, prelude::WinDivertFlags::new()) {
        Ok(h) => {
            log_println!(log::LogLevel::Info, "windivert: HANDLE constructed for {}", FILTER);

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
    use crate::{handle_packet, RUNNING};

    let mut buf = vec![0u8; 65536];

    while RUNNING.load(Ordering::SeqCst) {
        let pkt = WINDIVERT_HANDLE.recv(Some(&mut buf))?;

        handle_packet!(
            &pkt.data,
            handled => {},
            rejected => { WINDIVERT_HANDLE.send(&pkt)?; }
        );
    }

    Ok(())
}
