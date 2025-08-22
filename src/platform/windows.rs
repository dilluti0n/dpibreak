use anyhow::Result;
use once_cell::sync::Lazy;
use windivert::{
    WinDivert,
    layer::NetworkLayer
};
use std::sync::Arc;
use crate::Ordering;
use std::sync::atomic::AtomicBool;

pub static WINDIVERT_HANDLE: Lazy<WinDivert<NetworkLayer>> = Lazy::new(|| {
    use windivert::*;

    #[cfg(debug_assertions)]
    println!("WINDIVERT_HANDLE constructed");

    match WinDivert::network("outbound and tcp and tcp.DstPort == 443",
                             0, prelude::WinDivertFlags::new()) {
        Ok(h) => h,
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

pub fn run(running: Arc<AtomicBool>) -> Result<()> {
    use crate::handle_packet;

    let mut buf = vec![0u8; 65536];

    while running.load(Ordering::SeqCst) {
        let pkt = WINDIVERT_HANDLE.recv(Some(&mut buf))?;

        handle_packet!(
            &pkt.data,
            handled => {},
            rejected => { WINDIVERT_HANDLE.send(&pkt)?; }
        );
    }

    Ok(())
}
