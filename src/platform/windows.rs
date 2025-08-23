use anyhow::Result;
use windivert::{
    WinDivert,
    layer::NetworkLayer
};
use std::sync::{atomic::Ordering, LazyLock};

pub static WINDIVERT_HANDLE: LazyLock<WinDivert<NetworkLayer>> = LazyLock::new(|| {
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
