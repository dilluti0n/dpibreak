use std::error::Error;
use once_cell::sync::Lazy;
use windivert::{
    WinDivert,
    layer::NetworkLayer
};

pub static WINDIVERT_HANDLE: Lazy<WinDivert<NetworkLayer>> = Lazy::new(|| {
    use windivert::prelude::WinDivertFlags;

    println!("WINDIVERT_HANDLE constructed");

    match WinDivert::network("outbound and tcp.DstPort == 443",
                             0, WinDivertFlags::new()) {
        Ok(h) => h,
        Err(e) => { panic!("Err: {}", e); }
    }
});

pub fn bootstrap() -> Result<(), Box<dyn Error>> {
    Ok(())
}

pub fn cleanup() -> Result<(), Box<dyn Error>> {
    Ok(())
}

pub fn send_to_raw(pkt: &[u8]) {
    use windivert::*;

    let mut p = unsafe { packet::WinDivertPacket::<layer::NetworkLayer>::new(pkt.to_vec()) };

    p.address.set_outbound(true);
    p.address.set_ip_checksum(true);
    p.address.set_tcp_checksum(true);

    WINDIVERT_HANDLE.send(&p).unwrap();
}
