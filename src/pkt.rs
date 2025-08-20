use anyhow::Result;
use etherparse::{IpSlice, TcpSlice};

pub struct PktView<'a> {
    raw: &'a [u8],
    pub ip: IpSlice<'a>,
    pub tcp: TcpSlice<'a>
}

impl<'a> PktView<'a> {
    #[inline]
    pub fn from_raw(raw: &'a [u8]) -> Result<Self> {
        let ip = IpSlice::from_slice(raw)?;
        let tcp = TcpSlice::from_slice(ip.payload().payload)?;

        Ok(Self { raw, ip, tcp })
    }
}
