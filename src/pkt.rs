// Copyright 2025 Dillution <https://github.com/dilluti0n>.
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
use etherparse::{IpSlice, TcpSlice};

pub struct PktView<'a> {
    pub ip: IpSlice<'a>,
    pub tcp: TcpSlice<'a>
}

impl<'a> PktView<'a> {
    #[inline]
    pub fn from_raw(raw: &'a [u8]) -> Result<Self> {
        let ip = IpSlice::from_slice(raw)?;
        let tcp = TcpSlice::from_slice(ip.payload().payload)?;

        Ok(Self { ip, tcp })
    }
}
