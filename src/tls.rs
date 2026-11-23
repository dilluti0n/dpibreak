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

/// Same check as the kernel filter: a TLS handshake record (byte 0)
/// carrying a ClientHello (byte 5).
pub fn is_client_hello(payload: &[u8]) -> bool {
    payload.len() > 5 && payload[0] == 0x16 && payload[5] == 0x01
}

#[cfg(test)]
mod tests {
    use super::is_client_hello;

    #[test]
    fn client_hello_start() {
        // record: handshake, TLS 1.0, len; handshake: client_hello
        assert!(is_client_hello(&[0x16, 0x03, 0x01, 0x06, 0x80, 0x01, 0x00]));
    }

    #[test]
    fn not_client_hello() {
        assert!(!is_client_hello(&[]));
        assert!(!is_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x10]));
        // ServerHello
        assert!(!is_client_hello(&[0x16, 0x03, 0x03, 0x00, 0x10, 0x02]));
        // middle of a ClientHello (e.g. a key share), as left by
        // nf_queue() segmenting a GSO skb
        assert!(!is_client_hello(&[
            0x9c, 0x13, 0x9b, 0x16, 0xb0, 0x45, 0x52
        ]));
    }
}
