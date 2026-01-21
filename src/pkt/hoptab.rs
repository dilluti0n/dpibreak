// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct HopKey {
    hi: u64,
    lo: u64
}

impl HopKey {
    const ZERO: Self = Self { hi: 0, lo: 0 };

    #[inline]
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                // ::ffff:a.b.c.d  (IPv4-mapped IPv6)
                let v4u = u32::from(v4) as u64;
                Self { hi: 0, lo: (0xFFFFu64 << 32) | v4u }
            }
            IpAddr::V6(v6) => {
                let b = v6.octets();
                let hi = u64::from_be_bytes(b[0..8].try_into().unwrap());
                let lo = u64::from_be_bytes(b[8..16].try_into().unwrap());
                Self { hi, lo }
            }
        }
    }
}

const CAP: usize = 1 << 6;      // 64

#[derive(Clone, Copy)]
struct HopTabEntry {
    key: HopKey,  // IP
    meta: u64,    // [RESERVED(32)|TS(16)|HOP(8)|STATE(8)]
}

impl HopTabEntry {
    const ST_EMPTY: u8 = 0;

    pub const ST_OCCUPIED: u8 = 1 << 0;
    pub const ST_TOUCHED: u8 = 1 << 1;

    const EMPTY: Self = Self { key: HopKey::ZERO, meta: Self::ST_EMPTY as u64};

    const S_STATE: usize = 0;
    const S_HOP: usize = 8;
    const S_TS: usize = 16;

    #[inline]
    fn key(&self) -> HopKey {
        self.key
    }

    #[inline]
    fn new(key: HopKey, ts: u16, hop: u8) -> Self {
        Self {
            key: key,
            meta: ((ts as u64) << Self::S_TS)
                | ((hop as u64) << Self::S_HOP)
                | ((Self::ST_OCCUPIED as u64) << Self::S_STATE)
        }
    }

    #[inline]
    fn hop(&self) -> u8 {
        (self.meta >> Self::S_HOP) as u8
    }

    #[inline]
    fn state(&self) -> u8 {
        (self.meta >> Self::S_STATE) as u8
    }

    #[inline]
    fn has(&self, mask: u8) -> bool {
        (self.state() & mask) == mask
    }

    #[inline]
    fn touch(&mut self) {
        self.meta |= Self::ST_TOUCHED as u64;
    }

    #[inline]
    fn ts(&self) -> u16 {
        (self.meta >> Self::S_TS) as u16
    }

    #[inline]
    fn can_evict(&self) -> bool {
        !self.has(Self::ST_OCCUPIED) || self.has(Self::ST_TOUCHED)
    }
}

#[derive(Debug, Clone)]
pub enum HopLookupError {
    NotFound { ip: IpAddr },
}

impl fmt::Display for HopLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HopLookupError::NotFound { ip } => write!(f, "hop not found for {ip}"),
        }
    }
}

impl std::error::Error for HopLookupError {}

pub type HopResult<T> = std::result::Result<T, HopLookupError>;

struct HopTab<const CAP: usize> {
    entries: Box<[HopTabEntry; CAP]>,
    now: u16,
}

#[inline]
fn hash(key: HopKey) -> usize {
    let mut x = key.hi ^ key.lo.rotate_left(13);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x as usize
}

trait HashIdx {
    fn to_idx<const CAP: usize>(self) -> usize;
}

impl HashIdx for usize {
    #[inline]
    fn to_idx<const CAP: usize>(self) -> usize {
        self & (CAP - 1)
    }
}

impl<const CAP: usize> HopTab<CAP> {
    fn new() -> Self {
        Self {
            entries: Box::new([HopTabEntry::EMPTY; CAP]),
            now: 0,
        }
    }

    #[inline]
    fn age(&self, idx: usize) -> u16 {
        self.now.wrapping_sub(self.entries[idx].ts())
    }

    #[inline]
    fn is_stale(&self, idx: usize) -> bool {
        self.age(idx) > 64
    }

    #[inline]
    fn update(&mut self, idx: usize, entry: HopTabEntry) {
        self.entries[idx] = entry;
        self.now = self.now.wrapping_add(1);
    }

    fn put(&mut self, ip: IpAddr, hop: u8) {
        let key = HopKey::from_ip(ip);
        let entry = HopTabEntry::new(key, self.now, hop);

        let start = hash(key).to_idx::<CAP>();

        for step in 0..CAP {
            let idx = (start + step).to_idx::<CAP>();
            let e = self.entries[idx];

            if e.can_evict() || e.key() == key || self.is_stale(idx) {
                self.update(idx, entry);
                return;
            }

            let prio = self.evict_priority(&e);

            if prio > victim.1 {
                victim = (idx, prio);

                if prio == EvictPriority::Empty {
                    #[cfg(debug_assertions)]
                    log_println!(LogLevel::Debug,
                                 "HopTab::put: hit empty {}; {:#?}", victim.0, entry);
                    break;      // linear probing; there is no key here
                }
            }
        }

        if victim.1 > EvictPriority::None {
            self.update(victim.0, entry);
            #[cfg(debug_assertions)]
            log_println!(LogLevel::Debug, "HopTab::put: update {} to {:#?}", victim.0, entry);
        } else {
            log_println!(LogLevel::Warning, "HopTab::put: update fail: corrupted; {:#?}", entry);
        }
    }

    fn find_hop(&mut self, ip: IpAddr) -> HopResult<u8> {
        let key = HopKey::from_ip(ip);
        let start = hash(key).to_idx::<CAP>();

        for step in 0..CAP {
            let idx = (start + step).to_idx::<CAP>();
            let e = self.entries[idx];

            if e.has(HopTabEntry::ST_EMPTY) {
                continue;
            }

            if e.key() == key && !self.is_stale(idx) {
                self.entries[idx].touch();
                return Ok(e.hop());
            }
        }

        Err(HopLookupError::NotFound { ip })
    }
}

static H_TAB: OnceLock<Mutex<HopTab<CAP>>> = OnceLock::new();

#[inline]
fn htab() -> std::sync::MutexGuard<'static, HopTab<CAP>> {
    H_TAB.get_or_init(|| Mutex::new(HopTab::new()))
        .lock()
        .unwrap()
}

pub fn put_0(ip: IpAddr, hop: u8) {
    htab().put(ip, hop)
}

pub fn find_0(ip: IpAddr) -> HopResult<u8> {
    htab().find_hop(ip)
}
