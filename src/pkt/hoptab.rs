// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Linear probing hash table for ip-hop cache
//!
//! On inbound SYN/ACK (src port 443) from a server, infer the hop
//! count from the observed TTL via `crate::pkt::fake::infer_hops` and
//! store it with [`HopTab::put`]. Later, when sending a fake
//! ClientHello, look up the hop count by destination IP
//! [`HopTab::find_hop`] to automatically choose an appropriate TTL.
//!
//! One could consider keeping a global variable (like `current_hop`),
//! loading it when a SYN/ACK arrives, and reading it when needed. The
//! problem is that, before the ClientHello is sent after that SYN/ACK
//! (i.e., in between), a SYN/ACK from a different server may
//! arrive. To handle this, the (ip, hop) pair must be stored in an
//! appropriate data structure and looked up later.
//!
//! [`HopTab`] has capacity [`CAP`], which means that if at least
//! [`CAP`] SYN/ACKs arrive from distinct servers before the first
//! ClientHello is sent, [`HopLookupError::NotFound`] will inevitably
//! occur. (Given the size of [`CAP`], this is extremely unlikely.)
//! Also, after an entry is inserted, if [`HopTab::update`] runs at
//! least [`HopTab::STALE_AGE`] times, the entry is marked stale and
//! becomes evictable, so once the number of updates reaches
//! [`HopTab::STALE_AGE`] or more, there is a chance that
//! [`HopLookupError::NotFound`] occurs. Other than these cases, it
//! will not occur.


use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::log_println;
use crate::log::LogLevel;

/// Size of [`HopTab`]
const CAP: usize = 1 << 7;      // 128

/// 128-bit (IPv6-shaped) unified IP key for [`HopTab`] lookups (IPv4
/// stored as ::ffff:a.b.c.d).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct HopKey {
    hi: u64,
    lo: u64
}

impl HopKey {
    const ZERO: Self = Self { hi: 0, lo: 0 };

    #[inline]
    fn from_ipaddr(ip: IpAddr) -> Self {
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

    #[inline]
    fn to_ipaddr(self) -> IpAddr {
        // ::ffff:a.b.c.d (IPv4-mapped IPv6)
        if self.hi == 0 && (self.lo >> 32) == 0x0000_FFFF {
            let v4 = (self.lo & 0xFFFF_FFFF) as u32;
            return IpAddr::V4(Ipv4Addr::from(v4));
        }

        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.hi.to_be_bytes());
        b[8..16].copy_from_slice(&self.lo.to_be_bytes());
        IpAddr::V6(Ipv6Addr::from(b))
    }
}

#[derive(Clone, Copy)]
struct HopTabEntry {
    key: HopKey,

    /// [RESERVED(32) | TS(16) | HOP(8) | STATE(8)]
    ///   * TS: timestamp snapshot (see [`HopTab::now`])
    ///   * HOP: stored hop count
    ///   * STATE: [`Self::ST_OCCUPIED`], [`Self::ST_TOUCHED`]
    meta: u64,
}

impl HopTabEntry {
    /// For internal use; Do not use it globally
    const ST_EMPTY: u8 = 0;
    const ST_OCCUPIED: u8 = 1 << 0;

    /// Entry has been touched (i.e., consumed by [`HopTab::find_hop`]
    /// at least once).
    ///
    /// Note: "touched" does not mean "recently used, keep it". It
    /// means the entry already served its purpose (consumed for Fake
    /// ClientHello TTL), so it is more eligible for eviction under
    /// pressure than a fresh, untouched entry.
    const ST_TOUCHED: u8 = 1 << 1;

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
}

impl fmt::Debug for HopTabEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = self.key.to_ipaddr();
        let state = self.state();
        let hop = self.hop();
        let ts = self.ts();

        write!(
            f,
            "HopTabEntry{{ ip={}, state=0x{:02x}, hop={}, ts={}, meta=0x{:016x} }}",
            ip, state, hop, ts, self.meta
        )
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

    /// Logical tick counter.
    ///
    /// Increments on every successful [`Self::update`]
    /// (put/overwrite) and wraps via [`u16::wrapping_add`]. It is
    /// ensured that at least [`CAP`] - [`Self::STALE_AGE`] entries
    /// evictable. (i.e. [`HopTab`] not become corrupted.)
    now: u16,
}

/// Non-cryptographic hash using SplitMix64-style finalizer
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
    /// `CAP` must be a power of two (we index via `hash & (CAP-1)`).
    fn to_idx<const CAP: usize>(self) -> usize;
}

impl HashIdx for usize {
    #[inline]
    fn to_idx<const CAP: usize>(self) -> usize {
        self & (CAP - 1)
    }
}

#[derive(PartialEq, PartialOrd, Clone, Copy)]
enum EvictPriority {
    /// Occupied && fresh && untouched
    None = 0,

    /// Already consumed
    Touched = 1,
    Stale = 2,
    Empty = 3,

    /// Same key occers
    MustUpdate = 4,
}

impl<const CAP: usize> HopTab<CAP> {
    const ASSERT_CAP_POW2: () = {
        assert!(CAP.is_power_of_two());
    };

    /// To avoid the edge case where all entries become non-stale,
    /// [`Self::STALE_AGE`] must be smaller than [`CAP`].
    const STALE_AGE: usize = CAP >> 1; // 64

    fn new() -> Self {
        _ = Self::ASSERT_CAP_POW2;

        Self {
            entries: Box::new([HopTabEntry::EMPTY; CAP]),
            now: 0,
        }
    }

    #[inline]
    fn age(&self, entry: &HopTabEntry) -> u16 {
        // Since we use u16 with wrapping_sub, the age calculation remains
        // correct even when `self.now` overflows and wraps around to zero.
        // This holds true as long as the temporal distance between
        // `entry.ts()` and `self.now` does not exceed 2^15 (32,768).
        // Given that STALE_AGE (64) << 2^15, the "stale" judgment is
        // always mathematically sound.
        self.now.wrapping_sub(entry.ts())
    }

    #[inline]
    fn is_stale(&self, entry: &HopTabEntry) -> bool {
        self.age(entry) >= Self::STALE_AGE as u16
    }

    #[inline]
    fn update(&mut self, idx: usize, new: HopTabEntry) {
        self.entries[idx] = new;
        self.now = self.now.wrapping_add(1);
    }

    #[inline]
    fn evict_priority(&self, entry: &HopTabEntry) -> EvictPriority {
        if !entry.has(HopTabEntry::ST_OCCUPIED) {
            EvictPriority::Empty
        } else if self.is_stale(entry) {
            EvictPriority::Stale
        } else if entry.has(HopTabEntry::ST_TOUCHED) {
            EvictPriority::Touched
        } else {
            EvictPriority::None
        }
    }

    fn put(&mut self, ip: IpAddr, hop: u8) {
        let key = HopKey::from_ipaddr(ip);
        let entry = HopTabEntry::new(key, self.now, hop);
        let start = hash(key).to_idx::<CAP>();

        let mut victim = (0, EvictPriority::None); // (idx, priority)

        // Key must be unique in the table
        for step in 0..CAP {
            let idx = (start + step).to_idx::<CAP>();
            let e = self.entries[idx];

            // Hit; must update same key (hop could be changed)
            if e.key() == key && e.has(HopTabEntry::ST_OCCUPIED) {
                victim = (idx, EvictPriority::MustUpdate);
                #[cfg(debug_assertions)]
                log_println!(LogLevel::Debug, "HopTab::put: hit {}; {:#?}", victim.0, entry);
                break;
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
            log_println!(LogLevel::Error, "HopTab::put: update fail: corrupted; {:#?}", entry);
        }
    }

    fn find_hop(&mut self, ip: IpAddr) -> HopResult<u8> {
        let key = HopKey::from_ipaddr(ip);
        let start = hash(key).to_idx::<CAP>();

        for step in 0..CAP {
            let idx = (start + step).to_idx::<CAP>();
            let e = self.entries[idx];

            if !e.has(HopTabEntry::ST_OCCUPIED) {
                break;      // linear probing; there is no key here
            }

            if e.key() == key {
                self.entries[idx].touch();

                #[cfg(debug_assertions)]
                log_println!(LogLevel::Debug, "HopTab::find_hop: found {idx}; {:#?}", e);
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
