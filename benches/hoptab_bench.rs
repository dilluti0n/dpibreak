// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "bench")]

use std::net::{IpAddr, Ipv4Addr};
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, BatchSize, Throughput};
use std::hint::black_box;

#[macro_use]
#[path = "../src/log.rs"]
mod log;

#[path = "../src/opt.rs"]
mod opt;

#[path = "../src/pkt/hoptab.rs"]
pub mod hoptab;

use hoptab::{put, find, reset};

fn prepare_data(count: usize) -> Vec<(IpAddr, u8)> {
    (0..count as u32)
        .map(|i| (IpAddr::V4(Ipv4Addr::from(i)), (i % 255) as u8))
        .collect()
}

fn bench_hoptab_operations(c: &mut Criterion) {
    let dataset = prepare_data(1024);
    let mut group = c.benchmark_group("HopTab_Core");

    let (test_ip, test_hop) = dataset[0];
    reset();
    put(test_ip, test_hop);

    group.bench_function("find_hop_hit", |b| {
        b.iter(|| {
            _ = find(black_box(test_ip));
        })
    });
    reset();

    let mut i = 0;
    group.bench_function("put_and_evict", |b| {
        b.iter(|| {
            let (ip, hop) = dataset[i % dataset.len()];
            put(black_box(ip), black_box(hop));
            i += 1;
        })
    });

    group.finish();
}

#[inline]
fn xorshift64(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

pub fn bench_hoptab_usecase(c: &mut Criterion) {
    let dataset = prepare_data(1024);

    let mut group = c.benchmark_group("HopTab_Usecase");
    let mut seed = 0xC0FFEE_u64;

    for &noise in &[0usize, 1, 4, 16, 64, 128] {
        reset();

        // put origin
        let i = (xorshift64(&mut seed) as usize) % dataset.len();
        let (ip, hop) = dataset[i];
        put(black_box(ip), black_box(hop));

        // noise: other SYN/ACK
        for _ in 0..noise {
            let j = (xorshift64(&mut seed) as usize) % dataset.len();
            let (ip2, hop2) = dataset[j];
            put(black_box(ip2), black_box(hop2));
        }

        group.bench_function(
            BenchmarkId::new("find_between_noise", noise),
            |b| {
                b.iter(|| {
                    _ = black_box(find(black_box(ip)));
                })
            });
    }

    group.finish();
}

criterion_group!(benches, bench_hoptab_operations, bench_hoptab_usecase);
criterion_main!(benches);
