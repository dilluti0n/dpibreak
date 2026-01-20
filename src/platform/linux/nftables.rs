// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::Ordering;
use anyhow::Result;

use crate::{log::LogLevel, log_println, opt};
use super::{exec_process, INJECT_MARK, IS_U32_SUPPORTED};

const DPIBREAK_TABLE: &str = "dpibreak";

/// Apply json format nft rules with `nft_command() -j -f -`.
fn apply_nft_rules(rule: &str) -> Result<()> {
    exec_process(&[crate::opt::nft_command(), "-j", "-f", "-"], Some(rule))
}

pub fn install_nft_rules() -> Result<()> {
    let rule = serde_json::json!(
        {
            "nftables": [
                {"add": {"table": {"family": "inet", "name": DPIBREAK_TABLE}}},
                // Clienthello
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "name": "OUTPUT",
                            "type": "filter",
                            "hook": "output",
                            "prio": 0,
                            "policy": "accept",
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "chain": "OUTPUT",
                            "expr": [
                                {
                                    "match": {
                                        "left": { "meta": { "key": "mark" }},
                                        "op": "==",
                                        "right": INJECT_MARK
                                    }
                                },
                                { "return": null }
                            ]
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "chain": "OUTPUT",
                            "expr": [
                                {
                                    "match": {
                                        "left": {"payload": { "protocol": "tcp", "field": "dport" }},
                                        "op": "==",
                                        "right": 443
                                    }
                                },
                                // TLS ContentType == 0x16 (Handshake)
                                {
                                    "match": {
                                        "left": { "payload": { "base": "ih", "offset": 0, "len": 8 } },
                                        "op": "==",
                                        "right": 0x16
                                    }
                                },
                                // HandshakeType == 0x01 (ClientHello)
                                {
                                    "match": {
                                        // Note: offset and len are both "bit" unit not byte
                                        "left": { "payload": { "base": "ih", "offset": 40, "len": 8 } },
                                        "op": "==",
                                        "right": 0x01
                                    }
                                },
                                {
                                    "queue": {
                                        "num": crate::opt::queue_num(),
                                        "flags": [ "bypass" ]
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        }
    );

    apply_nft_rules(&serde_json::to_string(&rule)?)?;
    log_println!(LogLevel::Info,
        "nftables: add chain OUTPUT, match ClientHello -> queue {})",
        opt::queue_num());
    log_println!(LogLevel::Debug, "nftables: rule json={}", rule);

    // clienthello filtered by nft
    IS_U32_SUPPORTED.store(true, Ordering::Relaxed);
    log_println!(LogLevel::Info, "nftables: create table inet {DPIBREAK_TABLE}");

    Ok(())
}

pub fn cleanup_nftables_rules() -> Result<()> {
    // nft delete table inet dpibreak
    let rule = serde_json::json!({
        "nftables": [
            {"delete": {"table": {"family": "inet", "name": DPIBREAK_TABLE}}}
        ]
    });
    apply_nft_rules(&serde_json::to_string(&rule)?)?;
    log_println!(LogLevel::Info, "cleanup: nftables: delete table inet {}", DPIBREAK_TABLE);

    Ok(())
}
