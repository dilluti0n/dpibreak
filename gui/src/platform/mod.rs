// SPDX-License-Identifier: GPL-3.0-or-later

//! Platform backends. Each provides the same modules (`bundle`, `probe`,
//! `process`, `service`) and the same free functions and constants, so
//! the dashboard, theme and settings stay shared.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// How a status chip is colored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Neutral,
}

/// A platform specific chip for the Protection card.
#[derive(Clone, Debug)]
pub struct Chip {
    pub text: String,
    pub tone: Tone,
    pub hover: String,
}
