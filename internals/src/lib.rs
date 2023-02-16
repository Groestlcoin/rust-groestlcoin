// Written by the Rust Bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! # Rust Groestlcoin Internal
//!
//! This crate is only meant to be used internally by crates in the
//! [rust-groestlcoin](https://github.com/Groestlcoin) ecosystem.
//!

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_cfg))]
// Coding conventions
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod hex;
pub mod macros;

/// Mainly reexports based on features.
pub(crate) mod prelude {
    #[cfg(feature = "alloc")]
    pub(crate) use alloc::string::String;
}
