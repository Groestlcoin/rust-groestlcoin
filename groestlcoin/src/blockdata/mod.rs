// SPDX-License-Identifier: CC0-1.0

//! Groestlcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Groestlcoin system.
//!

pub mod block;
pub mod constants;
pub mod fee_rate;
pub mod locktime;
pub mod opcodes;
pub mod script;
pub mod transaction;
pub mod weight;
pub mod witness;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    fee_rate::FeeRate,
    weight::Weight
};
