// SPDX-License-Identifier: CC0-1.0

//! Groestlcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Groestlcoin consensus.
//!

pub mod encode;
pub mod params;

pub use self::encode::{
    deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt,
};
pub use self::params::Params;

#[cfg(feature = "serde")]
pub mod serde;
