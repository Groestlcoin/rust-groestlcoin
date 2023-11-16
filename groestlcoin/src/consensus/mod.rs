// SPDX-License-Identifier: CC0-1.0

//! Groestlcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Groestlcoin consensus.
//!

pub mod encode;
pub mod params;
#[cfg(feature = "serde")]
pub mod serde;
#[cfg(feature = "groestlcoinconsensus")]
pub mod validation;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt},
    params::Params,
};

#[cfg(feature = "groestlcoinconsensus")]
#[doc(inline)]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};
