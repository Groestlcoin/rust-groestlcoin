// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash types.
//!
//! This module defines types for hashes used throughout the library. These
//! types are needed in order to avoid mixing data of the same hash format
//! (e.g. `SHA256d`) but of different meaning (such as transaction id, block
//! hash).
//!

#[rustfmt::skip]
macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::consensus::Encodable for $hashtype {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, $crate::io::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $hashtype {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(r: &mut R) -> Result<Self, $crate::consensus::encode::Error> {
                use $crate::hashes::Hash;
                Ok(Self::from_inner(<<$hashtype as $crate::hashes::Hash>::Inner>::consensus_decode(r)?))
            }
        }
    };
}

#[rustfmt::skip]
macro_rules! impl_asref_push_bytes {
    ($($hashtype:ident),*) => {
        $(
            impl AsRef<$crate::blockdata::script::PushBytes> for $hashtype {
                fn as_ref(&self) -> &$crate::blockdata::script::PushBytes {
                    use $crate::hashes::Hash;
                    self.as_inner().as_ref()
                }
            }

            impl From<$hashtype> for $crate::blockdata::script::PushBytesBuf {
                fn from(hash: $hashtype) -> Self {
                    use $crate::hashes::Hash;
                    hash.as_inner().into()
                }
            }
        )*
    };
}

// newtypes module is solely here so we can rustfmt::skip.
pub use newtypes::*;

#[rustfmt::skip]
mod newtypes {
    use crate::hashes::Hash; // needed for From implimentations to convert hash types
    use crate::hashes::{sha256, sha256d, hash160, hash_newtype, groestld};

    hash_newtype! {
        /// A groestlcoin transaction hash/transaction ID.
        ///
        /// For compatibility with the existing Groestlcoin infrastructure and historical
        /// and current versions of the Groestlcoin Core software itself, this and
        /// other [`sha256d::Hash`] types, are serialized in reverse
        /// byte order when converted to a hex string via [`std::fmt::Display`] trait operations.
        /// See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
        pub struct Txid(sha256d::Hash);

        pub struct TxidInternal(sha256::Hash);
        impl From<TxidInternal> for Txid {
            fn from(txid: TxidInternal) -> Self {
                Self::from_inner(txid.into_inner())
            }
        }

        /// A bitcoin witness transaction ID.
        pub struct Wtxid(sha256d::Hash);

        pub struct WtxidInternal(sha256::Hash);
        impl From<WtxidInternal> for Wtxid {
            fn from(txid: WtxidInternal) -> Self {
                Self::from_inner(txid.into_inner())
            }
        }

        /// A bitcoin block hash.
        pub struct BlockHash(groestld::Hash);

        impl From<BlockHash> for sha256d::Hash {
            fn from(blockid: BlockHash) -> Self {
                Self::from_inner(blockid.into_inner())
            }
        }

        /// A hash of a public key.
        pub struct PubkeyHash(hash160::Hash);
        /// A hash of Bitcoin Script bytecode.
        pub struct ScriptHash(hash160::Hash);
        /// SegWit version of a public key hash.
        pub struct WPubkeyHash(hash160::Hash);
        /// SegWit version of a Bitcoin Script bytecode hash.
        pub struct WScriptHash(sha256::Hash);

        /// A hash of the Merkle tree branch or root for transactions
        pub struct TxMerkleNode(sha256d::Hash);
        /// A hash corresponding to the Merkle tree root for witness data
        pub struct WitnessMerkleNode(sha256d::Hash);
        /// A hash corresponding to the witness structure commitment in the coinbase transaction
        pub struct WitnessCommitment(sha256d::Hash);
        /// XpubIdentifier as defined in BIP-32.
        pub struct XpubIdentifier(hash160::Hash);

        /// Filter hash, as defined in BIP-157
        pub struct FilterHash(groestld::Hash);
        /// Filter header, as defined in BIP-157
        pub struct FilterHeader(groestld::Hash);
    }

    impl_hashencode!(Txid);
    impl_hashencode!(Wtxid);
    impl_hashencode!(BlockHash);

    impl_hashencode!(TxMerkleNode);
    impl_hashencode!(WitnessMerkleNode);

    impl_hashencode!(FilterHash);
    impl_hashencode!(FilterHeader);

    impl_asref_push_bytes!(PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash);
}
