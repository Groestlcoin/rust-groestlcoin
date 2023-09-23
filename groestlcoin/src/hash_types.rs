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
                Ok(Self::from_byte_array(<<$hashtype as $crate::hashes::Hash>::Bytes>::consensus_decode(r)?))
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
                    self.as_byte_array().into()
                }
            }

            impl From<$hashtype> for $crate::blockdata::script::PushBytesBuf {
                fn from(hash: $hashtype) -> Self {
                    use $crate::hashes::Hash;
                    hash.as_byte_array().into()
                }
            }
        )*
    };
}
pub(crate) use impl_asref_push_bytes;
// newtypes module is solely here so we can rustfmt::skip.
pub use newtypes::*;

#[rustfmt::skip]
mod newtypes {
    use hashes::Hash; // needed for From implimentations to convert hash types
    use hashes::{sha256, sha256d, hash_newtype, groestld};

    hash_newtype! {
        /// A groestlcoin transaction hash/transaction ID.
        ///
        /// For compatibility with the existing Groestlcoin infrastructure and historical
        /// and current versions of the Groestlcoin Core software itself, this and
        /// other [`sha256d::Hash`] types, are serialized in reverse
        /// byte order when converted to a hex string via [`std::fmt::Display`] trait operations.
        /// See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
        pub struct Txid(sha256d::Hash);
        /// use single sha256 for transactions
        pub struct TxidInternal(sha256::Hash);

        /// A bitcoin witness transaction ID.
        pub struct Wtxid(sha256d::Hash);
        /// use single sha256 for transactions
        pub struct WtxidInternal(sha256::Hash);

        /// A bitcoin block hash.
        pub struct BlockHash(groestld::Hash);

        /// A hash of the Merkle tree branch or root for transactions
        pub struct TxMerkleNode(sha256d::Hash);
        /// A hash corresponding to the Merkle tree root for witness data
        pub struct WitnessMerkleNode(sha256d::Hash);
        /// A hash corresponding to the witness structure commitment in the coinbase transaction
        pub struct WitnessCommitment(sha256d::Hash);

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

    impl From<TxidInternal> for Txid {
        fn from(txid: TxidInternal) -> Self {
            Self::from(sha256d::Hash::from_byte_array(txid.to_raw_hash().to_byte_array()))
        }
    }

    impl From<WtxidInternal> for Wtxid {
        fn from(txid: WtxidInternal) -> Self {
            Self::from(sha256d::Hash::from_byte_array(txid.to_raw_hash().to_byte_array()))
        }
    }

    impl From<BlockHash> for sha256d::Hash {
        fn from(blockid: BlockHash) -> Self {
            sha256d::Hash::from_byte_array(blockid.to_raw_hash().to_byte_array())
        }
    }
}
