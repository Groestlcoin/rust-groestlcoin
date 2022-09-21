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

// newtypes module is solely here so we can rustfmt::skip.
pub use newtypes::*;

#[rustfmt::skip]
mod newtypes {
    use crate::hashes::Hash; // needed for From implimentations to convert hash types
    use crate::hashes::{sha256, sha256d, hash160, hash_newtype, groestld};

    hash_newtype!(
        Txid, sha256d::Hash, 32, doc="A groestlcoin transaction hash/transaction ID.

For compatibility with the existing Groestlcoin infrastructure and historical
and current versions of the Groestlcoin Core software itself, this and
other [`sha256d::Hash`] types, are serialized in reverse
byte order when converted to a hex string via [`std::fmt::Display`] trait operations.
See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
");
    hash_newtype!(TxidInternal, sha256::Hash, 32, doc="A groestlcoin transaction hash/transaction ID.");
    hash_newtype!(Wtxid, sha256d::Hash, 32, doc="A groestlcoin witness transaction ID.");
    hash_newtype!(WtxidInternal, sha256::Hash, 32, doc="A groestlcoin witness transaction ID.");
    hash_newtype!(BlockHash, groestld::Hash, 32, doc="A groestlcoin block hash.");
    hash_newtype!(Sighash, sha256::Hash, 32, doc="Hash of the transaction according to the signature algorithm");

    impl From<TxidInternal> for Txid {
        fn from(txid: TxidInternal) -> Self {
            Self::from_inner(txid.into_inner())
        }
    }

    impl From<WtxidInternal> for Wtxid {
        fn from(txid: WtxidInternal) -> Self {
            Self::from_inner(txid.into_inner())
        }
    }

    impl From<BlockHash> for sha256d::Hash {
        fn from(blockid: BlockHash) -> Self {
            Self::from_inner(blockid.into_inner())
        }
    }

    hash_newtype!(PubkeyHash, hash160::Hash, 20, doc="A hash of a public key.");
    hash_newtype!(ScriptHash, hash160::Hash, 20, doc="A hash of Groestlcoin Script bytecode.");
    hash_newtype!(WPubkeyHash, hash160::Hash, 20, doc="SegWit version of a public key hash.");
    hash_newtype!(WScriptHash, sha256::Hash, 32, doc="SegWit version of a Groestlcoin Script bytecode hash.");

    hash_newtype!(TxMerkleNode, sha256d::Hash, 32, doc="A hash of the Merkle tree branch or root for transactions");
    hash_newtype!(WitnessMerkleNode, sha256d::Hash, 32, doc="A hash corresponding to the Merkle tree root for witness data");
    hash_newtype!(WitnessCommitment, sha256d::Hash, 32, doc="A hash corresponding to the witness structure commitment in the coinbase transaction");
    hash_newtype!(XpubIdentifier, hash160::Hash, 20, doc="XpubIdentifier as defined in BIP-32.");

    hash_newtype!(FilterHash, groestld::Hash, 32, doc="Filter hash, as defined in BIP-157");
    hash_newtype!(FilterHeader, groestld::Hash, 32, doc="Filter header, as defined in BIP-157");

    impl_hashencode!(Txid);
    impl_hashencode!(Wtxid);
    impl_hashencode!(BlockHash);
    impl_hashencode!(Sighash);

    impl_hashencode!(TxMerkleNode);
    impl_hashencode!(WitnessMerkleNode);

    impl_hashencode!(FilterHash);
    impl_hashencode!(FilterHeader);
}