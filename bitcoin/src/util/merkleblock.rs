// Written by John L. Jegutanis
// SPDX-License-Identifier: CC0-1.0
//
// This code was translated from merkleblock.h, merkleblock.cpp and pmt_tests.cpp
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// SPDX-License-Identifier: MIT

//! Merkle Block and Partial Merkle Tree.
//!
//! Support proofs that transaction(s) belong to a block.
//!
//! # Examples
//!
//! ```rust
//! use groestlcoin::hash_types::Txid;
//! use groestlcoin::hashes::hex::FromHex;
//! use groestlcoin::{Block, MerkleBlock};
//!
//! // Get the proof from a groestlcoind by running in the terminal:
//! // $ TXID="d0c54928d8ace117254e2786c308632976f0f612d62dd0f0a280b9e1db6e3dd7"
//! // $ groestlcoin-cli gettxoutproof [\"$TXID\"]
//! let mb_bytes = Vec::from_hex("0000002063280a27a86a2bf9c5e3ba174690c316bdbc12945a73a863650d00000\
//! 0000000d4aefe8dcb716400868f87660cc7e59d2d5372121240801f5428a43ae735f66247af00625c331b1a3a8aee65\
//! 0400000003b0e1f8e96bbde499c4564a1442643b203794e432c2c4ecfaaaf066b7772e3768d73d6edbe1b980a2f0d02\
//! dd612f6f076296308c386274e2517e1acd82849c5d01cd7ef8c0ab37f5ea8ecc95c9db52e406e4a0fde8741ea8ce4b7\
//! 8224aa1e6a1c010b").unwrap();
//! let mb: MerkleBlock = groestlcoin::consensus::deserialize(&mb_bytes).unwrap();
//!
//! // Authenticate and extract matched transaction ids
//! let mut matches: Vec<Txid> = vec![];
//! let mut index: Vec<u32> = vec![];
//! assert!(mb.extract_matches(&mut matches, &mut index).is_ok());
//! assert_eq!(1, matches.len());
//! assert_eq!(
//!     Txid::from_hex(
//!         "d0c54928d8ace117254e2786c308632976f0f612d62dd0f0a280b9e1db6e3dd7").unwrap(),
//!     matches[0]
//! );
//! assert_eq!(1, index.len());
//! assert_eq!(1, index[0]);
//! ```

use core::fmt;

use crate::prelude::*;

use crate::io;

use crate::hashes::Hash;
use crate::hash_types::{Txid, TxMerkleNode};

use crate::blockdata::transaction::Transaction;
use crate::blockdata::constants::{MAX_BLOCK_WEIGHT, MIN_TRANSACTION_WEIGHT};
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::util::merkleblock::MerkleBlockError::*;
use crate::{Block, BlockHeader};

/// An error when verifying the merkle block.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum MerkleBlockError {
    /// Merkle root in the header doesn't match to the root calculated from partial merkle tree.
    MerkleRootMismatch,
    /// Partial merkle tree contains no transactions.
    NoTransactions,
    /// There are too many transactions.
    TooManyTransactions,
    /// General format error.
    BadFormat(String),
}

impl fmt::Display for MerkleBlockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MerkleBlockError::*;

        match *self {
            MerkleRootMismatch => write!(f, "merkle header root doesn't match to the root calculated from the partial merkle tree"),
            NoTransactions => write!(f, "partial merkle tree contains no transactions"),
            TooManyTransactions => write!(f, "too many transactions"),
            BadFormat(ref s) => write!(f, "general format error: {}", s),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for MerkleBlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::MerkleBlockError::*;

        match *self {
            MerkleRootMismatch | NoTransactions | TooManyTransactions | BadFormat(_) => None,
        }
    }
}

/// Data structure that represents a partial merkle tree.
///
/// It represents a subset of the txid's of a known block, in a way that
/// allows recovery of the list of txid's and the merkle root, in an
/// authenticated way.
///
/// The encoding works as follows: we traverse the tree in depth-first order,
/// storing a bit for each traversed node, signifying whether the node is the
/// parent of at least one matched leaf txid (or a matched txid itself). In
/// case we are at the leaf level, or this bit is 0, its merkle node hash is
/// stored, and its children are not explored further. Otherwise, no hash is
/// stored, but we recurse into both (or the only) child branch. During
/// decoding, the same depth-first traversal is performed, consuming bits and
/// hashes as they written during encoding.
///
/// The serialization is fixed and provides a hard guarantee about the
/// encoded size:
///
///   SIZE <= 10 + ceil(32.25*N)
///
/// Where N represents the number of leaf nodes of the partial tree. N itself
/// is bounded by:
///
///   N <= total_transactions
///   N <= 1 + matched_transactions*tree_height
///
/// The serialization format:
///  - uint32     total_transactions (4 bytes)
///  - varint     number of hashes   (1-3 bytes)
///  - uint256[]  hashes in depth-first order (<= 32*N bytes)
///  - varint     number of bytes of flag bits (1-3 bytes)
///  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (<= 2*N-1 bits)
/// The size constraints follow from this.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PartialMerkleTree {
    /// The total number of transactions in the block
    num_transactions: u32,
    /// node-is-parent-of-matched-txid bits
    bits: Vec<bool>,
    /// Transaction ids and internal hashes
    hashes: Vec<TxMerkleNode>,
}

impl PartialMerkleTree {
    /// Returns the total number of transactions in the block.
    pub fn num_transactions(&self) -> u32 {
        self.num_transactions
    }

    /// Returns the node-is-parent-of-matched-txid bits of the partial merkle tree.
    pub fn bits(&self) -> &Vec<bool> {
        &self.bits
    }

    /// Returns the transaction ids and internal hashes of the partial merkle tree.
    pub fn hashes(&self) -> &Vec<TxMerkleNode> {
        &self.hashes
    }

    /// Construct a partial merkle tree
    /// The `txids` are the transaction hashes of the block and the `matches` is the contains flags
    /// wherever a tx hash should be included in the proof.
    ///
    /// Panics when `txids` is empty or when `matches` has a different length
    ///
    /// # Examples
    ///
    /// ```rust
    /// use groestlcoin::hash_types::Txid;
    /// use groestlcoin::hashes::hex::FromHex;
    /// use groestlcoin::util::merkleblock::PartialMerkleTree;
    ///
    /// // Block 80000
    /// let txids: Vec<Txid> = [
    ///     "c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25",
    ///     "5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2",
    /// ]
    /// .iter()
    /// .map(|hex| Txid::from_hex(hex).unwrap())
    /// .collect();
    ///
    /// // Select the second transaction
    /// let matches = vec![false, true];
    /// let tree = PartialMerkleTree::from_txids(&txids, &matches);
    /// assert!(tree.extract_matches(&mut vec![], &mut vec![]).is_ok());
    /// ```
    pub fn from_txids(txids: &[Txid], matches: &[bool]) -> Self {
        // We can never have zero txs in a merkle block, we always need the coinbase tx
        assert_ne!(txids.len(), 0);
        assert_eq!(txids.len(), matches.len());

        let mut pmt = PartialMerkleTree {
            num_transactions: txids.len() as u32,
            bits: Vec::with_capacity(txids.len()),
            hashes: vec![],
        };
        // calculate height of tree
        let mut height = 0;
        while pmt.calc_tree_width(height) > 1 {
            height += 1;
        }
        // traverse the partial tree
        pmt.traverse_and_build(height, 0, txids, matches);
        pmt
    }

    /// Extract the matching txid's represented by this partial merkle tree
    /// and their respective indices within the partial tree.
    /// returns the merkle root, or error in case of failure
    pub fn extract_matches(
        &self,
        matches: &mut Vec<Txid>,
        indexes: &mut Vec<u32>,
    ) -> Result<TxMerkleNode, MerkleBlockError> {
        matches.clear();
        indexes.clear();
        // An empty set will not work
        if self.num_transactions == 0 {
            return Err(NoTransactions);
        };
        // check for excessively high numbers of transactions
        if self.num_transactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT {
            return Err(TooManyTransactions);
        }
        // there can never be more hashes provided than one for every txid
        if self.hashes.len() as u32 > self.num_transactions {
            return Err(BadFormat("Proof contains more hashes than transactions".to_owned()));
        };
        // there must be at least one bit per node in the partial tree, and at least one node per hash
        if self.bits.len() < self.hashes.len() {
            return Err(BadFormat("Proof contains less bits than hashes".to_owned()));
        };
        // calculate height of tree
        let mut height = 0;
        while self.calc_tree_width(height) > 1 {
            height += 1;
        }
        // traverse the partial tree
        let mut bits_used = 0u32;
        let mut hash_used = 0u32;
        let hash_merkle_root =
            self.traverse_and_extract(height, 0, &mut bits_used, &mut hash_used, matches, indexes)?;
        // Verify that all bits were consumed (except for the padding caused by
        // serializing it as a byte sequence)
        if (bits_used + 7) / 8 != (self.bits.len() as u32 + 7) / 8 {
            return Err(BadFormat("Not all bit were consumed".to_owned()));
        }
        // Verify that all hashes were consumed
        if hash_used != self.hashes.len() as u32 {
            return Err(BadFormat("Not all hashes were consumed".to_owned()));
        }
        Ok(TxMerkleNode::from_inner(hash_merkle_root.into_inner()))
    }

    /// Helper function to efficiently calculate the number of nodes at given height
    /// in the merkle tree
    #[inline]
    fn calc_tree_width(&self, height: u32) -> u32 {
        (self.num_transactions + (1 << height) - 1) >> height
    }

    /// Calculate the hash of a node in the merkle tree (at leaf level: the txid's themselves)
    fn calc_hash(&self, height: u32, pos: u32, txids: &[Txid]) -> TxMerkleNode {
        if height == 0 {
            // Hash at height 0 is the txid itself
            TxMerkleNode::from_inner(txids[pos as usize].into_inner())
        } else {
            // Calculate left hash
            let left = self.calc_hash(height - 1, pos * 2, txids);
            // Calculate right hash if not beyond the end of the array - copy left hash otherwise
            let right = if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.calc_hash(height - 1, pos * 2 + 1, txids)
            } else {
                left
            };
            // Combine subhashes
            PartialMerkleTree::parent_hash(left, right)
        }
    }

    /// Recursive function that traverses tree nodes, storing the data as bits and hashes
    fn traverse_and_build(&mut self, height: u32, pos: u32, txids: &[Txid], matches: &[bool]) {
        // Determine whether this node is the parent of at least one matched txid
        let mut parent_of_match = false;
        let mut p = pos << height;
        while p < (pos + 1) << height && p < self.num_transactions {
            parent_of_match |= matches[p as usize];
            p += 1;
        }
        // Store as flag bit
        self.bits.push(parent_of_match);

        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, store hash and stop
            let hash = self.calc_hash(height, pos, txids);
            self.hashes.push(hash);
        } else {
            // Otherwise, don't store any hash, but descend into the subtrees
            self.traverse_and_build(height - 1, pos * 2, txids, matches);
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.traverse_and_build(height - 1, pos * 2 + 1, txids, matches);
            }
        }
    }

    /// Recursive function that traverses tree nodes, consuming the bits and hashes produced by
    /// TraverseAndBuild. It returns the hash of the respective node and its respective index.
    fn traverse_and_extract(
        &self,
        height: u32,
        pos: u32,
        bits_used: &mut u32,
        hash_used: &mut u32,
        matches: &mut Vec<Txid>,
        indexes: &mut Vec<u32>,
    ) -> Result<TxMerkleNode, MerkleBlockError> {
        if *bits_used as usize >= self.bits.len() {
            return Err(BadFormat("Overflowed the bits array".to_owned()));
        }
        let parent_of_match = self.bits[*bits_used as usize];
        *bits_used += 1;
        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, use stored hash and do not descend
            if *hash_used as usize >= self.hashes.len() {
                return Err(BadFormat("Overflowed the hash array".to_owned()));
            }
            let hash = self.hashes[*hash_used as usize];
            *hash_used += 1;
            if height == 0 && parent_of_match {
                // in case of height 0, we have a matched txid
                matches.push(Txid::from_inner(hash.into_inner()));
                indexes.push(pos);
            }
            Ok(hash)
        } else {
            // otherwise, descend into the subtrees to extract matched txids and hashes
            let left = self.traverse_and_extract(
                height - 1,
                pos * 2,
                bits_used,
                hash_used,
                matches,
                indexes,
            )?;
            let right;
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                right = self.traverse_and_extract(
                    height - 1,
                    pos * 2 + 1,
                    bits_used,
                    hash_used,
                    matches,
                    indexes,
                )?;
                if right == left {
                    // The left and right branches should never be identical, as the transaction
                    // hashes covered by them must each be unique.
                    return Err(BadFormat("Found identical transaction hashes".to_owned()));
                }
            } else {
                right = left;
            }
            // and combine them before returning
            Ok(PartialMerkleTree::parent_hash(left, right))
        }
    }

    /// Helper method to produce SHA256D(left + right)
    fn parent_hash(left: TxMerkleNode, right: TxMerkleNode) -> TxMerkleNode {
        let mut encoder = TxMerkleNode::engine();
        left.consensus_encode(&mut encoder).expect("engines don't error");
        right.consensus_encode(&mut encoder).expect("engines don't error");
        TxMerkleNode::from_engine(encoder)
    }
}

impl Encodable for PartialMerkleTree {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let ret = self.num_transactions.consensus_encode(w)?
            + self.hashes.consensus_encode(w)?;
        let mut bytes: Vec<u8> = vec![0; (self.bits.len() + 7) / 8];
        for p in 0..self.bits.len() {
            bytes[p / 8] |= (self.bits[p] as u8) << (p % 8) as u8;
        }
        Ok(ret + bytes.consensus_encode(w)?)
    }
}

impl Decodable for PartialMerkleTree {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let num_transactions: u32 = Decodable::consensus_decode(r)?;
        let hashes: Vec<TxMerkleNode> = Decodable::consensus_decode(r)?;

        let bytes: Vec<u8> = Decodable::consensus_decode(r)?;
        let mut bits: Vec<bool> = vec![false; bytes.len() * 8];

        for (p, bit) in bits.iter_mut().enumerate() {
            *bit = (bytes[p / 8] & (1 << (p % 8) as u8)) != 0;
        }
        Ok(PartialMerkleTree {
            num_transactions,
            hashes,
            bits,
        })
    }
}

/// Data structure that represents a block header paired to a partial merkle tree.
///
/// NOTE: This assumes that the given Block has *at least* 1 transaction. If the Block has 0 txs,
/// it will hit an assertion.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MerkleBlock {
    /// The block header
    pub header: BlockHeader,
    /// Transactions making up a partial merkle tree
    pub txn: PartialMerkleTree,
}

impl MerkleBlock {
    /// Create a MerkleBlock from a block, that contains proofs for specific txids.
    ///
    /// The `block` is a full block containing the header and transactions and `match_txids` is a
    /// function that returns true for the ids that should be included in the partial merkle tree.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use groestlcoin::hash_types::Txid;
    /// use groestlcoin::hashes::hex::FromHex;
    /// use groestlcoin::{Block, MerkleBlock};
    ///
    /// // Block 3955536
    /// let block_bytes = Vec::from_hex("00000020450e366ad9baf7d521a694807338c297ead7346a98f43c051607000000000000caabd19248525c508c3c2a4c9565b955101d9e16f8bc86fa88eb37d1858a576c4bae00620255191a7481e74102010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03505b3c044bae006208a3020481518c50010841756a38657248340000000002ba75cd1d0000000017a914875ff5ac568b44a58b7f71df71e6d8288725a9a7870000000000000000266a24aa21a9edc35c83936b072117a46bba1ff64d5ab727b7aeee38588a31cc3079ae0ca2afb4012000000000000000000000000000000000000000000000000000000000000000000000000002000000000102fb64bfc922cd3bc89f8debf2b0e50c2f5119dcb1fcaf7b7eb339fd14251adcbd0100000000feffffff4402fc870d323a6fe72023d5d7d6805aa4888d371ec53f4f47734a4b6b6e82a50000000000feffffff026216610200000000160014ba6e9bbd517e3211eaf7117357b2b893b0e0c1b19b509806000000001976a914e133a6f4e2b52f2f0e2e0cacd8690c353dc6c36b88ac0247304402200e4ef473fc6a978298ebf8f1fed412df8233a31f76bc455c98559fc4628ab74502205016b75d9dfa89983735ec28fc399b798b8255dd0d8b3becd6ae1946806fefa901210266f32f6f88b244b0ab319e57aa02c472893b872caa219e7f48a1c2d5f0e8b7b70247304402202915fcfc91eca87a1312be5a6cf18eac7353214f5e5725c152d18bd64319471c02207f51d690f5adcbfbdafb4417e966ce0496e696799ba685efe9aa14d10f528bbe01210264e733d2386f25730c665e6f8f739e275a151b13f5133192aa60d64f656c051a4f5b3c00").unwrap();
    /// let block: Block = groestlcoin::consensus::deserialize(&block_bytes).unwrap();
    ///
    /// // Create a merkle block containing a single transaction
    /// let txid = Txid::from_hex(
    ///     "5a122f0ce6973325e60d687163cddbcb0979e6c11188ab787fdaf3f8b200f918").unwrap();
    /// let match_txids: Vec<Txid> = vec![txid].into_iter().collect();
    /// let mb = MerkleBlock::from_block_with_predicate(&block, |t| match_txids.contains(t));
    ///
    /// // Authenticate and extract matched transaction ids
    /// let mut matches: Vec<Txid> = vec![];
    /// let mut index: Vec<u32> = vec![];
    /// assert!(mb.extract_matches(&mut matches, &mut index).is_ok());
    /// assert_eq!(txid, matches[0]);
    /// ```
    pub fn from_block_with_predicate<F>(block: &Block, match_txids: F) -> Self
    where
        F: Fn(&Txid) -> bool
    {
        let block_txids: Vec<_> = block.txdata.iter().map(Transaction::txid).collect();
        Self::from_header_txids_with_predicate(&block.header, &block_txids, match_txids)
    }

    /// Create a MerkleBlock from the block's header and txids, that contain proofs for specific txids.
    ///
    /// The `header` is the block header, `block_txids` is the full list of txids included in the block and
    /// `match_txids` is a function that returns true for the ids that should be included in the partial merkle tree.
    pub fn from_header_txids_with_predicate<F>(
        header: &BlockHeader,
        block_txids: &[Txid],
        match_txids: F,
    ) -> Self
    where
        F: Fn(&Txid) -> bool
    {
        let matches: Vec<bool> = block_txids
            .iter()
            .map(match_txids)
            .collect();

        let pmt = PartialMerkleTree::from_txids(block_txids, &matches);
        MerkleBlock {
            header: *header,
            txn: pmt,
        }
    }

    /// Extract the matching txid's represented by this partial merkle tree
    /// and their respective indices within the partial tree.
    /// returns Ok(()) on success, or error in case of failure
    pub fn extract_matches(
        &self,
        matches: &mut Vec<Txid>,
        indexes: &mut Vec<u32>,
    ) -> Result<(), MerkleBlockError> {
        let merkle_root = self.txn.extract_matches(matches, indexes)?;

        if merkle_root.eq(&self.header.merkle_root) {
            Ok(())
        } else {
            Err(MerkleRootMismatch)
        }
    }
}

impl Encodable for MerkleBlock {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = self.header.consensus_encode(w)?
            + self.txn.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for MerkleBlock {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(MerkleBlock {
            header: Decodable::consensus_decode(r)?,
            txn: Decodable::consensus_decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::cmp::min;

    use crate::hashes::Hash;
    use crate::hashes::hex::{FromHex, ToHex};
    use crate::hash_types::{Txid, TxMerkleNode};
    use secp256k1::rand::prelude::*;

    use crate::consensus::encode::{deserialize, serialize};
    use crate::util::hash::bitcoin_merkle_root;
    use crate::util::merkleblock::{MerkleBlock, PartialMerkleTree};
    use crate::Block;

    /// accepts `pmt_test_$num`
    fn pmt_test_from_name(name: &str) {
        pmt_test(name[9..].parse().unwrap())
    }

    macro_rules! pmt_tests {
    ($($name:ident),* $(,)?) => {
         $(
        #[test]
        fn $name() {
            pmt_test_from_name(stringify!($name));
        }
         )*
    }
}
    pmt_tests!(pmt_test_1, pmt_test_4, pmt_test_7, pmt_test_17, pmt_test_56, pmt_test_100,
        pmt_test_127, pmt_test_256, pmt_test_312, pmt_test_513, pmt_test_1000, pmt_test_4095);

    fn pmt_test(tx_count: usize) {
        let mut rng = thread_rng();
        // Create some fake tx ids
        let tx_ids = (1..=tx_count)
            .map(|i| Txid::from_hex(&format!("{:064x}", i)).unwrap())
            .collect::<Vec<_>>();

        // Calculate the merkle root and height
        let hashes = tx_ids.iter().map(|t| t.as_hash());
        let merkle_root_1: TxMerkleNode = bitcoin_merkle_root(hashes).expect("hashes is not empty").into();
        let mut height = 1;
        let mut ntx = tx_count;
        while ntx > 1 {
            ntx = (ntx + 1) / 2;
            height += 1;
        }

        // Check with random subsets with inclusion chances 1, 1/2, 1/4, ..., 1/128
        for att in 1..15 {
            let mut matches = vec![false; tx_count];
            let mut match_txid1 = vec![];
            for j in 0..tx_count {
                // Generate `att / 2` random bits
                let rand_bits = match att / 2 {
                    0 => 0,
                    bits => rng.gen::<u64>() >> (64 - bits),
                };
                let include = rand_bits == 0;
                matches[j] = include;

                if include {
                    match_txid1.push(tx_ids[j]);
                };
            }

            // Build the partial merkle tree
            let pmt1 = PartialMerkleTree::from_txids(&tx_ids, &matches);
            let serialized = serialize(&pmt1);

            // Verify PartialMerkleTree's size guarantees
            let n = min(tx_count, 1 + match_txid1.len() * height);
            assert!(serialized.len() <= 10 + (258 * n + 7) / 8);

            // Deserialize into a tester copy
            let pmt2: PartialMerkleTree =
                deserialize(&serialized).expect("Could not deserialize own data");

            // Extract merkle root and matched txids from copy
            let mut match_txid2: Vec<Txid> = vec![];
            let mut indexes = vec![];
            let merkle_root_2 = pmt2
                .extract_matches(&mut match_txid2, &mut indexes)
                .expect("Could not extract matches");

            // Check that it has the same merkle root as the original, and a valid one
            assert_eq!(merkle_root_1, merkle_root_2);
            assert_ne!(merkle_root_2, TxMerkleNode::all_zeros());

            // check that it contains the matched transactions (in the same order!)
            assert_eq!(match_txid1, match_txid2);

            // check that random bit flips break the authentication
            for _ in 0..4 {
                let mut pmt3: PartialMerkleTree = deserialize(&serialized).unwrap();
                pmt3.damage(&mut rng);
                let mut match_txid3 = vec![];
                let merkle_root_3 = pmt3
                    .extract_matches(&mut match_txid3, &mut indexes)
                    .unwrap();
                assert_ne!(merkle_root_3, merkle_root_1);
            }
        }
    }

    #[test]
    fn pmt_malleability() {
        // Create some fake tx ids with the last 2 hashes repeating
        let txids: Vec<Txid> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 9, 10]
            .iter()
            .map(|i| Txid::from_hex(&format!("{:064x}", i)).unwrap())
            .collect();

        let matches = vec![
            false, false, false, false, false, false, false, false, false, true, true, false,
        ];

        let tree = PartialMerkleTree::from_txids(&txids, &matches);
        // Should fail due to duplicate txs found
        let result = tree.extract_matches(&mut vec![], &mut vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn merkleblock_serialization() {
        // Got it by running the rpc call
        // `gettxoutproof '["d0c54928d8ace117254e2786c308632976f0f612d62dd0f0a280b9e1db6e3dd7"]'`
        let mb_hex =
            "0000002063280a27a86a2bf9c5e3ba174690c316bdbc12945a73a863650d000000000000d4aefe8dcb7164\
            00868f87660cc7e59d2d5372121240801f5428a43ae735f66247af00625c331b1a3a8aee650400000003b0e\
            1f8e96bbde499c4564a1442643b203794e432c2c4ecfaaaf066b7772e3768d73d6edbe1b980a2f0d02dd612\
            f6f076296308c386274e2517e1acd82849c5d01cd7ef8c0ab37f5ea8ecc95c9db52e406e4a0fde8741ea8ce\
            4b78224aa1e6a1c010b";

        let mb: MerkleBlock = deserialize(&Vec::from_hex(mb_hex).unwrap()).unwrap();
        assert_eq!(get_block_3955537().block_hash(), mb.header.block_hash());
        assert_eq!(
            mb.header.merkle_root,
            mb.txn.extract_matches(&mut vec![], &mut vec![]).unwrap()
        );
        // Serialize again and check that it matches the original bytes
        assert_eq!(mb_hex, serialize(&mb).to_hex().as_str());
    }

    /// Create a CMerkleBlock using a list of txids which will be found in the
    /// given block.
    #[test]
    fn merkleblock_construct_from_txids_found() {
        let block = get_block_3955537();

        let txids: Vec<Txid> = [
            "ab6bea05b7c5d1a6b08af39b348adbfbf9fe1df5620e63a53d2b504dbf35c012",
            "68372e77b766f0aafaecc4c232e49437203b6442144a56c499e4bd6be9f8e1b0",
        ]
        .iter()
        .map(|hex| Txid::from_hex(hex).unwrap())
        .collect();

        let txid1 = txids[0];
        let txid2 = txids[1];
        let txids = vec![txid1, txid2];

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| txids.contains(t));

        assert_eq!(merkle_block.header.block_hash(), block.block_hash());

        let mut matches: Vec<Txid> = vec![];
        let mut index: Vec<u32> = vec![];

        assert_eq!(
            merkle_block
                .txn
                .extract_matches(&mut matches, &mut index)
                .unwrap(),
            block.header.merkle_root
        );
        assert_eq!(matches.len(), 2);

        // Ordered by occurrence in depth-first tree traversal.
        assert_eq!(matches[0], txid2);
        assert_eq!(index[0], 0);

        assert_eq!(matches[1], txid1);
        assert_eq!(index[1], 3);
    }

    /// Create a CMerkleBlock using a list of txids which will not be found in the given block
    #[test]
    fn merkleblock_construct_from_txids_not_found() {
        let block = get_block_3955537();
        let txids: Vec<Txid> = ["c0ffee00003bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20"]
            .iter()
            .map(|hex| Txid::from_hex(hex).unwrap())
            .collect();

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| txids.contains(t));

        assert_eq!(merkle_block.header.block_hash(), block.block_hash());

        let mut matches: Vec<Txid> = vec![];
        let mut index: Vec<u32> = vec![];

        assert_eq!(
            merkle_block
                .txn
                .extract_matches(&mut matches, &mut index)
                .unwrap(),
            block.header.merkle_root
        );
        assert_eq!(matches.len(), 0);
        assert_eq!(index.len(), 0);
    }

    impl PartialMerkleTree {
        /// Flip one bit in one of the hashes - this should break the authentication
        fn damage(&mut self, rng: &mut ThreadRng) {
            let n = rng.gen_range(0..self.hashes.len());
            let bit = rng.gen::<u8>();
            let hashes = &mut self.hashes;
            let mut hash = hashes[n].into_inner();
            hash[(bit >> 3) as usize] ^= 1 << (bit & 7);
            hashes[n] = TxMerkleNode::from_slice(&hash).unwrap();
        }
    }

    /// Returns a real block (0000000000000f20f063e2e0b1dd2f028db56840242db8324acf92286e8850fb)
    /// with 4 txs.
    fn get_block_3955537() -> Block {
        let block_hex =
            "0000002063280a27a86a2bf9c5e3ba174690c316bdbc12945a73a863650d000000000000d4aefe8dcb7164\
            00868f87660cc7e59d2d5372121240801f5428a43ae735f66247af00625c331b1a3a8aee650401000000000\
            1010000000000000000000000000000000000000000000000000000000000000000ffffffff2003515b3c04\
            48af00620817d6e2c74d0300000d2f537570724e6f76612e63632f00000000020000000000000000266a24a\
            a21a9edfddd9cc99b0154352e9ea6d5f12c359ffca1ae5cda7d75d1285f3521e37ea4d9c1b4cd1d00000000\
            1976a91450510d0b8964947df969382852dfd93e4391cfff88ac01200000000000000000000000000000000\
            0000000000000000000000000000000000000000002000000000102653e3ac69bf8f0d6a48385968aa413ec\
            cfbd4cf01769d6fec374506830265cf70100000017160014f62e5f53ba42b8d0949720da1eebbdbc14be185\
            7feffffff53ba0f2224ee366e4f17db23ff8dafa14aeb8eaca5b9d2e4eb0a24a75e610f2600000000171600\
            14f62e5f53ba42b8d0949720da1eebbdbc14be1857feffffff0200e46c3a030300001976a91421ae19e60f5\
            ddaa8ce047e6aaa64e0043adca63a88ac20a921fa14050000160014c67b6462c2159f531e9f8b4f945c389c\
            f8685572024730440220295453d1a0f82884aafd20cf1f73108fc8018268f702af7f690e9ff951e7d10c022\
            0596715e0485de9da833b38bbbf99180c6dca29716c2bb9be8afd89ab89f8ab170121034b09677b822055fc\
            7ad90ec5ee75cd06574a8bd8700373fd8d6e857b613f7a080247304402203eec21f1b1dd5990b4084f7ddcd\
            9d5bfaa959213f1678f110ede5fda247331c6022049795b56f701d6c940538b0a883085cce8b47f36335340\
            038e4c62c3469b696f0121034b09677b822055fc7ad90ec5ee75cd06574a8bd8700373fd8d6e857b613f7a0\
            8505b3c0002000000000105426664063a845eb297793696c3c961d37e8310e1d9975ef86b711c50911cff0c\
            0000000000feffffffea23ec05f81afd16621bc9742f11d8a321a804a916d2ae1eb14ca0ff91b8bbe502000\
            00000feffffff4402fc870d323a6fe72023d5d7d6805aa4888d371ec53f4f47734a4b6b6e82a50100000000\
            feffffff7aeff72e233d5b122de9d45036c80a07b664e646cde14cabbfbb5dfa992d327c0000000000fefff\
            fffea23ec05f81afd16621bc9742f11d8a321a804a916d2ae1eb14ca0ff91b8bbe5010000006a4730440220\
            26e21ecdc31c6436f882c41d7a2a02827ec989f8a5f40a23f87266d36877c486022033099b8c581a4f2f21e\
            f5a618a33b90003ac772dc839a198235a412db4a559fa012103f4d68cf98ee844a188cea91cc8faac380452\
            464348672245500298922fd6b7f8feffffff0282e75a0400000000160014ba2b993d8c1e6c564c3184c59b8\
            1b1a8fc87e1fc34e85ca4000000001976a914fcad3abf614562d224c6cc8b0e00d2fa9016404388ac024730\
            440220339b2118a41f6574fdf0fd61e9b92f08164bc828d4f3792a52ab48ddb6ebf2e802202006b70f568d4\
            f4b8b80e45b73142485064272520c977a091efe33f44b0dacdc0121036fa3008d0a4a94682d42cb1f455db2\
            0042b1c9a675d3c3bf980cc94ec5b335470247304402206cd9a3b5e0edd770f489d941ec4ebb5a9448956ca\
            c12b1783c0e029bca64629d02202bfe07b23c57f44852bf3bc065921d9769a59b7e83b1f008fbc05ca10439\
            112b0121031ee015822703f39f60a24adefd0e62bf3031e979cafb5ced086f466a5471ce360247304402204\
            ffb11c8f73e75d96a18498d86c9a9183f49bfd4d10bb5eb3a8cad881536b2e6022058d972d9bdffd179f75a\
            0660b9cd1af321991c12d356f12bc0ea6681d4e5d0100121031ee015822703f39f60a24adefd0e62bf3031e\
            979cafb5ced086f466a5471ce360247304402200b70640eaa4eebc29c841d118305699ac77ee504d9a7d1ea\
            3f7a05420f08a4740220756725f39148bcaee454b8b90b5ca71e6d71bca0c5f67db38c542b77e344818c012\
            1031fe7edb0947516e8473fe597d7939c01632980cbdf58a31e165996f14a2a6b4800505b3c000200000000\
            0102985f8c7314abd2358afe05bf45b1eeaf2d371e5754b3797fd4ee19651056b6970100000017160014187\
            af46a71950196b4665b766f4523f169e6fd4bfeffffff1c863414458d41676e30e8d2b225c599105a1a76c2\
            9a79173140036b5c9f2b640100000017160014187af46a71950196b4665b766f4523f169e6fd4bfeffffff0\
            259dd4e3b0000000017a9143d3c9cda9d76d184e6cfa6d250839626c897a1d08770d84b0000000000160014\
            b2164058e5fb9a8844de8f86a5bf3f3f560edcc80247304402202add298df69cc13f596593f92f2af3f003a\
            c700706282c52ca02f0863afcdbbf02207777816b8b1570846241a449425fb2eeadef846f26348fd5fc947d\
            534cd7b5e401210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc50247304\
            4022063e1d9da6fe2e9ba958701f98cd9a4268410594abbc6e8112b410895ef29d3f4022059f74ebcf6f805\
            01d464e8d76a8ae5251f2270889d2db881f0f22883511e880301210251ffb811aaf0ddfb5c19ca56db4d04b\
            e3e71a7f3565178420b9c051f59355fc5505b3c00";
        deserialize(&Vec::from_hex(block_hex).unwrap()).unwrap()
    }
}
