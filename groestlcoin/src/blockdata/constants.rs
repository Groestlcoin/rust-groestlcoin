// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use groestlcoin_internals::impl_array_newtype;
use hex_lit::hex;

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::blockdata::witness::Witness;
use crate::hashes::{sha256d, Hash};
use crate::internal_macros::impl_bytes_newtype;
use crate::network::constants::Network;
use crate::pow::CompactTarget;

/// How many gros are in "one groestlcoin".
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 60;
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (groestlcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 36; // 0x24
/// Mainnet (groestlcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 1_050_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 121;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 105_000_000 * COIN_VALUE;

/// Constructs and returns the coinbase (and only) transaction of the Groestlcoin genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new()
        .push_int(486604799)
        .push_int_non_minimal(4)
        .push_slice(b"Pressure must be put on Vladimir Putin over Crimea")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    let out_script =
        script::Builder::new().push_slice(script_bytes).push_opcode(OP_CHECKSIG).into_script();
    ret.output.push(TxOut { value: 0, script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Groestlcoin => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1395342829,
                bits: CompactTarget::from_consensus(0x1e0fffff),
                nonce: 220035,
            },
            txdata,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::THREE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1440000002,
                bits: CompactTarget::from_consensus(0x1e00ffff),
                nonce: 6556309,
            },
            txdata,
        },
        Network::Signet => Block {
            header: block::Header {
                version: block::Version::THREE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1606082400,
                bits: CompactTarget::from_consensus(0x1e00ffff),
                nonce: 14675970,
            },
            txdata,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::THREE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1440000002,
                bits: CompactTarget::from_consensus(0x1e00ffff),
                nonce: 6556309,
            },
            txdata,
        },
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet groestlcoin.
    pub const GROESTLCOIN: Self = Self([
        35, 144, 99, 59, 112, 240, 98, 203, 58, 61, 104, 20, 182, 126, 41, 168, 13, 157, 117,
        129, 219, 11, 204, 73, 77, 89, 124, 146, 197, 10, 0, 0,
    ]);
    /// `ChainHash` for testnet groestlcoin.
    pub const TESTNET: Self = Self([
        54, 205, 242, 220, 183, 85, 98, 135, 40, 42, 5, 192, 100, 1, 35, 35, 186, 230, 99,
        193, 110, 211, 205, 152, 152, 252, 80, 187, 255, 0, 0, 0,
    ]);
    /// `ChainHash` for signet groestlcoin.
    pub const SIGNET: Self = Self([
        49, 171, 20, 187, 146, 53, 242, 162, 235, 108, 135, 123, 81, 175, 87, 67, 37, 140, 129,
        231, 233, 205, 198, 147, 121, 162, 162, 202, 127, 0, 0, 0,
    ]);
    /// `ChainHash` for regtest groestlcoin.
    pub const REGTEST: Self = Self([
        54, 205, 242, 220, 183, 85, 98, 135, 40, 42, 5, 192, 100, 1, 35, 35, 186, 230, 99,
        193, 110, 211, 205, 152, 152, 252, 80, 187, 255, 0, 0, 0,
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::GROESTLCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::consensus::encode::serialize;
    use crate::internal_macros::hex;
    use crate::network::constants::Network;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("3a04ffff001d0104325072657373757265206d75737420626520707574206f6e20566c6164696d697220507574696e206f766572204372696d6561"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, 0);
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            gen.wtxid().to_string(),
            "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb"
        );
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Groestlcoin);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb"
        );

        assert_eq!(gen.header.time, 1395342829);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0fffff));
        assert_eq!(gen.header.nonce, 220035);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "00000ac5927c594d49cc0bdb81759d0da8297eb614683d3acb62f0703b639023"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::THREE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb"
        );
        assert_eq!(gen.header.time, 1440000002);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e00ffff));
        assert_eq!(gen.header.nonce, 6556309);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "000000ffbb50fc9898cdd36ec163e6ba23230164c0052a28876255b7dcf2cd36"
        );
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, block::Version::THREE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb"
        );
        assert_eq!(gen.header.time, 1606082400);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e00ffff));
        assert_eq!(gen.header.nonce, 14675970);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "0000007fcaa2a27993c6cde9e7818c254357af517b876ceba2f23592bb14ab31"
        );
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use crate::hashes::sha256;

        // The genesis block hash is a double-groestl and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        #[allow(unreachable_patterns)] // This is specifically trying to catch later added variants.
        match network {
            Network::Groestlcoin => {},
            Network::Testnet => {},
            Network::Signet => {},
            Network::Regtest => {},
            _ => panic!("Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Groestlcoin;
        testnet_chain_hash_genesis_block, Network::Testnet;
        signet_chain_hash_genesis_block, Network::Signet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Groestlcoin).to_string();
        let want = "2390633b70f062cb3a3d6814b67e29a80d9d7581db0bcc494d597c92c50a0000";
        assert_eq!(got, want);
    }
}
