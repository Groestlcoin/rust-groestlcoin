// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Blockdata constants
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction
//!

use std::default::Default;

use hashes::hex::FromHex;
use hashes::sha256d;
use blockdata::opcodes;
use blockdata::script;
use blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn};
use blockdata::block::{Block, BlockHeader};
use network::constants::Network;
use util::uint::Uint256;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 1;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 1;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;


/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256::from_u64(0xFFFF).unwrap() << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    21_000_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_scriptint(486604799)
                                          .push_scriptint(4)
                                          .push_slice(b"Pressure must be put on Vladimir Putin over Crimea")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: vec![],
    });

    // Outputs
    let out_script = script::Builder::new()
        .push_slice(&Vec::<u8>::from_hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f").unwrap())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 0 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Bitcoin => {
            Block {
                header: BlockHeader {
                    version: 112,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1395342829,
                    bits: 0x1e0fffff,
                    nonce: 220035
                },
                txdata: txdata
            }
        }
        Network::Testnet => {
            Block {
                header: BlockHeader {
                    version: 3,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1440000002,
                    bits: 0x1e00ffff,
                    nonce: 6556309
                },
                txdata: txdata
            }
        }
        Network::Regtest => {
            Block {
                header: BlockHeader {
                    version: 3,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1440000002,
                    bits: 0x1e00ffff,
                    nonce: 6556309
                },
                txdata: txdata
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::default::Default;
    use hex::decode as hex_decode;

    use network::constants::Network;
    use consensus::encode::serialize;
    use blockdata::constants::{genesis_block, bitcoin_genesis_tx};
    use blockdata::constants::{MAX_SEQUENCE, COIN_VALUE};
    use util::hash::BitcoinHash;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Default::default());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex_decode("3a04ffff001d0104325072657373757265206d75737420626520707574206f6e20566c6164696d697220507574696e206f766572204372696d6561").unwrap());

        assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex_decode("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, 0);

        assert_eq!(format!("{:x}", gen.wtxid()),
                   "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb".to_string());
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, 112);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                   "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb".to_string());
        assert_eq!(gen.header.time, 1395342829);
        assert_eq!(gen.header.bits, 0x1e0fffff);
        assert_eq!(gen.header.nonce, 220035);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "00000ac5927c594d49cc0bdb81759d0da8297eb614683d3acb62f0703b639023".to_string());
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 3);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                  "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb".to_string());
        assert_eq!(gen.header.time, 1440000002);
        assert_eq!(gen.header.bits, 0x1e00ffff);
        assert_eq!(gen.header.nonce, 6556309);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "000000ffbb50fc9898cdd36ec163e6ba23230164c0052a28876255b7dcf2cd36".to_string());
    }
}

