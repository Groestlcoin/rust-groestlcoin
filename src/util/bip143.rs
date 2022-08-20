// Written in 2018 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! BIP143 implementation.
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use core::ops::{Deref, DerefMut};

use crate::io;

use crate::hashes::Hash;
use crate::hash_types::Sighash;
use crate::blockdata::script::Script;
use crate::blockdata::transaction::Transaction;
use crate::blockdata::witness::Witness;
use crate::consensus::encode;
use crate::util::sighash::{self, EcdsaSighashType};

/// A replacement for SigHashComponents which supports all sighash modes
#[deprecated(since = "0.28.0", note = "please use [sighash::SighashCache] instead")]
pub struct SigHashCache<R: Deref<Target = Transaction>> {
    cache: sighash::SighashCache<R>,
}

#[allow(deprecated)]
impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        Self { cache: sighash::SighashCache::new(tx) }
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), encode::Error> {
        self.cache
            .segwit_encode_signing_data_to(writer, input_index, script_code, value, sighash_type)
            .expect("input_index greater than tx input len");
        Ok(())
    }

    /// Compute the BIP143 sighash for any flag type.
    pub fn signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType
    ) -> Sighash {
        let mut enc = Sighash::engine();
        self.encode_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)
            .expect("engines don't error");
        Sighash::from_engine(enc)
    }
}

#[allow(deprecated)]
impl<R: DerefMut<Target = Transaction>> SigHashCache<R> {
    /// When the SigHashCache is initialized with a mutable reference to a transaction instead of a
    /// regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    ///
    /// panics if `input_index` is out of bounds with respect of the number of inputs
    ///
    /// ```
    /// use groestlcoin::{EcdsaSighashType, Script, Transaction, PackedLockTime};
    /// use groestlcoin::util::bip143::SigHashCache;
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SigHashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.signature_hash(inp, &prevout_script, 42, EcdsaSighashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.access_witness(inp).push(&[]);
    /// }
    /// ```
    pub fn access_witness(&mut self, input_index: usize) -> &mut Witness {
        self.cache.witness_mut(input_index).unwrap()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::hash_types::Sighash;
    use crate::blockdata::script::Script;
    use crate::blockdata::transaction::Transaction;
    use crate::consensus::encode::deserialize;
    use crate::hashes::hex::FromHex;
    use crate::util::sighash::SighashCache;

    use super::*;

    fn run_test_sighash_bip143(tx: &str, script: &str, input_index: usize, value: u64, hash_type: u32, expected_result: &str) {
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
        let script = Script::from(Vec::<u8>::from_hex(script).unwrap());
        let raw_expected = Sighash::from_hex(expected_result).unwrap();
        let expected_result = Sighash::from_slice(&raw_expected[..]).unwrap();
        let mut cache = SighashCache::new(&tx);
        let sighash_type = EcdsaSighashType::from_u32_consensus(hash_type);
        let actual_result = cache.segwit_signature_hash(input_index, &script, value, sighash_type).unwrap();
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn bip143_sighash_flags() {
        // All examples generated via Bitcoin Core RPC using signrawtransactionwithwallet
        // with additional debug printing
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x01, "d056435d9246c2b45512c14ee13452f92be9e4ebe0ec2fba5eb73c8e5bc996d3");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x02, "0aa07aaf9f5259a7e42be6447c15b075e50d8a3b69d9710f0a527c11fdef8d7e");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x03, "3a817c8845041998a9216046253f3de03da34ee86d587e26371269fcd95589a4");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x81, "b54f97f21a3dbb1c385dcfd2f031d2e92b11dc6af8c540cdc7b94084061ddb50");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x82, "73ac3205753518d3212d6ee84bcb6cda6817321a7bab8f5d54093a6af2a00590");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x83, "7d61149f5b04ce63835f6e14bd54e4e09ac24ac9a6bddfc532ef24e4af90cfa4");
    }
}
