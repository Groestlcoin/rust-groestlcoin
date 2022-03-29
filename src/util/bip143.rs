// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP143 implementation.
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use hashes::Hash;
use hash_types::SigHash;
use blockdata::script::Script;
use blockdata::witness::Witness;
use blockdata::transaction::{Transaction, TxIn, EcdsaSigHashType};
use consensus::{encode, Encodable};

use io;
use core::ops::{Deref, DerefMut};
use util::sighash;

/// Parts of a sighash which are common across inputs or signatures, and which are
/// sufficient (in conjunction with a private key) to sign the transaction
#[derive(Clone, PartialEq, Eq, Debug)]
#[deprecated(since = "0.24.0", note = "please use [sighash::SigHashCache] instead")]
pub struct SighashComponents {
    tx_version: i32,
    tx_locktime: u32,
    /// Hash of all the previous outputs
    pub hash_prevouts: SigHash,
    /// Hash of all the input sequence nos
    pub hash_sequence: SigHash,
    /// Hash of all the outputs in this transaction
    pub hash_outputs: SigHash,
}

#[allow(deprecated)]
impl SighashComponents {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// information about its inputs.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: &Transaction) -> SighashComponents {
        let hash_prevouts = {
            let mut enc = SigHash::engine();
            for txin in &tx.input {
                txin.previous_output.consensus_encode(&mut enc).expect("engines don't error");
            }
            SigHash::from_engine(enc)
        };

        let hash_sequence = {
            let mut enc = SigHash::engine();
            for txin in &tx.input {
                txin.sequence.consensus_encode(&mut enc).expect("engines don't error");
            }
            SigHash::from_engine(enc)
        };

        let hash_outputs = {
            let mut enc = SigHash::engine();
            for txout in &tx.output {
                txout.consensus_encode(&mut enc).expect("engines don't error");
            }
            SigHash::from_engine(enc)
        };

        SighashComponents {
            tx_version: tx.version,
            tx_locktime: tx.lock_time,
            hash_prevouts,
            hash_sequence,
            hash_outputs,
        }
    }

    /// Compute the BIP143 sighash for a `SIGHASH_ALL` signature for the given
    /// input.
    pub fn sighash_all(&self, txin: &TxIn, script_code: &Script, value: u64) -> SigHash {
        let mut enc = SigHash::engine();
        self.tx_version.consensus_encode(&mut enc).expect("engines don't error");
        self.hash_prevouts.consensus_encode(&mut enc).expect("engines don't error");
        self.hash_sequence.consensus_encode(&mut enc).expect("engines don't error");
        txin
            .previous_output
            .consensus_encode(&mut enc)
            .expect("engines don't error");
        script_code.consensus_encode(&mut enc).expect("engines don't error");
        value.consensus_encode(&mut enc).expect("engines don't error");
        txin.sequence.consensus_encode(&mut enc).expect("engines don't error");
        self.hash_outputs.consensus_encode(&mut enc).expect("engines don't error");
        self.tx_locktime.consensus_encode(&mut enc).expect("engines don't error");
        1u32.consensus_encode(&mut enc).expect("engines don't error"); // hashtype
        SigHash::from_engine(enc)
    }
}

/// A replacement for SigHashComponents which supports all sighash modes
#[deprecated(since = "0.28.0", note = "please use [sighash::SigHashCache] instead")]
pub struct SigHashCache<R: Deref<Target = Transaction>> {
    cache: sighash::SigHashCache<R>,
}

#[allow(deprecated)]
impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        Self { cache: sighash::SigHashCache::new(tx) }
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSigHashType,
    ) -> Result<(), encode::Error> {
        self.cache
            .segwit_encode_signing_data_to(writer, input_index, script_code, value, sighash_type)
            .expect("input_index greater than tx input len");
        Ok(())
    }

    /// Compute the BIP143 sighash for any flag type. See SighashComponents::sighash_all simpler
    /// API for the most common case
    pub fn signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSigHashType
    ) -> SigHash {
        let mut enc = SigHash::engine();
        self.encode_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)
            .expect("engines don't error");
        SigHash::from_engine(enc)
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
    /// use groestlcoin::blockdata::transaction::{Transaction, EcdsaSigHashType};
    /// use groestlcoin::util::bip143::SigHashCache;
    /// use groestlcoin::Script;
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: 0, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SigHashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.signature_hash(inp, &prevout_script, 42, EcdsaSigHashType::All);
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
    use std::str::FromStr;
    use hash_types::SigHash;
    use blockdata::script::Script;
    use blockdata::transaction::Transaction;
    use consensus::encode::deserialize;
    use network::constants::Network;
    use util::address::Address;
    use util::key::PublicKey;
    use hashes::hex::FromHex;

    use super::*;

    fn p2pkh_hex(pk: &str) -> Script {
        let pk: PublicKey = PublicKey::from_str(pk).unwrap();
        let witness_script = Address::p2pkh(&pk, Network::Groestlcoin).script_pubkey();
        witness_script
    }

    fn run_test_sighash_bip143(tx: &str, script: &str, input_index: usize, value: u64, hash_type: u32, expected_result: &str) {
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
        let script = Script::from(Vec::<u8>::from_hex(script).unwrap());
        let raw_expected = SigHash::from_hex(expected_result).unwrap();
        let expected_result = SigHash::from_slice(&raw_expected[..]).unwrap();
        let mut cache = SigHashCache::new(&tx);
        let sighash_type = EcdsaSigHashType::from_u32_consensus(hash_type);
        let actual_result = cache.signature_hash(input_index, &script, value, sighash_type);
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn bip143_p2wpkh() {
        let tx = deserialize::<Transaction>(
            &Vec::from_hex(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
                0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
                00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
                510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
            ).unwrap()[..],
        ).unwrap();

        let witness_script = p2pkh_hex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        let value = 600_000_000;

        let comp = SighashComponents::new(&tx);
        assert_eq!(
            comp,
            SighashComponents {
                tx_version: 1,
                tx_locktime: 17,
                hash_prevouts: hex_hash!(
                    SigHash, "c771f7ed8ee6224d08700833d1c6d31e7a1f6b7a3840c4e186c22136e8c9a6ed"
                ),
                hash_sequence: hex_hash!(
                    SigHash, "b258c7ef98e1770484c86e4023c5b7361eb8e02e56b6fb7233af17ebe9eb017e"
                ),
                hash_outputs: hex_hash!(
                    SigHash, "48f88af72cd8cc9af8cbeb53b6c60b20b4a074dcd5be578cbc279311c7d72ea9"
                ),
            }
        );

        assert_eq!(
            comp.sighash_all(&tx.input[1], &witness_script, value),
            hex_hash!(SigHash, "78d30165e9873c05d3e3eea458d41559dbb42ad5bb79db4e5be4827a05ed62b4")
        );
    }

    #[test]
    fn bip143_p2wpkh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &Vec::from_hex(
                "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000\
                0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac00\
                08af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
            ).unwrap()[..],
        ).unwrap();

        let witness_script = p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        let value = 1_000_000_000;
        let comp = SighashComponents::new(&tx);
        assert_eq!(
            comp,
            SighashComponents {
                tx_version: 1,
                tx_locktime: 1170,
                hash_prevouts: hex_hash!(
                    SigHash, "cddf06e3e7cc7c2b515aa8960e7ee526ffe975f30a421ca092075ade5cf47533"
                ),
                hash_sequence: hex_hash!(
                    SigHash, "b4248c210a2905b94345e1a8414d0e12efcfb2f4f0f2397159a71283397a0ccd"
                ),
                hash_outputs: hex_hash!(
                    SigHash, "324d2443ed14b2ca1e7af61aba2d7fa517c5b8feb6433106b67a653a98b5c1a1"
                ),
            }
        );

        assert_eq!(
            comp.sighash_all(&tx.input[0], &witness_script, value),
            hex_hash!(SigHash, "12885c3df56d146075151c6dbf2afe9506333d4f3e6cea38f58ca8520805a30f")
        );
    }

    #[test]
    fn bip143_p2wsh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &Vec::from_hex(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
             ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
             05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000").unwrap()[..],
        ).unwrap();

        let witness_script = hex_script!(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae"
        );
        let value = 987654321;

        let comp = SighashComponents::new(&tx);
        assert_eq!(
            comp,
            SighashComponents {
                tx_version: 1,
                tx_locktime: 0,
                hash_prevouts: hex_hash!(
                    SigHash, "1f1f6dc580200b32c0579c35acc3f5e54045e46fe1b6e6d3dbe75e3ad9e5125d"
                ),
                hash_sequence: hex_hash!(
                    SigHash, "ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e"
                ),
                hash_outputs: hex_hash!(
                    SigHash, "691738022230671f6f97f0f6343ac62568f82a3e02bfb20dba155d509480c523"
                ),
            }
        );

        assert_eq!(
            comp.sighash_all(&tx.input[0], &witness_script, value),
            hex_hash!(SigHash, "f49b945ea2188fbb44771c80c51e3b5185e90748b4600dd45c3e6268f634fa8a")
        );
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
