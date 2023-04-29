<<<<<<<< HEAD:groestlcoin/fuzz/fuzz_targets/deserialize_psbt.rs
extern crate groestlcoin;

fn do_test(data: &[u8]) {
    let psbt: Result<groestlcoin::psbt::PartiallySignedTransaction, _> = groestlcoin::psbt::Psbt::deserialize(data);
========
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let psbt: Result<bitcoin::psbt::PartiallySignedTransaction, _> =
        bitcoin::psbt::Psbt::deserialize(data);
>>>>>>>> upstream/master:fuzz/fuzz_targets/bitcoin/deserialize_psbt.rs
    match psbt {
        Err(_) => {}
        Ok(psbt) => {
            let ser = groestlcoin::psbt::Psbt::serialize(&psbt);
            let deser = groestlcoin::psbt::Psbt::deserialize(&ser).unwrap();
            // Since the fuzz data could order psbt fields differently, we compare to our deser/ser instead of data
            assert_eq!(ser, groestlcoin::psbt::Psbt::serialize(&deser));
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
