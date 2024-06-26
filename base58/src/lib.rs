// SPDX-License-Identifier: CC0-1.0

//! Groestlcoin base58 encoding and decoding.
//!
//! This crate can be used in a no-std environment but requires an allocator.

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

static BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub mod error;

#[cfg(not(feature = "std"))]
pub use alloc::{string::String, vec::Vec};
use core::{fmt, iter, slice, str};
#[cfg(feature = "std")]
pub use std::{string::String, vec::Vec};

use hashes::{groestld, Hash};

use crate::error::{IncorrectChecksumError, TooShortError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::error::{Error, InvalidCharacterError};

#[rustfmt::skip]
static BASE58_DIGITS: [Option<u8>; 128] = [
    None,     None,     None,     None,     None,     None,     None,     None,     // 0-7
    None,     None,     None,     None,     None,     None,     None,     None,     // 8-15
    None,     None,     None,     None,     None,     None,     None,     None,     // 16-23
    None,     None,     None,     None,     None,     None,     None,     None,     // 24-31
    None,     None,     None,     None,     None,     None,     None,     None,     // 32-39
    None,     None,     None,     None,     None,     None,     None,     None,     // 40-47
    None,     Some(0),  Some(1),  Some(2),  Some(3),  Some(4),  Some(5),  Some(6),  // 48-55
    Some(7),  Some(8),  None,     None,     None,     None,     None,     None,     // 56-63
    None,     Some(9),  Some(10), Some(11), Some(12), Some(13), Some(14), Some(15), // 64-71
    Some(16), None,     Some(17), Some(18), Some(19), Some(20), Some(21), None,     // 72-79
    Some(22), Some(23), Some(24), Some(25), Some(26), Some(27), Some(28), Some(29), // 80-87
    Some(30), Some(31), Some(32), None,     None,     None,     None,     None,     // 88-95
    None,     Some(33), Some(34), Some(35), Some(36), Some(37), Some(38), Some(39), // 96-103
    Some(40), Some(41), Some(42), Some(43), None,     Some(44), Some(45), Some(46), // 104-111
    Some(47), Some(48), Some(49), Some(50), Some(51), Some(52), Some(53), Some(54), // 112-119
    Some(55), Some(56), Some(57), None,     None,     None,     None,     None,     // 120-127
];

/// Decodes a base58-encoded string into a byte vector.
pub fn decode(data: &str) -> Result<Vec<u8>, InvalidCharacterError> {
    // 11/15 is just over log_256(58)
    let mut scratch = vec![0u8; 1 + data.len() * 11 / 15];
    // Build in base 256
    for d58 in data.bytes() {
        // Compute "X = X * 58 + next_digit" in base 256
        if d58 as usize >= BASE58_DIGITS.len() {
            return Err(InvalidCharacterError { invalid: d58 });
        }
        let mut carry = match BASE58_DIGITS[d58 as usize] {
            Some(d58) => d58 as u32,
            None => {
                return Err(InvalidCharacterError { invalid: d58 });
            }
        };
        for d256 in scratch.iter_mut().rev() {
            carry += *d256 as u32 * 58;
            *d256 = carry as u8;
            carry /= 256;
        }
        assert_eq!(carry, 0);
    }

    // Copy leading zeroes directly
    let mut ret: Vec<u8> = data.bytes().take_while(|&x| x == BASE58_CHARS[0]).map(|_| 0).collect();
    // Copy rest of string
    ret.extend(scratch.into_iter().skip_while(|&x| x == 0));
    Ok(ret)
}

/// Decodes a base58check-encoded string into a byte vector verifying the checksum.
pub fn decode_check(data: &str) -> Result<Vec<u8>, Error> {
    let mut ret: Vec<u8> = decode(data)?;
    if ret.len() < 4 {
        return Err(TooShortError { length: ret.len() }.into());
    }
    let check_start = ret.len() - 4;

    let hash_check =
        groestld::Hash::hash(&ret[..check_start])[..4].try_into().expect("4 byte slice");
    let data_check = ret[check_start..].try_into().expect("4 byte slice");

    let expected = u32::from_le_bytes(hash_check);
    let actual = u32::from_le_bytes(data_check);

    if actual != expected {
        return Err(IncorrectChecksumError { incorrect: actual, expected }.into());
    }

    ret.truncate(check_start);
    Ok(ret)
}

/// Encodes `data` as a base58 string (see also `base58::encode_check()`).
pub fn encode(data: &[u8]) -> String { encode_iter(data.iter().cloned()) }

/// Encodes `data` as a base58 string including the checksum.
///
/// The checksum is the first four bytes of the groestld of the data, concatenated onto the end.
pub fn encode_check(data: &[u8]) -> String {
    let checksum = groestld::Hash::hash(data);
    encode_iter(data.iter().cloned().chain(checksum[0..4].iter().cloned()))
}

/// Encodes a slice as base58, including the checksum, into a formatter.
///
/// The checksum is the first four bytes of the groestld of the data, concatenated onto the end.
pub fn encode_check_to_fmt(fmt: &mut fmt::Formatter, data: &[u8]) -> fmt::Result {
    let checksum = groestld::Hash::hash(data);
    let iter = data.iter().cloned().chain(checksum[0..4].iter().cloned());
    format_iter(fmt, iter)
}

fn encode_iter<I>(data: I) -> String
where
    I: Iterator<Item = u8> + Clone,
{
    let mut ret = String::new();
    format_iter(&mut ret, data).expect("writing into string shouldn't fail");
    ret
}

fn format_iter<I, W>(writer: &mut W, data: I) -> Result<(), fmt::Error>
where
    I: Iterator<Item = u8> + Clone,
    W: fmt::Write,
{
    let mut ret = SmallVec::new();

    let mut leading_zero_count = 0;
    let mut leading_zeroes = true;
    // Build string in little endian with 0-58 in place of characters...
    for d256 in data {
        let mut carry = d256 as usize;
        if leading_zeroes && carry == 0 {
            leading_zero_count += 1;
        } else {
            leading_zeroes = false;
        }

        for ch in ret.iter_mut() {
            let new_ch = *ch as usize * 256 + carry;
            *ch = (new_ch % 58) as u8;
            carry = new_ch / 58;
        }
        while carry > 0 {
            ret.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // ... then reverse it and convert to chars
    for _ in 0..leading_zero_count {
        ret.push(0);
    }

    for ch in ret.iter().rev() {
        writer.write_char(BASE58_CHARS[*ch as usize] as char)?;
    }

    Ok(())
}

/// Vector-like object that holds the first 100 elements on the stack. If more space is needed it
/// will be allocated on the heap.
struct SmallVec<T> {
    len: usize,
    stack: [T; 100],
    heap: Vec<T>,
}

impl<T: Default + Copy> SmallVec<T> {
    fn new() -> SmallVec<T> { SmallVec { len: 0, stack: [T::default(); 100], heap: Vec::new() } }

    fn push(&mut self, val: T) {
        if self.len < 100 {
            self.stack[self.len] = val;
            self.len += 1;
        } else {
            self.heap.push(val);
        }
    }

    fn iter(&self) -> iter::Chain<slice::Iter<T>, slice::Iter<T>> {
        // If len<100 then we just append an empty vec
        self.stack[0..self.len].iter().chain(self.heap.iter())
    }

    fn iter_mut(&mut self) -> iter::Chain<slice::IterMut<T>, slice::IterMut<T>> {
        // If len<100 then we just append an empty vec
        self.stack[0..self.len].iter_mut().chain(self.heap.iter_mut())
    }
}

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;

    use super::*;

    #[test]
    fn test_base58_encode() {
        // Basics
        assert_eq!(&encode(&[0][..]), "1");
        assert_eq!(&encode(&[1][..]), "2");
        assert_eq!(&encode(&[58][..]), "21");
        assert_eq!(&encode(&[13, 36][..]), "211");

        // Leading zeroes
        assert_eq!(&encode(&[0, 13, 36][..]), "1211");
        assert_eq!(&encode(&[0, 0, 0, 0, 13, 36][..]), "1111211");

        // Long input (>100 bytes => has to use heap)
        let res = encode(
            "GroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestl\
            coinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoinGroestlcoin"
                .as_bytes(),
        );
        let exp = "2hXiLBbH9kmBoA9HWRRpWuHu29Hg49ApfMGzw6CXJkHn2sVUFjm8qF8FQQm29jFNXHjUXs59Q\
            K9gk2MrWjiLokRHQ2t71bY5HjQUmutR2rTU91sc9gZjixxegH45Zs19PkCweG4bshVEm3XvqSDnELis8yjxkb\
            aeV3DFCuYA69mxwtsqZpJxqWCSbu9vPBAoX5bWKeF5bRXNSd9tp4F7GMWCmvQqC2fxpVqk78YkxCs6H4EAJncp\
            sNxAxCwrLQ164Pzn2y5zupcmLmwEf1SRmN997q5J3rU3ytRf3ot1iuymf";
        assert_eq!(&res, exp);

        // Addresses
        let addr = hex!("24f8917303bfa8ef24f292e8fa1419b20460ba064d");
        assert_eq!(&encode_check(&addr[..]), "Fsq2GUc7R9f3JSfv3ma5JwkGPaFm3uH23D");
    }

    #[test]
    fn test_base58_decode() {
        // Basics
        assert_eq!(decode("1").ok(), Some(vec![0u8]));
        assert_eq!(decode("2").ok(), Some(vec![1u8]));
        assert_eq!(decode("21").ok(), Some(vec![58u8]));
        assert_eq!(decode("211").ok(), Some(vec![13u8, 36]));

        // Leading zeroes
        assert_eq!(decode("1211").ok(), Some(vec![0u8, 13, 36]));
        assert_eq!(decode("111211").ok(), Some(vec![0u8, 0, 0, 13, 36]));

        // Addresses
        assert_eq!(
            decode_check("Fsq2GUc7R9f3JSfv3ma5JwkGPaFm3uH23D").ok(),
            Some(hex!("24f8917303bfa8ef24f292e8fa1419b20460ba064d"))
        );
        // Non Base58 char.
        assert_eq!(
            decode("¢").unwrap_err(),
            InvalidCharacterError { invalid: 194 }
        );
    }

    #[test]
    fn test_base58_roundtrip() {
        let s = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1zNPxJ";
        let v: Vec<u8> = decode_check(s).unwrap();
        assert_eq!(encode_check(&v[..]), s);
        assert_eq!(decode_check(&encode_check(&v[..])).ok(), Some(v));

        // Check that empty slice passes roundtrip.
        assert_eq!(decode_check(&encode_check(&[])), Ok(vec![]));
        // Check that `len > 4` is enforced.
        assert_eq!(decode_check(&encode(&[1, 2, 3])), Err(TooShortError { length: 3 }.into()));
    }
}
