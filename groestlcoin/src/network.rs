// SPDX-License-Identifier: CC0-1.0

//! Groestlcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Groestlcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use groestlcoin::Network;
//! use groestlcoin::consensus::encode::serialize;
//!
//! let network = Network::Groestlcoin;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD4]);
//! ```

use core::convert::TryFrom;
use core::fmt;
use core::fmt::Display;
use core::str::FromStr;

use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::constants::ChainHash;
use crate::error::impl_std_error;
use crate::p2p::Magic;
use crate::prelude::{String, ToOwned};

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    /// Mainnet Groestlcoin.
    Groestlcoin,
    /// Groestlcoin's testnet network.
    Testnet,
    /// Groestlcoin's signet network.
    Signet,
    /// Groestlcoin's regtest network.
    Regtest,
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use groestlcoin::p2p::Magic;
    /// use groestlcoin::Network;
    /// use std::convert::TryFrom;
    ///
    /// assert_eq!(Ok(Network::Groestlcoin), Network::try_from(Magic::from_bytes([0xF9, 0xBE, 0xB4, 0xD4])));
    /// assert_eq!(None, Network::from_magic(Magic::from_bytes([0xFF, 0xFF, 0xFF, 0xFF])));
    /// ```
    pub fn from_magic(magic: Magic) -> Option<Network> { Network::try_from(magic).ok() }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use groestlcoin::p2p::Magic;
    /// use groestlcoin::Network;
    ///
    /// let network = Network::Groestlcoin;
    /// assert_eq!(network.magic(), Magic::from_bytes([0xF9, 0xBE, 0xB4, 0xD4]));
    /// ```
    pub fn magic(self) -> Magic { Magic::from(self) }

    /// Converts a `Network` to its equivalent `groestlcoind -chain` argument name.
    ///
    /// ```bash
    /// $ groestlcoin-23.0/bin/groestlcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Network::Groestlcoin => "main",
            Network::Testnet => "test",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// Converts a `groestlcoind -chain` argument name to its equivalent `Network`.
    ///
    /// ```bash
    /// $ groestlcoin-23.0/bin/groestlcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        use Network::*;

        let network = match core_arg {
            "main" => Groestlcoin,
            "test" => Testnet,
            "signet" => Signet,
            "regtest" => Regtest,
            _ => return Err(ParseNetworkError(core_arg.to_owned())),
        };
        Ok(network)
    }

    /// Return the network's chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use groestlcoin::Network;
    /// use groestlcoin::blockdata::constants::ChainHash;
    ///
    /// let network = Network::Groestlcoin;
    /// assert_eq!(network.chain_hash(), ChainHash::GROESTLCOIN);
    /// ```
    pub fn chain_hash(self) -> ChainHash { ChainHash::using_genesis_block(self) }

    /// Creates a `Network` from the chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use groestlcoin::Network;
    /// use groestlcoin::blockdata::constants::ChainHash;
    /// use std::convert::TryFrom;
    ///
    /// assert_eq!(Ok(Network::Groestlcoin), Network::try_from(ChainHash::GROESTLCOIN));
    /// ```
    pub fn from_chain_hash(chain_hash: ChainHash) -> Option<Network> {
        Network::try_from(chain_hash).ok()
    }
}

#[cfg(feature = "serde")]
pub mod as_core_arg {
    //! Module for serialization/deserialization of network variants into/from Groestlcoin Core values
    #![allow(missing_docs)]

    use serde;

    use crate::Network;

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(network.to_core_arg())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
            type Value = Network;

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Network::from_core_arg(s).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"groestlcoin network encoded as a string (either main, test, signet or regtest)",
                    )
                })
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "groestlcoin network encoded as a string (either main, test, signet or regtest)"
                )
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetworkError(String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network", self.0; self)
    }
}
impl_std_error!(ParseNetworkError);

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Network::*;

        let network = match s {
            "groestlcoin" => Groestlcoin,
            "testnet" => Testnet,
            "signet" => Signet,
            "regtest" => Regtest,
            _ => return Err(ParseNetworkError(s.to_owned())),
        };
        Ok(network)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use Network::*;

        let s = match *self {
            Groestlcoin => "groestlcoin",
            Testnet => "testnet",
            Signet => "signet",
            Regtest => "regtest",
        };
        write!(f, "{}", s)
    }
}

/// Error in parsing network from chain hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownChainHash(ChainHash);

impl Display for UnknownChainHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown chain hash: {}", self.0)
    }
}

impl_std_error!(UnknownChainHash);

impl TryFrom<ChainHash> for Network {
    type Error = UnknownChainHash;

    fn try_from(chain_hash: ChainHash) -> Result<Self, Self::Error> {
        match chain_hash {
            // Note: any new network entries must be matched against here.
            ChainHash::GROESTLCOIN => Ok(Network::Groestlcoin),
            ChainHash::TESTNET => Ok(Network::Testnet),
            ChainHash::SIGNET => Ok(Network::Signet),
            //ChainHash::REGTEST => Ok(Network::Regtest),
            _ => Err(UnknownChainHash(chain_hash)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Network;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::p2p::ServiceFlags;

    #[test]
    fn serialize_test() {
        assert_eq!(serialize(&Network::Groestlcoin.magic()), &[0xf9, 0xbe, 0xb4, 0xd4]);
        assert_eq!(serialize(&Network::Testnet.magic()), &[0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(serialize(&Network::Signet.magic()), &[0x6f, 0x89, 0x2b, 0x8f]);
        assert_eq!(serialize(&Network::Regtest.magic()), &[0xfa, 0xbf, 0xb5, 0xda]);

        assert_eq!(deserialize(&[0xf9, 0xbe, 0xb4, 0xd4]).ok(), Some(Network::Groestlcoin.magic()));
        assert_eq!(deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(), Some(Network::Testnet.magic()));
        assert_eq!(deserialize(&[0x6f, 0x89, 0x2b, 0x8f]).ok(), Some(Network::Signet.magic()));
        assert_eq!(deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(), Some(Network::Regtest.magic()));
    }

    #[test]
    fn string_test() {
        assert_eq!(Network::Groestlcoin.to_string(), "groestlcoin");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");

        assert_eq!("groestlcoin".parse::<Network>().unwrap(), Network::Groestlcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("signet".parse::<Network>().unwrap(), Network::Signet);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(flags2.has(*f), *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO);
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!("ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)", flag.to_string());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        use Network::*;
        let tests = vec![
            (Groestlcoin, "groestlcoin"),
            (Testnet, "testnet"),
            (Signet, "signet"),
            (Regtest, "regtest"),
        ];

        for tc in tests {
            let network = tc.0;

            let want = format!("\"{}\"", tc.1);
            let got = serde_json::to_string(&tc.0).expect("failed to serialize network");
            assert_eq!(got, want);

            let back: Network = serde_json::from_str(&got).expect("failed to deserialize network");
            assert_eq!(back, network);
        }
    }

    #[test]
    fn from_to_core_arg() {
        let expected_pairs = [
            (Network::Groestlcoin, "main"),
            (Network::Testnet, "test"),
            (Network::Regtest, "regtest"),
            (Network::Signet, "signet"),
        ];

        for (net, core_arg) in &expected_pairs {
            assert_eq!(Network::from_core_arg(core_arg), Ok(*net));
            assert_eq!(net.to_core_arg(), *core_arg);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_core_arg() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(with = "crate::network::as_core_arg")]
            pub network: Network,
        }

        serde_test::assert_tokens(
            &T { network: Network::Groestlcoin },
            &[
                serde_test::Token::Struct { name: "T", len: 1 },
                serde_test::Token::Str("network"),
                serde_test::Token::Str("main"),
                serde_test::Token::StructEnd,
            ],
        );
    }
}
