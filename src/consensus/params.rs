// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Bitcoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Bitcoin
//! chains (such as mainnet, testnet).
//!

use crate::network::constants::Network;
use crate::util::uint::Uint256;

/// Lowest possible difficulty for Mainnet. See comment on Params::pow_limit for more info.
const MAX_BITS_BITCOIN: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00000fffffffffffu64,
]);
/// Lowest possible difficulty for Testnet. See comment on Params::pow_limit for more info.
const MAX_BITS_TESTNET: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x000000ffffffffffu64,
]);
/// Lowest possible difficulty for Signet. See comment on Params::pow_limit for more info.
const MAX_BITS_SIGNET: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00000377ae000000u64,
]);
/// Lowest possible difficulty for Regtest. See comment on Params::pow_limit for more info.
const MAX_BITS_REGTEST: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00ffffffffffffffu64,
]);

/// Parameters that influence chain consensus.
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when BIP16 becomes active.
    pub bip16_time: u32,
    /// Block height at which BIP34 becomes active.
    pub bip34_height: u32,
    /// Block height at which BIP65 becomes active.
    pub bip65_height: u32,
    /// Block height at which BIP66 becomes active.
    pub bip66_height: u32,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
    /// Proof of work limit value. It contains the lowest possible difficulty.
    ///
    /// Note that this value differs from Bitcoin Core's powLimit field in that this value is
    /// attainable, but Bitcoin Core's is not. Specifically, because targets in Bitcoin are always
    /// rounded to the nearest float expressible in "compact form", not all targets are attainable.
    /// Still, this should not affect consensus as the only place where the non-compact form of
    /// this is used in Bitcoin Core's consensus algorithm is in comparison and there are no
    /// compact-expressible values between Bitcoin Core's and the limit expressed here.
    pub pow_limit: Uint256,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u64,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
}

impl Params {
    /// Creates parameters set for the given network.
    pub fn new(network: Network) -> Self {
        match network {
            Network::Groestlcoin => Params {
                network: Network::Groestlcoin,
                bip16_time: 0,
                bip34_height: 800000, // 0000000007f3f37410d5f7e71a07bf09bb802d5af6726fc891f0248ad857708c
                bip65_height: 2464000, // 00000000000030f90269dd2c0fb5f7502f332cd183b1596817f0cc4cfd6966b1
                bip66_height: 800000, // 0000000007f3f37410d5f7e71a07bf09bb802d5af6726fc891f0248ad857708c
                rule_change_activation_threshold: 1815, // 90%
                miner_confirmation_window: 2016,
                pow_limit: MAX_BITS_BITCOIN,
                pow_target_spacing: 60,            // 1 minute.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: false,
                no_pow_retargeting: false,
            },
            Network::Testnet => Params {
                network: Network::Testnet,
                bip16_time: 0,
                bip34_height: 286, // 0000004b7778ba253a75b716c55b2c6609b5fb97691b3260978f9ce4a633106d
                bip65_height: 982000, // 000000204a7e703f80543d9329d4b90e4269e08f36ad746cfe145add340b8738
                bip66_height: 286, // 0000004b7778ba253a75b716c55b2c6609b5fb97691b3260978f9ce4a633106d
                rule_change_activation_threshold: 1512, // 75%
                miner_confirmation_window: 2016,
                pow_limit: MAX_BITS_TESTNET,
                pow_target_spacing: 60,            // 1 minute.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: true,
                no_pow_retargeting: false,
            },
            Network::Signet => Params {
                network: Network::Signet,
                bip16_time: 0,
                bip34_height: 1,
                bip65_height: 1,
                bip66_height: 1,
                rule_change_activation_threshold: 1815, // 90%
                miner_confirmation_window: 2016,
                pow_limit: MAX_BITS_SIGNET,
                pow_target_spacing: 60,            // 1 minute.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: false,
                no_pow_retargeting: false,
            },
            Network::Regtest => Params {
                network: Network::Regtest,
                bip16_time: 0,
                bip34_height: 1,
                bip65_height: 1,
                bip66_height: 1,
                rule_change_activation_threshold: 108, // 75%
                miner_confirmation_window: 144,
                pow_limit: MAX_BITS_REGTEST,
                pow_target_spacing: 60,            // 1 minute.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: true,
                no_pow_retargeting: true,
            },
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}
