// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//!
//! This module exports cipher names for use with [Preferred].
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::LazyLock;

use delegate::delegate;
use ssh_encoding::Encode;

use self::none::NoMacAlgorithm;
use crate::crypto::provider;

pub(crate) mod crypto;
pub(crate) mod crypto_etm;
mod none;

pub(crate) trait MacAlgorithm {
    fn key_len(&self) -> usize;
    fn make_mac(&self, key: &[u8]) -> Box<dyn Mac + Send>;
}

pub(crate) trait Mac {
    fn mac_len(&self) -> usize;
    fn is_etm(&self) -> bool {
        false
    }
    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]);
    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool;
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl Encode for Name {
    delegate! { to self.as_ref() {
        fn encoded_len(&self) -> Result<usize, ssh_encoding::Error>;
        fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error>;
    }}
}

impl TryFrom<&str> for Name {
    type Error = ();
    fn try_from(s: &str) -> Result<Name, ()> {
        MACS.keys().find(|x| x.0 == s).map(|x| **x).ok_or(())
    }
}

impl Name {
    /// Whether the crate feature of this MAC is enabled, so that russh
    /// negotiates it if the crypto backend implements it. Each MAC has a
    /// feature of the same name, without `@openssh.com`; `none` has the `none`
    /// feature. See [`crate::kex::Name::is_enabled`].
    pub const fn is_enabled(&self) -> bool {
        matches!(
            crate::helpers::algorithm_flags(FEATURES, self.0),
            Some((true, _))
        )
    }

    /// Whether this is a legacy MAC (SHA-1, or `none`), which
    /// `Preferred::default()` doesn't offer even when it is enabled.
    pub(crate) const fn is_legacy(&self) -> bool {
        matches!(
            crate::helpers::algorithm_flags(FEATURES, self.0),
            Some((_, true))
        )
    }
}

/// `none`
pub const NONE: Name = Name("none");
/// `hmac-sha1`
pub const HMAC_SHA1: Name = Name("hmac-sha1");
/// `hmac-sha2-256`
pub const HMAC_SHA256: Name = Name("hmac-sha2-256");
/// `hmac-sha2-512`
pub const HMAC_SHA512: Name = Name("hmac-sha2-512");
/// `hmac-sha1-etm@openssh.com`
pub const HMAC_SHA1_ETM: Name = Name("hmac-sha1-etm@openssh.com");
/// `hmac-sha2-256-etm@openssh.com`
pub const HMAC_SHA256_ETM: Name = Name("hmac-sha2-256-etm@openssh.com");
/// `hmac-sha2-512-etm@openssh.com`
pub const HMAC_SHA512_ETM: Name = Name("hmac-sha2-512-etm@openssh.com");

pub(crate) static _NONE: NoMacAlgorithm = NoMacAlgorithm {};

/// Every MAC algorithm name russh knows. The crypto backend may implement
/// only some of them; the others are never offered nor accepted.
pub const ALL_MAC_ALGORITHMS: &[&Name] = &[
    &NONE,
    &HMAC_SHA1,
    &HMAC_SHA256,
    &HMAC_SHA512,
    &HMAC_SHA1_ETM,
    &HMAC_SHA256_ETM,
    &HMAC_SHA512_ETM,
];

/// The MACs of the crypto backend (see `crate::crypto`), plus `none`.
pub(crate) static MACS: LazyLock<HashMap<&'static Name, &(dyn MacAlgorithm + Send + Sync)>> =
    LazyLock::new(|| {
        let mut h: HashMap<&'static Name, &(dyn MacAlgorithm + Send + Sync)> = HashMap::new();
        h.insert(&NONE, &_NONE);
        h.extend(provider::mac::ALGORITHMS.iter().copied());
        h
    });

/// For each MAC: its name, whether its crate feature is enabled, and whether
/// it is legacy.
const FEATURES: &[(&str, bool, bool)] = &[
    (
        HMAC_SHA512_ETM.0,
        cfg!(feature = "hmac-sha2-512-etm"),
        false,
    ),
    (
        HMAC_SHA256_ETM.0,
        cfg!(feature = "hmac-sha2-256-etm"),
        false,
    ),
    (HMAC_SHA512.0, cfg!(feature = "hmac-sha2-512"), false),
    (HMAC_SHA256.0, cfg!(feature = "hmac-sha2-256"), false),
    (HMAC_SHA1_ETM.0, cfg!(feature = "hmac-sha1-etm"), true),
    (HMAC_SHA1.0, cfg!(feature = "hmac-sha1"), true),
    (NONE.0, cfg!(feature = "none"), true),
];

#[cfg(test)]
mod tests {
    /// Every MAC has exactly one entry in `FEATURES`.
    #[test]
    fn every_mac_has_a_feature() {
        let mut names: Vec<&str> = super::FEATURES.iter().map(|(name, ..)| *name).collect();
        names.sort_unstable();
        let mut all: Vec<&str> = super::ALL_MAC_ALGORITHMS.iter().map(|n| n.0).collect();
        all.sort_unstable();
        assert_eq!(names, all);
        assert_eq!(
            super::HMAC_SHA512_ETM.is_enabled(),
            cfg!(feature = "hmac-sha2-512-etm")
        );
        assert!(super::HMAC_SHA1.is_legacy());
        assert!(!super::HMAC_SHA256.is_legacy());
    }
}
