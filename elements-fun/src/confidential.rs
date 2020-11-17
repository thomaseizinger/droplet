// Rust Elements Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@blockstream.com>
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

//! # Confidential Commitments
//!
//! Structures representing Pedersen commitments of various types
//!

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{fmt, io};

use crate::encode::{self, Decodable, Encodable};

// Helper macro to implement various things for the various confidential
// commitment types
macro_rules! impl_confidential_commitment {
    ($name:ident, $prefixA:expr, $prefixB:expr) => {
        impl $name {
            pub const fn is_valid_prefix(tag: u8) -> bool {
                tag == $prefixA || tag == $prefixB
            }

            pub fn new(tag: u8, commitment: &[u8]) -> Result<Self, encode::Error> {
                if commitment.len() != 32 {
                    return Err(encode::Error::ParseFailed(
                        "commitments must be 32 bytes long",
                    ));
                }

                if !Self::is_valid_prefix(tag) {
                    return Err(encode::Error::InvalidConfidentialPrefix(tag));
                }
                let mut bytes = [0u8; 33];
                bytes[0] = tag;
                bytes[1..].copy_from_slice(&commitment);

                Ok(Self(bytes))
            }

            pub fn from_slice(bytes: &[u8]) -> Result<$name, encode::Error> {
                Self::new(bytes[0], &bytes[1..])
            }

            pub fn commitment(&self) -> [u8; 33] {
                self.0
            }

            pub fn encoded_length(&self) -> usize {
                33
            }
        }

        impl hex::FromHex for $name {
            type Error = encode::Error;

            fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
                let bytes = Vec::<u8>::from_hex(hex)
                    .map_err(|_| encode::Error::ParseFailed("failed to parse as hex"))?; // TODO: Proper error handling

                Ok($name::from_slice(&bytes)?)
            }
        }

        impl Encodable for $name {
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
                self.0.consensus_encode(&mut s)
            }
        }

        impl Decodable for $name {
            fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<$name, encode::Error> {
                let bytes = <[u8; 33]>::consensus_decode(&mut d)?;

                Ok(Self::new(bytes[0], &bytes[1..])?)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                for b in self.0.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }

        #[cfg(feature = "serde")]
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;

                let mut seq = s.serialize_seq(Some(33))?;
                seq.serialize_element(self.0.as_ref())?;
                seq.end()
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                use serde::de::{Error, SeqAccess, Visitor};
                struct CommitVisitor;

                impl<'de> Visitor<'de> for CommitVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("a committed value")
                    }

                    fn visit_seq<A: SeqAccess<'de>>(
                        self,
                        mut access: A,
                    ) -> Result<Self::Value, A::Error> {
                        let prefix: u8 = if let Some(x) = access.next_element()? {
                            x
                        } else {
                            return Err(A::Error::custom("missing prefix"));
                        };

                        if prefix != $prefixA && prefix != $prefixB {
                            return Err(A::Error::custom("missing commitment"));
                        }

                        let bytes = access
                            .next_element::<[u8; 32]>()?
                            .ok_or_else(|| A::Error::custom("missing commitment"))?;

                        Ok($name::new(prefix, &bytes).map_err(A::Error::custom)?)
                    }
                }

                d.deserialize_seq(CommitVisitor)
            }
        }
    };
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct AssetCommitment([u8; 33]);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ValueCommitment([u8; 33]);

// TODO: Rename to nonce once other one is deleted
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct NonceCommitment([u8; 33]);

impl_confidential_commitment!(AssetCommitment, 0x0a, 0x0b);
impl_confidential_commitment!(ValueCommitment, 0x08, 0x09);
impl_confidential_commitment!(NonceCommitment, 0x02, 0x03);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitments() {
        let x = ValueCommitment::new(0x08, &[1; 32]).unwrap();
        let mut commitment = x.commitment();
        assert_eq!(x, ValueCommitment::from_slice(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(ValueCommitment::from_slice(&commitment[..]).is_err());

        let x = AssetCommitment::new(0x0a, &[1; 32]).unwrap();
        let mut commitment = x.commitment();
        assert_eq!(x, AssetCommitment::from_slice(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(AssetCommitment::from_slice(&commitment[..]).is_err());

        let x = NonceCommitment::new(0x02, &[1; 32]).unwrap();
        let mut commitment = x.commitment();
        assert_eq!(x, NonceCommitment::from_slice(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(NonceCommitment::from_slice(&commitment[..]).is_err());
    }
}