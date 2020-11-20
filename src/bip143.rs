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

//! BIP143 Implementation
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use encode::{self, Encodable};
use hash_types::SigHash;
use hashes::{sha256d, Hash};
use script::Script;
use std::ops::Deref;
use std::io;
use transaction::SigHashType;
use transaction::Transaction;

/// A replacement for SigHashComponents which supports all sighash modes
pub struct SigHashCache<R: Deref<Target = Transaction>> {
    /// Access to transaction required for various introspection
    tx: R,
    /// Hash of all the previous outputs, computed as required
    hash_prevouts: Option<sha256d::Hash>,
    /// Hash of all the input sequence nos, computed as required
    hash_sequence: Option<sha256d::Hash>,
    /// Hash of all the outputs in this transaction, computed as required
    hash_outputs: Option<sha256d::Hash>,
    /// Hash of all the issunaces in this transaction, computed as required
    hash_issuances: Option<sha256d::Hash>,
}

impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        SigHashCache {
            tx: tx,
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
            hash_issuances: None,
        }
    }

    /// Calculate hash for prevouts
    pub fn hash_prevouts(&mut self) -> sha256d::Hash {
        let hash_prevout = &mut self.hash_prevouts;
        let input = &self.tx.input;
        *hash_prevout.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                txin.previous_output.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for input sequence values
    pub fn hash_sequence(&mut self) -> sha256d::Hash {
        let hash_sequence = &mut self.hash_sequence;
        let input = &self.tx.input;
        *hash_sequence.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                txin.sequence.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for issuances
    pub fn hash_issuances(&mut self) -> sha256d::Hash {
        let hash_issuance = &mut self.hash_issuances;
        let input = &self.tx.input;
        *hash_issuance.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                if txin.has_issuance() {
                    txin.asset_issuance.consensus_encode(&mut enc).unwrap();
                } else {
                    0u8.consensus_encode(&mut enc).unwrap();
                }
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for outputs
    pub fn hash_outputs(&mut self) -> sha256d::Hash {
        let hash_output = &mut self.hash_outputs;
        let output = &self.tx.output;
        *hash_output.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txout in output {
                txout.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: SigHashType,
    ) -> Result<(), encode::Error> {
        let zero_hash = sha256d::Hash::default();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.hash_prevouts().consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay && sighash != SigHashType::Single && sighash != SigHashType::None {
            self.hash_sequence().consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        // Elements: Push the hash issuance zero hash as required
        // If required implement for issuance, but not necessary as of now
        if !anyone_can_pay {
            self.hash_issuances().consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        // input specific values
        {
            let txin = &self.tx.input[input_index];

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
            if txin.has_issuance(){
                txin.asset_issuance.consensus_encode(&mut writer)?;
            }
        }

        // hashoutputs
        if sighash != SigHashType::Single && sighash != SigHashType::None {
            self.hash_outputs().consensus_encode(&mut writer)?;
        } else if sighash == SigHashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = SigHash::engine();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            SigHash::from_engine(single_enc).consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.as_u32().consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Compute the BIP143 sighash for any flag type.
    pub fn signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: SigHashType
    ) -> SigHash {
        let mut enc = SigHash::engine();
        self.encode_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)
            .expect("engines don't error");
        SigHash::from_engine(enc)
    }
}
