use grin_wallet_util::grin_keychain::{Identifier, SwitchCommitmentType};
use secp256k1zkp::{pedersen::{Commitment, ProofMessage}, Secp256k1};

use crate::Error;

pub fn subarray(buffer: &[u8], start: usize, end: Option<usize>) -> Vec<u8> {
    let end = end.unwrap_or(buffer.len());
    buffer[start..end].to_vec()
}

