use blake2::{Blake2b, Digest};
use grin_wallet_util::grin_keychain::Identifier;
use grin_wallet_util::grin_keychain::{BlindSum, SwitchCommitmentType};
use secp256k1zkp::key::SecretKey;
use secp256k1zkp::Secp256k1;
use std::convert::TryFrom;

const MESSAGE_START: &[u8] = &[0, 0];
const MESSAGE_SWITCH_TYPE_INDEX: usize = MESSAGE_START.len();
const MESSAGE_IDENTIFIER_INDEX: usize = MESSAGE_SWITCH_TYPE_INDEX + 1;
const IDENTIFIER_LENGTH: usize = 32; // Assuming Identifier.LENGTH is 32
const MESSAGE_LENGTH: usize = MESSAGE_IDENTIFIER_INDEX + IDENTIFIER_LENGTH;

pub struct ProofBuilder {
	rewind_hash: [u8; 32],
}

impl ProofBuilder {
	pub fn new(root_public_key: &[u8]) -> Self {
		let mut hasher = Blake2b::new();
		hasher.update(root_public_key);
		let hash_result = hasher.finalize();
		let rewind_hash =
			<[u8; 32]>::try_from(hash_result.as_slice()).expect("Hash should be 32 bytes");

		ProofBuilder { rewind_hash }
	}

	pub async fn get_rewind_nonce(&self, commitment: &[u8]) -> Result<[u8; 32], &'static str> {
		let mut hasher = Blake2b::new();
		hasher.update(&commitment);
		hasher.update(&self.rewind_hash);
		let hash_result = hasher.finalize();
		let rewind_nonce =
			<[u8; 32]>::try_from(hash_result.as_slice()).expect("Hash should be 32 bytes");

		let secp = Secp256k1::new();
		let secret_key = SecretKey::from_slice(&rewind_nonce).map_err(|_| "Invalid commitment")?;
		if secp.is_valid_secret_key(&secret_key) {
			Ok(rewind_nonce)
		} else {
			Err("Invalid commitment")
		}
	}

	pub fn decode_message(message: &[u8]) -> Result<(Identifier, u8), &'static str> {
		if message.len() != MESSAGE_LENGTH || &message[0..MESSAGE_START.len()] != MESSAGE_START {
			return Err("Invalid message");
		}

		let switch_type = message[MESSAGE_SWITCH_TYPE_INDEX];
		if switch_type != SwitchCommitmentType::None && switch_type != SwitchCommitmentType::Regular
		{
			return Err("Invalid message switch type");
		}

		let identifier = Identifier(
			&message[MESSAGE_IDENTIFIER_INDEX..MESSAGE_IDENTIFIER_INDEX + IDENTIFIER_LENGTH],
		);

		Ok((identifier, switch_type))
	}

	pub fn encode_message(
		identifier: &Identifier,
		switch_type: u8,
	) -> Result<Vec<u8>, &'static str> {
		if switch_type > 0xff {
			return Err("Invalid switchType");
		}

		let mut message = vec![0u8; MESSAGE_LENGTH];
		message[MESSAGE_SWITCH_TYPE_INDEX] = switch_type;
		message[MESSAGE_IDENTIFIER_INDEX..MESSAGE_IDENTIFIER_INDEX + IDENTIFIER_LENGTH]
			.copy_from_slice(&identifier.to_bytes());

		Ok(message)
	}
}
