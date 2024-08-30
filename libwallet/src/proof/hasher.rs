use digest::generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

use crate::grin_core::global::is_floonet;
use crate::grin_keychain::extkey_bip32::{BIP32Hasher, ChildNumber, ExtendedPrivKey};
use crate::grin_keychain::Keychain;
use crate::grin_keychain::SwitchCommitmentType;
use crate::grin_util::secp::key::SecretKey;

use crate::Error;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Debug)]
///BIP32GrinboxHasher
pub struct BIP32GrinboxHasher {
	is_floonet: bool,
	hmac_sha512: HmacSha512,
}

impl BIP32GrinboxHasher {
	/// New empty hasher
	pub fn new(is_floonet: bool) -> Self {
		Self {
			is_floonet,
			hmac_sha512: HmacSha512::new(GenericArray::from_slice(&[0u8; 128])),
		}
	}
}

impl BIP32Hasher for BIP32GrinboxHasher {
	fn network_priv(&self) -> [u8; 4] {
		match self.is_floonet {
			true => [42, 0, 0, 42],
			false => [42, 1, 0, 42],
		}
	}
	fn network_pub(&self) -> [u8; 4] {
		match self.is_floonet {
			true => [42, 0, 1, 42],
			false => [42, 1, 1, 42],
		}
	}
	fn master_seed() -> [u8; 12] {
		b"Grinbox_seed".to_owned()
	}
	fn init_sha512(&mut self, seed: &[u8]) {
		self.hmac_sha512 = HmacSha512::new_from_slice(seed).expect("HMAC can take key of any size");
	}
	fn append_sha512(&mut self, value: &[u8]) {
		self.hmac_sha512.update(value);
	}
	fn result_sha512(&mut self) -> [u8; 64] {
		let mut result = [0; 64];
		result.copy_from_slice(self.hmac_sha512.clone().finalize().into_bytes().as_slice());
		result
	}
	fn sha_256(&self, input: &[u8]) -> [u8; 32] {
		let mut sha2_res = [0; 32];
		let mut sha2 = Sha256::new();
		sha2.update(input);
		sha2_res.copy_from_slice(sha2.finalize().as_slice());
		sha2_res
	}
	fn ripemd_160(&self, input: &[u8]) -> [u8; 20] {
		let mut ripemd_res = [0; 20];
		let mut ripemd = Ripemd160::new();
		ripemd.update(input);
		ripemd_res.copy_from_slice(ripemd.finalize().as_slice());
		ripemd_res
	}
}

///this derive_address_key will used in both mwc-wallet and wallet713 to derive the key.
pub fn derive_address_key<K: Keychain>(keychain: &K, index: u32) -> Result<SecretKey, Error> {
	let root = keychain
		.derive_key(713, &K::root_key_id(), SwitchCommitmentType::Regular)
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	let mut hasher = BIP32GrinboxHasher::new(is_floonet());
	let secp = keychain.secp();
	let master = ExtendedPrivKey::new_master(secp, &mut hasher, &root.0)
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	let private_key = master
		.ckd_priv(secp, &mut hasher, ChildNumber::from_normal_idx(index))
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	Ok(private_key.secret_key)
}
