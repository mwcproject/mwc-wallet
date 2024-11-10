// Copyright 2020 The Mwc Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate colored;
use crate::mwc_util as util;
use crate::mwc_util::secp::key::{PublicKey, SecretKey};
use crate::mwc_util::secp::pedersen::Commitment;
use crate::mwc_util::secp::{pedersen, Secp256k1, Signature};
use crate::proof::crypto::Hex;

use super::crypto;
use super::message::EncryptedMessage;
use super::proofaddress::ProvableAddress;
use crate::error::Error;
use crate::slate_versions::VersionedSlate;
use crate::Slate;
use ed25519_dalek::Verifier;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::{fs, path};
use util::Mutex;

use crate::mwc_core::core::amount_to_hr_string;
use crate::mwc_core::core::Committed;
use crate::mwc_core::global;
use colored::*;
use std::collections::HashSet;

/// Dir name with proof files
pub const TX_PROOF_SAVE_DIR: &'static str = "saved_proofs";

lazy_static! {

	/// Global proof in memory storage.
	static ref SLATE_PROOFS: Mutex< HashMap<uuid::Uuid, TxProof> > = Mutex::new(HashMap::new());
}

/// Add a txProof into the mem storage
pub fn push_proof_for_slate(uuid: &uuid::Uuid, proof: TxProof) {
	SLATE_PROOFS.lock().insert(uuid.clone(), proof);
}

/// Get txProof form the mem storage. At step we suppose to Finalize
pub fn pop_proof_for_slate(uuid: &uuid::Uuid) -> Option<TxProof> {
	SLATE_PROOFS.lock().remove(uuid)
}

/// Tx Proof - the mwc713 based proof that can be made for any address that is a public key.
/// we would like to generalize mwc713 proof implementation to be used in mwc-wallet proof framework with changing
/// of the message to generate signature in receiver wallet.
/// in mwc713 proof signature is generated using json string of  slate; and after upgrade
/// it is generated using three factors: amount,sender address and commitment sum.
#[derive(Debug, Serialize, Deserialize)]
pub struct TxProof {
	/// From address.
	pub address: ProvableAddress,
	/// Message that contain slate data
	pub message: String,
	/// Challenge
	pub challenge: String,
	/// Message & Challenge signature
	pub signature: Option<Signature>,
	/// Private key to decrypt the message
	pub key: [u8; 32],
	/// Placeholder
	pub amount: u64,
	/// Placeholder
	pub fee: u64,
	/// Placeholder
	pub inputs: Vec<Commitment>,
	/// Placeholder
	pub outputs: Vec<Commitment>,
	/// added to support the new proof implementation but be backward compatible
	pub version: Option<String>,
	/// this is the encrypted slate message
	pub slate_message: Option<String>,
	/// Tor (Dalek ed25519) signature
	pub tor_proof_signature: Option<String>,
	/// Tor Sender address
	pub tor_sender_address: Option<String>,
}

impl TxProof {
	/// Verify this Proof
	pub fn verify_extract(
		&self,
		secp: &Secp256k1,
		expected_destination: Option<&ProvableAddress>,
	) -> Result<(ProvableAddress, Slate), Error> {
		let mut challenge = String::new();
		challenge.push_str(self.message.as_str());
		challenge.push_str(self.challenge.as_str());

		let mut tor_proof = false;
		if let Some(version) = &self.version {
			if version.eq("tor") {
				tor_proof = true;
			}
		}
		if tor_proof {
			if let Some(signature) = &self.tor_proof_signature {
				let dalek_sig_vec = util::from_hex(&signature).map_err(|e| {
					Error::TxProofGenericError(format!(
						"Unable to deserialize tor payment proof signature, {}",
						e
					))
				})?;

				let dalek_sig = ed25519_dalek::Signature::from_bytes(dalek_sig_vec.as_ref())
					.map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to deserialize tor payment proof receiver signature, {}",
							e
						))
					})?;

				let receiver_dalek_pub_key = self.address.tor_public_key().map_err(|e| {
					Error::TxProofGenericError(format!(
						"Unable to deserialize tor payment proof receiver address, {}",
						e
					))
				})?;
				if let Err(e) = receiver_dalek_pub_key.verify(&challenge.as_bytes(), &dalek_sig) {
					return Err(Error::PaymentProof(format!(
						"Invalid proof signature, {}",
						e
					)))?;
				};
			}
		} else {
			let public_key = self.address.public_key().map_err(|e| {
				Error::TxProofGenericError(format!(
					"Unable to build public key from address {}, {}",
					self.address, e
				))
			})?;
			if let Some(signature) = &self.signature {
				crypto::verify_signature(&challenge, &signature, &public_key, secp)
					.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;
			} else {
				return Err(Error::TxProofVerifySignature(format!(
					"empty proof signature!"
				)));
			}
		}

		let encrypted_message: EncryptedMessage;
		if let Some(_version) = &self.version {
			//this is the newer version tx_proof
			encrypted_message = serde_json::from_str(&self.slate_message.clone().unwrap())
				.map_err(|e| {
					Error::TxProofGenericError(format!(
						"Fail to convert Json to EncryptedMessage {}, {}",
						self.message, e
					))
				})?;
		} else {
			encrypted_message = serde_json::from_str(&self.message.clone()).map_err(|e| {
				Error::TxProofGenericError(format!(
					"Fail to convert proof message Json to EncryptedMessage {}, {}",
					self.message, e
				))
			})?;
		}

		// TODO: at some point, make this check required
		let destination = &encrypted_message.destination; //sender address

		if expected_destination.is_some()
			&& destination.public_key != expected_destination.clone().unwrap().public_key
		{
			return Err(Error::TxProofVerifyDestination(
				expected_destination.unwrap().public_key.clone(),
				destination.public_key.clone(),
			));
		}

		let mut decrypted_message = encrypted_message
			.decrypt_with_key(&self.key)
			.map_err(|e| Error::TxProofGenericError(format!("Unable to decrypt message, {}", e)))?;
		//the decrypted_message cloud have been appended with the _<torkey>tor
		let mut tor_key = "tor".to_string();
		if decrypted_message.ends_with("tor") {
			let leng = decrypted_message.len();
			if leng <= 59 {
				return Err(Error::TxProofGenericError(format!(
					"Unable to build Slate form proof message"
				)));
			}
			tor_key = decrypted_message.clone()[leng - 59..].to_string();
			tor_key.truncate(56);
			decrypted_message.truncate(leng - 59); //remove the "tor" and tor_key from the elnd
		}

		let slate = Slate::deserialize_upgrade_plain(&decrypted_message).map_err(|e| {
			Error::TxProofGenericError(format!("Unable to build Slate form proof message, {}", e))
		})?;
		//for mwc713 display purpose. the destination needs to be onion address
		if let Some(onion_addr) = self.tor_sender_address.clone() {
			if tor_key != "tor" && tor_key != onion_addr {
				return Err(Error::TxProofVerifySender(tor_key.to_string(), onion_addr));
			}
			let tor_sender = ProvableAddress::from_str(&onion_addr).map_err(|e| {
				Error::TxProofGenericError(format!("Unable to create sender onion address, {}", e))
			})?;
			Ok((tor_sender, slate))
		} else {
			Ok((destination.clone(), slate))
		}
	}

	/// Build proof data. message suppose to be slate.
	pub fn from_response(
		from: &ProvableAddress,
		message: String,
		challenge: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: &ProvableAddress,
		secp: &Secp256k1,
	) -> Result<(Slate, TxProof), Error> {
		let address = from;

		let signature = util::from_hex(&signature).map_err(|e| {
			Error::TxProofGenericError(format!(
				"Unable to build signature from HEX {}, {}",
				signature, e
			))
		})?;
		let signature = Signature::from_der(secp, &signature)
			.map_err(|e| Error::TxProofGenericError(format!("Unable to build signature, {}", e)))?;

		let public_key = address.public_key().map_err(|e| {
			Error::TxProofGenericError(format!(
				"Unable to build public key for address {}, {}",
				address, e
			))
		})?;

		let encrypted_message: EncryptedMessage = serde_json::from_str(&message).map_err(|e| {
			Error::TxProofGenericError(format!(
				"Unable to build message fom HEX {}, {}",
				message, e
			))
		})?;
		let key = encrypted_message
			.key(&public_key, secret_key, secp)
			.map_err(|e| {
				Error::TxProofGenericError(format!("Unable to build a signature, {}", e))
			})?;

		let proof = TxProof {
			address: address.clone(),
			message,
			challenge,
			signature: Some(signature),
			key,
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			version: None,
			slate_message: None,
			tor_proof_signature: None,
			tor_sender_address: None,
		};

		let (_, slate) = proof.verify_extract(secp, Some(expected_destination))?;

		Ok((slate, proof))
	}

	/// Build proof data from slate
	pub fn from_slate(
		message: String,
		slate: &Slate,
		secret_key: &SecretKey,
		expected_destination: &ProvableAddress, //sender address
		tor_destination: Option<String>,        //tor onion address
		secp: &Secp256k1,
	) -> Result<TxProof, Error> {
		if let Some(p) = slate.payment_proof.clone() {
			if let Some(signature) = p.receiver_signature {
				//build the signature from signature string:
				if p.receiver_address.public_key.len() == 56 {
					let address = p.receiver_address;

					let _public_key = address.tor_public_key().map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to build dalek public key for address {}, {}",
							address, e
						))
					})?;

					//build the encrypted message from the slate
					//and generate the key.

					let version = slate.lowest_version();
					let slate = VersionedSlate::into_version_plain(slate.clone(), version)
						.map_err(|e| {
							Error::TxProofGenericError(format!("Slate serialization error, {}", e))
						})?;

					let mut slate_json_with_tor = serde_json::to_string(&slate).map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to build public key for address {}, {}",
							address, e
						))
					})?;
					if let Some(tor_des) = tor_destination.clone() {
						slate_json_with_tor = slate_json_with_tor + &tor_des + "tor";
					}

					let encrypted_message = EncryptedMessage::new(
						slate_json_with_tor,
						expected_destination, //this is the sender address
						&expected_destination.public_key().map_err(|e| {
							Error::TxProofGenericError(format!(
								"Unable to build public key for address {}, {}",
								address, e
							))
						})?,
						&secret_key,
						secp,
					)
					.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

					let message_ser = &serde_json::to_string(&encrypted_message).map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to build public key for address {}, {}",
							address, e
						))
					})?;
					let key = encrypted_message
						.key(
							&expected_destination.public_key().unwrap(),
							secret_key,
							secp,
						)
						.map_err(|e| {
							Error::TxProofGenericError(format!(
								"Unable to build a signature, {}",
								e
							))
						})?;

					//create the tor address for the sender wallet.

					let proof = TxProof {
						address: address.clone(),
						message,
						challenge: "".to_string(),
						signature: None,
						key,
						amount: 0,
						fee: 0,
						inputs: vec![],
						outputs: vec![],
						version: Some("tor".to_string()),
						slate_message: Some(message_ser.to_string()),
						tor_proof_signature: Some(signature),
						tor_sender_address: tor_destination,
					};
					proof.verify_extract(secp, Some(expected_destination))?;
					Ok(proof)
				} else {
					let address = p.receiver_address;
					let signature = util::from_hex(&signature).map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to build signature from HEX {}, {}",
							signature, e
						))
					})?;
					let signature = Signature::from_der(secp, &signature).map_err(|e| {
						Error::TxProofGenericError(format!("Unable to build signature, {}", e))
					})?;

					let _public_key = address.public_key().map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to build public key for address {}, {}",
							address, e
						))
					})?;

					//build the encrypted message from the slate
					//and generate the key.

					let version = slate.lowest_version();
					let slate = VersionedSlate::into_version_plain(slate.clone(), version)
						.map_err(|e| {
							Error::TxProofGenericError(format!("Slate serialization error, {}", e))
						})?;

					let encrypted_message = EncryptedMessage::new(
						serde_json::to_string(&slate).map_err(|e| {
							Error::TxProofGenericError(format!(
								"Unable to build public key for address {}, {}",
								address, e
							))
						})?,
						expected_destination, //this is the sender address when receiver wallet sends the slate back
						&expected_destination.public_key().map_err(|e| {
							Error::TxProofGenericError(format!(
								"Unable to build public key for address {}, {}",
								address, e
							))
						})?,
						&secret_key,
						secp,
					)
					.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

					let message_ser = &serde_json::to_string(&encrypted_message).map_err(|e| {
						Error::TxProofGenericError(format!(
							"Unable to build public key for address {}, {}",
							address, e
						))
					})?;
					let key = encrypted_message
						.key(
							&expected_destination.public_key().unwrap(),
							secret_key,
							secp,
						)
						.map_err(|e| {
							Error::TxProofGenericError(format!(
								"Unable to build a signature, {}",
								e
							))
						})?;

					let proof = TxProof {
						address: address.clone(),
						message,
						challenge: "".to_string(),
						signature: Some(signature),
						key,
						amount: 0,
						fee: 0,
						inputs: vec![],
						outputs: vec![],
						version: Some("version2".to_string()),
						slate_message: Some(message_ser.to_string()),
						tor_proof_signature: None,
						tor_sender_address: None,
					};
					proof.verify_extract(secp, Some(expected_destination))?;
					Ok(proof)
				}
			} else {
				return Err(Error::TxProofGenericError(
					"No receiver signature in payment proof in slate".to_string(),
				));
			}
		} else {
			return Err(Error::TxProofGenericError(
				"No pyament proof in slate".to_string(),
			));
		}
	}

	/// Init proff files storage
	pub fn init_proof_backend(data_file_dir: &str) -> Result<(), Error> {
		let stored_tx_proof_path = path::Path::new(data_file_dir).join(TX_PROOF_SAVE_DIR);
		fs::create_dir_all(&stored_tx_proof_path)
			.expect("Couldn't create wallet backend tx proof storage directory!");
		Ok(())
	}

	/// Check if Proofs are here
	pub fn has_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<bool, Error> {
		let filename = format!("{}.proof", uuid);
		let path = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let tx_proof_file = Path::new(&path).to_path_buf();
		Ok(tx_proof_file.exists())
	}

	/// Read stored proof file. data_file_dir
	pub fn get_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<TxProof, Error> {
		let filename = format!("{}.proof", uuid);
		let path = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let tx_proof_file = Path::new(&path).to_path_buf();
		if !tx_proof_file.exists() {
			return Err(Error::TransactionHasNoProof(
				tx_proof_file.to_str().unwrap_or(&"UNKNOWN").to_string(),
			));
		}
		let mut tx_proof_f = File::open(tx_proof_file)?;
		let mut content = String::new();
		tx_proof_f.read_to_string(&mut content)?;
		Ok(serde_json::from_str(&content).map_err(|e| {
			Error::TxProofGenericError(format!("Unable to Build TxProof from Json, {}", e))
		})?)
	}

	/// Store tx proof at the file.
	pub fn store_tx_proof(&self, data_file_dir: &str, uuid: &str) -> Result<(), Error> {
		let filename = format!("{}.proof", uuid);
		let path = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let path_buf = Path::new(&path).to_path_buf();
		let mut stored_tx = File::create(path_buf)?;
		let proof_ser = serde_json::to_string(self).map_err(|e| {
			Error::TxProofGenericError(format!("Unable to conver TxProof to Json, {}", e))
		})?;
		stored_tx.write_all(&proof_ser.as_bytes())?;
		stored_tx.sync_all()?;
		Ok(())
	}
}

///support mwc713 payment proof message
pub fn proof_ok(
	sender: Option<String>,
	receiver: String,
	amount: u64,
	outputs: Vec<String>,
	kernel: String,
) {
	let sender_message = sender
		.as_ref()
		.map(|s| format!(" from [{}]", s.bright_green()))
		.unwrap_or(String::new());

	let tor_sender_message = sender
		.as_ref()
		.map(|s| {
			format!(
				" from [{}{}{}]",
				"http://".bright_green(),
				s.bright_green(),
				".onion".bright_green()
			)
		})
		.unwrap_or(String::new());

	if receiver.len() == 56 {
		println!(
			"this file proves that [{}] MWCs was sent to [{}]{}",
			amount_to_hr_string(amount, false).bright_green(),
			format!(
				"{}{}{}",
				"http://".bright_green(),
				receiver.bright_green(),
				".onion".bright_green()
			),
			tor_sender_message
		);
	} else {
		println!(
			"this file proves that [{}] MWCs was sent to [{}]{}",
			amount_to_hr_string(amount, false).bright_green(),
			receiver.bright_green(),
			sender_message
		);
	}

	if sender.is_none() {
		println!(
			"{}: this proof does not prove which address sent the funds, only which received it",
			"WARNING".bright_yellow()
		);
	}

	println!("\noutputs:");
	if global::is_mainnet() {
		for output in outputs {
			println!(
				"   {}: https://explorer.mwc.mw/#o{}",
				output.bright_magenta(),
				output
			);
		}
		println!("kernel:");
		println!(
			"   {}: https://explorer.mwc.mw/#k{}",
			kernel.bright_magenta(),
			kernel
		);
	} else {
		for output in outputs {
			println!(
				"   {}: https://explorer.floonet.mwc.mw/#o{}",
				output.bright_magenta(),
				output
			);
		}
		println!("kernel:");
		println!(
			"   {}: https://explorer.floonet.mwc.mw/#k{}",
			kernel.bright_magenta(),
			kernel
		);
	}
	println!("\n{}: this proof should only be considered valid if the kernel is actually on-chain with sufficient confirmations", "WARNING".bright_yellow());
	println!("please use a mwc block explorer to verify this is the case.");
}

//to support mwc713 payment proof verification
fn verify_tx_proof(
	tx_proof: &TxProof,
	secp: &Secp256k1,
) -> Result<
	(
		Option<ProvableAddress>,
		ProvableAddress,
		u64,
		Vec<pedersen::Commitment>,
		pedersen::Commitment,
	),
	Error,
> {
	let (destination, slate) = tx_proof.verify_extract(secp, None).map_err(|e| {
		Error::TxProofGenericError(format!("Unable to extract destination and slate, {}", e))
	})?;

	let inputs_ex = tx_proof.inputs.iter().collect::<HashSet<_>>();

	let mut inputs: Vec<pedersen::Commitment> = slate
		.tx_or_err()?
		.inputs_committed()
		.iter()
		.filter(|c| !inputs_ex.contains(c))
		.map(|c| c.clone())
		.collect();

	let outputs_ex = tx_proof.outputs.iter().collect::<HashSet<_>>();

	let outputs: Vec<pedersen::Commitment> = slate
		.tx_or_err()?
		.outputs()
		.iter()
		.map(|o| o.commitment())
		.filter(|c| !outputs_ex.contains(c))
		.collect();

	let excess_parts: Vec<&PublicKey> = slate
		.participant_data
		.iter()
		.map(|p| &p.public_blind_excess)
		.collect();
	let excess_sum = PublicKey::from_combination(secp, excess_parts)
		.map_err(|e| Error::TxProofGenericError(format!("Unable to combine public keys, {}", e)))?;

	let commit_amount = secp.commit_value(tx_proof.amount)?;
	inputs.push(commit_amount);

	let mut input_com: Vec<pedersen::Commitment> = slate.tx_or_err()?.inputs_committed();
	let mut output_com: Vec<pedersen::Commitment> = slate.tx_or_err()?.outputs_committed();

	input_com.push(secp.commit(0, slate.tx_or_err()?.offset.secret_key(secp)?)?);

	output_com.push(secp.commit_value(slate.fee)?);

	let excess_sum_com = Secp256k1::commit_sum(secp, output_com, input_com)?;

	if excess_sum_com.to_pubkey(secp)? != excess_sum {
		return Err(Error::TxProofGenericError(
			"Excess sum mismatch".to_string(),
		));
	}

	return Ok((
		Some(destination),
		tx_proof.address.clone(),
		tx_proof.amount,
		outputs,
		excess_sum_com,
	));
}

///to support mwc713 payment proof verification
pub fn verify_tx_proof_wrapper(
	tx_proof: &TxProof,
	secp: &Secp256k1,
) -> Result<(Option<String>, String, u64, Vec<String>, String), Error> {
	let (sender, receiver, amount, outputs, excess_sum) = verify_tx_proof(tx_proof, secp)?;

	let outputs = outputs
		.iter()
		.map(|o| crate::mwc_util::to_hex(&o.0))
		.collect();

	Ok((
		sender.map(|a| a.public_key.clone()),
		receiver.public_key.clone(),
		amount,
		outputs,
		excess_sum.to_hex(),
	))
}
