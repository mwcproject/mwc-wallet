use crate::Error;
use blake2_rfc::blake2b::blake2b;
use grin_wallet_util::grin_keychain::{Identifier, SwitchCommitmentType};
use grin_wallet_util::grin_util::{to_hex, ZeroingString};
use hidapi::HidApi;
use ledger_transport::APDUAnswer;
use ledger_transport_hid::TransportNativeHID;
use secp256k1zkp::pedersen::{Commitment, ProofMessage, RangeProof};
use secp256k1zkp::{pedersen, Signature};
use secp256k1zkp::{PublicKey, Secp256k1, SecretKey};
use std::convert::TryInto;

use super::adpu::APDUCommands;
use super::types::{ParseError, Status, SECP256K1_PUBLIC_KEY_LENGTH, TAU_X_LENGTH};
use super::utils::subarray;

/// Verify all aspects of a completed payment proof on the current slate
pub fn initialize_hid_api() -> Result<HidApi, ParseError> {
	HidApi::new().map_err(|e| ParseError::HidApiError(e.to_string()))
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn create_transport(api: &HidApi) -> Result<TransportNativeHID, ParseError> {
	TransportNativeHID::new(api).map_err(|e| ParseError::TransportError(e.to_string()))
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn send_apdu_command(
	transport: &TransportNativeHID,
	command: APDUCommands,
) -> Result<Vec<u8>, ParseError> {
	let apdu_command = command.to_apdu_command();
	let transport = transport
		.exchange(&apdu_command)
		.map_err(|e| ParseError::ApduError(e.to_string()));
	match transport {
		Ok(r) => {
			match r.retcode() {
				0x9000 => Ok(r.data().to_vec()), // Success
				code => {
					let status = match code {
						0xb100 => Status::UnknownClass,
						0xb101 => Status::UnknownInstruction,
						0xb102 => Status::MalformedRequest,
						0xb103 => Status::UserRejected,
						0xb104 => Status::InternalError,
						0xd100 => Status::InvalidParameters,
						0xd101 => Status::InvalidState,
						0xd102 => Status::DeviceLocked,
						0x5515 => Status::OperatingSystemLocked,
						0x6E01 => Status::AppNotLaunched,
						_ => {
							return Err(ParseError::ApduError(format!(
								"Unknown status code: 0x{:X}",
								code
							)))
						}
					};
					Err(ParseError::LedgerStatusError(status.to_string()))
				}
			}
		}
		Err(_) => Err(ParseError::ApduCommandError),
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn rewind_hash(secp: &Secp256k1, public_root_key: PublicKey) -> Vec<u8> {
	let ser = public_root_key.serialize_vec(&secp, true);
	blake2b(32, &[], &ser[..]).as_bytes().to_vec()
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn get_rewind_nonce(
	secp: &Secp256k1,
	commit: Commitment,
	hash: Vec<u8>,
) -> Result<SecretKey, Error> {
	let res = blake2b(32, &commit.0, &hash);
	Ok(SecretKey::from_slice(secp, res.as_bytes()).unwrap())
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn proof_message(
	_secp: &Secp256k1,
	id: Identifier,
	switch: SwitchCommitmentType,
) -> Result<ProofMessage, Error> {
	let mut msg = [0; 20];
	msg[2] = switch as u8;
	let id_bytes = id.to_bytes();
	msg[3..20].clone_from_slice(&id_bytes[..17]);
	Ok(ProofMessage::from_bytes(&msg))
}

/// Get the Root Public Key of an account
pub fn get_root_public_key(
	transport: &TransportNativeHID,
	account: u32,
) -> Result<Vec<u8>, ParseError> {
	let response = send_apdu_command(
		&transport,
		APDUCommands::GetRootPublicKey { account: account },
	)
	.unwrap();
	let data = response;
	{
		if data.len() != 33 {
			return Err(ParseError::UnexpectedKeyLength);
		}
		let root_public_key = &data[0..33];
		Ok(root_public_key.to_vec())
	}
}

/// Verify the root public key of an account
pub fn verify_root_public_key(
	transport: &TransportNativeHID,
	account: u32,
) -> Result<(), ParseError> {
	let response = send_apdu_command(transport, APDUCommands::VerifyRootPublicKey { account });
	match response {
		Ok(_r) => Ok(()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn get_bulletproof_components(
	secp: &Secp256k1,
	transport: &TransportNativeHID,
	identifier: Identifier,
	value: u64,
	switch: SwitchCommitmentType,
) -> Result<(SecretKey, PublicKey, PublicKey), ParseError> {
	let identifier = identifier.to_bytes();
	let response_proof = send_apdu_command(
		transport,
		APDUCommands::GetBulletproofComponents {
			account: 0,
			identifier,
			value,
			switch_type: switch.into(),
			message_type: 0,
		},
	)
	.map_err(|_| ParseError::ApduCommandError)?;

	let get_bulletproof_components_response = response_proof;

	let tau_x = SecretKey::from_slice(
		&secp,
		&subarray(&get_bulletproof_components_response, 0, Some(TAU_X_LENGTH)),
	)
	.map_err(|_| ParseError::SecretKeyParseError)?;

	let t_one = PublicKey::from_slice(
		&secp,
		&subarray(
			&get_bulletproof_components_response,
			TAU_X_LENGTH,
			Some(TAU_X_LENGTH + SECP256K1_PUBLIC_KEY_LENGTH),
		),
	)
	.map_err(|_| ParseError::PublicKeyParseError)?;

	let t_two = PublicKey::from_slice(
		&secp,
		&subarray(
			&get_bulletproof_components_response,
			TAU_X_LENGTH + SECP256K1_PUBLIC_KEY_LENGTH,
			Some(TAU_X_LENGTH + 2 * SECP256K1_PUBLIC_KEY_LENGTH),
		),
	)
	.map_err(|_| ParseError::PublicKeyParseError)?;

	Ok((tau_x, t_one, t_two))
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn get_commitment(
	transport: &TransportNativeHID,
	identifier: Identifier,
	value: u64,
	switch: SwitchCommitmentType,
) -> Result<Commitment, ParseError> {
	let identifier = identifier.to_bytes();
	let switch = switch.into();
	let commit_response = send_apdu_command(
		&transport,
		APDUCommands::GetCommitment {
			account: 0,
			identifier: identifier,
			value: value,
			switch_type: switch,
		},
	)
	.unwrap();
	let data = commit_response;
	if data.len() != 33 {
		return Err(ParseError::UnexpectedKeyLength);
	}
	let mut commitment = [0u8; 33];
	commitment.copy_from_slice(&data[0..33]);
	let commit = Commitment(commitment);
	Ok(commit)
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn start_transations(
	transport: &TransportNativeHID,
	account: u32,
	index: u32,
	output_value: u64,
	input_value: u64,
	fee: u64,
	secret_nonce_index: Option<u8>,
	address: Option<Vec<u8>>,
) -> Result<(), ParseError> {
	let secret_nonce_index = secret_nonce_index.unwrap_or(0);
	let response = send_apdu_command(
		&transport,
		APDUCommands::StartTransaction {
			account: account,
			index: index,
			output: output_value,
			input: input_value,
			fee: fee,
			secret_nonce_index: secret_nonce_index,
			address: address,
		},
	);

	match response {
		Ok(_r) => Ok(()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn continue_transations_include_input(
	transport: &TransportNativeHID,
	identifier: Identifier,
	value: u64,
	switch: SwitchCommitmentType,
) -> Result<(), ParseError> {
	let identifier = identifier.to_bytes();
	let switch = switch.into();
	let response = send_apdu_command(
		&transport,
		APDUCommands::ContinueTransactionIncludeInput {
			identifier: identifier,
			value: value,
			switch_type: switch,
		},
	);

	match response {
		Ok(_r) => Ok(()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn continue_transations_include_output(
	transport: &TransportNativeHID,
	identifier: Identifier,
	value: u64,
	switch: SwitchCommitmentType,
) -> Result<(), ParseError> {
	let identifier = identifier.to_bytes();
	let switch = switch.into();
	let response = send_apdu_command(
		&transport,
		APDUCommands::ContinueTransactionIncludeOutput {
			identifier: identifier,
			value: value,
			switch_type: switch,
		},
	);

	match response {
		Ok(_r) => Ok(()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn continue_transations_apply_offset(
	transport: &TransportNativeHID,
	offset: [u8; 32],
) -> Result<Vec<u8>, ParseError> {
	let response = send_apdu_command(
		&transport,
		APDUCommands::ContinueTransactionApplyOffset { offset: offset },
	);

	match response {
		Ok(r) => Ok(r.into()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Returns the signature for a provided UTF-8 message signed with the app's
/// internal transaction state's blinding factor.
pub fn continue_transations_get_public_key(
	transport: &TransportNativeHID,
) -> Result<Vec<u8>, ParseError> {
	let response = send_apdu_command(&transport, APDUCommands::ContinueTransactionGetPublicKey {});

	match response {
		Ok(r) => Ok(r.into()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Returns the signature for a provided UTF-8 message signed with the app's
/// internal transaction state's blinding factor.
pub fn continue_transations_get_message_signature(
	transport: &TransportNativeHID,
) -> Result<Vec<u8>, ParseError> {
	let response = send_apdu_command(&transport, APDUCommands::ContinueTransactionGetPublicKey {});

	match response {
		Ok(r) => Ok(r.into()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Returns the signature for a provided UTF-8 message signed with the app's
/// internal transaction state's blinding factor.
pub fn finish_transactions(
	transport: &TransportNativeHID,
	address_type: Option<u8>,
	public_nonce: [u8; 33],
	public_key: [u8; 33],
	kernel_type: u8,
	kernel_commitment: Option<[u8; 33]>,
	payment_proof: Option<Vec<u8>>,
) -> Result<Vec<u8>, ParseError> {
	let response = send_apdu_command(
		&transport,
		APDUCommands::FinishTransaction {
			address_type: address_type,
			public_nonce: public_nonce,
			public_key: public_key,
			kernel_type: kernel_type,
			kernel_commitment: kernel_commitment,
			payment_proof: payment_proof,
		},
	);

	match response {
		Ok(r) => Ok(r.into()),
		Err(_e) => Err(ParseError::UnexpectedKeyLength),
	}
}

/// Function to prompt for root public key
pub fn prompt_pk(account: u32) -> Result<ZeroingString, ParseError> {
	let api = initialize_hid_api()?;
	let transport = create_transport(&api)?;
	let root_pk = get_root_public_key(&transport, account).unwrap();
	Ok(ZeroingString::from(to_hex(&root_pk)))
}

/// Verify all aspects of a completed payment proof on the current slate
fn parse_app_info(data: &[u8]) {
	if data.is_empty() {
		println!("No response data received.");
		return;
	}

	if data.len() > 2 {
		let app_name_len = data[1] as usize;
		if data.len() >= 2 + app_name_len {
			let app_name = &data[2..2 + app_name_len];
			println!("App Name: {:?}", String::from_utf8_lossy(app_name));
		} else {
			println!("Insufficient data for application name.");
		}

		let app_version_start = 2 + app_name_len + 1;
		if data.len() > app_version_start {
			let app_version_len = data[app_version_start - 1] as usize;
			if data.len() >= app_version_start + app_version_len {
				let app_version = &data[app_version_start..app_version_start + app_version_len];
				println!("App Version: {:?}", String::from_utf8_lossy(app_version));
			} else {
				println!("Insufficient data for application version.");
			}
		} else {
			println!("Insufficient data for application version length.");
		}
	} else {
		println!("Unexpected response length.");
	}
}

/// Verify all aspects of a completed payment proof on the current slate
fn parse_device_info(data: &[u8]) {
	if data.is_empty() {
		println!("Unexpected response length.");
		return;
	}

	let mut index = 0;

	// Parse the target ID
	if data.len() >= index + 4 {
		let target_id = &data[index..index + 4];
		println!("Target ID: {:?}", target_id);
		index += 4;
	} else {
		println!("Insufficient data for Target ID.");
	}

	// Parse the version length
	if data.len() > index {
		let version_len = data[index] as usize;
		index += 1;
		if data.len() >= index + version_len {
			let version = &data[index..index + version_len];
			println!("Version: {:?}", String::from_utf8_lossy(version));
			index += version_len;
		} else {
			println!("Insufficient data for version information.");
		}
	} else {
		println!("Insufficient data for version length.");
	}

	// Check if the device is locked based on a specific byte (assuming it's at a specific position)
	if data.len() > index && data[index] == 1 {
		println!("The device is locked.");
	} else {
		println!("The device is unlocked.");
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn parse_response(data: &[u8]) -> Result<[u8; 33], ParseError> {
	// Ensure the data length is 33
	if data.len() == 33 {
		// Try to convert the slice to a fixed-size array
		match data.try_into() {
			Ok(array) => Ok(array),
			Err(_) => Err(ParseError::ConversionError),
		}
	} else {
		Err(ParseError::ConversionError)
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn parse_bp(data: &[u8]) -> Result<[u8; 675], ParseError> {
	// Ensure the data length is 33
	if data.len() > 675 {
		// Try to convert the slice to a fixed-size array
		match data.try_into() {
			Ok(array) => Ok(array),
			Err(_) => Err(ParseError::ConversionError),
		}
	} else {
		Err(ParseError::ConversionError)
	}
}
