use ledger_transport::APDUCommand;

/// Verify all aspects of a completed payment proof on the current slate
pub fn create_command(
	class: u8,
	instruction: u8,
	p1: u8,
	p2: u8,
	data: Vec<u8>,
) -> APDUCommand<Vec<u8>> {
	APDUCommand {
		cla: class,
		ins: instruction,
		p1,
		p2,
		data,
	}
}
/// Verify all aspects of a completed payment proof on the current slate
pub enum APDUCommands {
	/// Returns an account's root public key after displaying a message on the device's
	/// screen to obtain the user's approval. The root public key can be used to create a view key.
	GetRootPublicKey { account: u32 },

	/// Returns an account's MQS or Tor address at a provided index.
	/// This address is also the account's payment proof address at the provided index.
	GetAddress {
		account: u32,
		index: u32,
		address_type: u8,
	},

	/// Returns the SHA512 hash of the account's root public key.
	/// This hash can be used to determine if a connected hardware
	/// wallet corresponds to a previously obtained root public key.
	GetSeedCookie { account: u32 },

	/// Returns the account's commitment for the provided identifier, value, and switch type.
	GetCommitment {
		account: u32,
		identifier: [u8; 17],
		value: u64,
		switch_type: u8,
	},

	/// Returns the account's bulletproof components tau x, t one, and t two for the provided identifier, value, and switch type.
	/// These bulletproof components can be used to create a bulletproof. A processing message is displayed on the device for the duration
	/// of this command that shows either sending transaction, receiving transaction, or creating coinbase depending on the parameter provided.
	///
	/// This command takes about 50 seconds to complete on a Ledger Nano S hardware wallet and about 25 seconds to complete on a Ledger Nano S Plus hardware wallet.
	GetBulletproofComponents {
		account: u32,
		identifier: [u8; 17],
		value: u64,
		switch_type: u8,
		message_type: u8,
	},

	/// Displays the account's root public key on the device and returns if the user verifies if the root public key is valid.
	VerifyRootPublicKey { account: u32 },

	/// Displays the account's MQS or Tor address at a provided index on the device and returns if the user verifies if the address is valid.
	VerifyAddress {
		account: u32,
		index: u32,
		address_type: u8,
	},

	/// Prepares the app's internal slate state to be able to encrypt data that will be provided
	/// later as an account at a provided index that can be decrypted by a provided address.
	/// An MQS recipient address can include an optional domain and port.
	StartEncryptingSlate {
		account: u32,
		index: u32,
		recipient_address: Vec<u8>,
	},

	/// Encrypts the provided data using the app's internal slate state and returns it.
	/// The data must be provided in chunks of 64 bytes with the last chunk allowed to be less than 64 bytes.
	ContinueEncryptingSlate { data: Vec<u8> },

	/// Returns the tag for all the data that was encrypted.
	FinishEncryptingSlate,

	/// Prepares the app's internal slate state to be able to decrypt data that will be provided
	/// later as an account at a provided index using a provided nonce and optional salt that was encrypted by a provided address.
	StartDecryptingSlate {
		account: u32,
		index: u32,
		nonce: [u8; 12],
		sender_address: Vec<u8>,
		salt: Option<[u8; 8]>,
	},
	/// Decrypts the provided data using the app's internal slate
	/// state and returns it encrypted with a random AES key.
	/// The data must be provided in chunks of 64 bytes with the last chunk allowed to be less than 64 bytes.
	ContinueDecryptingSlate { data: Vec<u8> },

	/// Returns the AES key used to encrypt the decrypted data chunks if a valid tag is provided.
	FinishDecryptingSlate { tag: [u8; 16] },

	/// Prepares the app's internal transaction state to be able to process a transaction
	/// that will be provided later as an account at a provided index using a provided output,
	/// input, fee, and secret nonce index. The secret nonce index select which previously generated
	///  secret nonce to use when sending. An optional sender or recipient address depending on
	/// if the transaction is received or sent can be provided if this transaction contains a payment proof.
	StartTransaction {
		account: u32,
		index: u32,
		output: u64,
		input: u64,
		fee: u64,
		secret_nonce_index: u8,
		address: Option<Vec<u8>>,
	},

	/// Includes the output for a provided identifier, value, and switch type in the transaction in the app's internal transaction state.
	ContinueTransactionIncludeOutput {
		identifier: [u8; 17],
		value: u64,
		switch_type: u8,
	},

	/// Includes the input for a provided identifier, value, and switch type in the transaction in the app's internal transaction state.
	ContinueTransactionIncludeInput {
		identifier: [u8; 17],
		value: u64,
		switch_type: u8,
	},

	/// Applies an offset to the transaction's blinding factor in the app's internal transaction state.
	/// Returns the secret nonce index if transaction is send and doesn't have a secret nonce.
	ContinueTransactionApplyOffset { offset: [u8; 32] },

	/// Returns the app's internal transaction state's blinding factor's public key.
	ContinueTransactionGetPublicKey,

	/// Returns the app's internal transaction state's public nonce.
	ContinueTransactionGetPublicNonce,

	/// Returns the signature for a provided UTF-8 message signed with the app's internal transaction state's blinding factor.
	ContinueTransactionGetMessageSignature { message: Vec<u8> },

	/// Returns the signature for the provided kernel information signed with the app's internal transaction state's blinding factor after obtaining user's approval.
	///
	/// A payment proof signature will be returned if receiving a payment, a kernel_commitment is provided, and an address was provided to the START_TRANSACTION command.
	/// In this situation, the the address provided to START_TRANSACTION will be treated as the sender's address and the address_type will
	/// be treated as the desired receiver's address type.
	///
	/// A payment proof address will be displayed if a kernel_commitment is provided, a payment_proof is provided if sending a payment,
	/// and an address was provided to the START_TRANSACTION command. In this situation, the the address provided to START_TRANSACTION
	/// will be treated as the receiver's address if sending a payment or the sender's address if receiving a payment.
	/// The address_type will be treated as the desired sender's address type if sending a payment or the desired receiver's address type if receiving a payment.
	/// The payment proof address displayed will be the recipient's payment proof address if sending a payment or the sender's payment proof address if receiving a payment.
	///
	/// If a sent transaction needs to be finalized at a later time, then the app's internal slate state can be restored by starting a transaction, including the same inputs and outputs, applying the same offset, and using the secret nonce index that was previously obtained with a CONTINUE_TRANSACTION_APPLY_OFFSET command.
	FinishTransaction {
		address_type: Option<u8>,
		public_nonce: [u8; 33],
		public_key: [u8; 33],
		kernel_type: u8,
		kernel_commitment: Option<[u8; 33]>,
		payment_proof: Option<Vec<u8>>,
	},

	/// Returns the signature for a provided timestamp or hardcoded challenge signed with an account's MQS private key
	/// at a provided index after obtaining user's approval. The default challenge, 7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc,
	/// will be signed if no timestamp is provided.
	GetMQSChallengeSignature {
		account: u32,
		index: u32,
		timestamp: Option<u64>,
		time_zone_offset: Option<i16>,
	},

	/// Returns the signature for a provided timestamp and identifier signed with an account's login private key after obtaining user's approval.
	GetLoginChallengeSignature {
		account: u32,
		timestamp: u64,
		time_zone_offset: i16,
		identifier: Vec<u8>,
	},
	/// Get Device Info
	GetDeviceInfo,

	/// Get App Info
	GetAppInfo,
}

impl APDUCommands {
	/// Verify all aspects of a completed payment proof on the current slate
	pub fn to_apdu_command(&self) -> APDUCommand<Vec<u8>> {
		match self {
			APDUCommands::GetRootPublicKey { account } => {
				create_command(0xC7, 0x00, 0x00, 0x00, account.to_le_bytes().to_vec())
			}

			APDUCommands::GetAddress {
				account,
				index,
				address_type,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(&index.to_le_bytes());
				create_command(0xC7, 0x01, *address_type, 0x00, data)
			}

			APDUCommands::GetSeedCookie { account } => {
				create_command(0xC7, 0x02, 0x00, 0x00, account.to_le_bytes().to_vec())
			}

			APDUCommands::GetCommitment {
				account,
				identifier,
				value,
				switch_type,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(identifier);
				data.extend_from_slice(&value.to_le_bytes());
				data.push(*switch_type);
				create_command(0xC7, 0x03, 0x00, 0x00, data)
			}

			APDUCommands::GetBulletproofComponents {
				account,
				identifier,
				value,
				switch_type,
				message_type,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(identifier);
				data.extend_from_slice(&value.to_le_bytes());
				data.push(*switch_type);
				create_command(0xC7, 0x04, *message_type, 0x00, data)
			}
			APDUCommands::VerifyRootPublicKey { account } => {
				create_command(0xC7, 0x05, 0x00, 0x00, account.to_le_bytes().to_vec())
			}

			APDUCommands::VerifyAddress {
				account,
				index,
				address_type,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(&index.to_le_bytes());
				create_command(0xC7, 0x06, *address_type, 0x00, data)
			}
			APDUCommands::StartEncryptingSlate {
				account,
				index,
				recipient_address,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(&index.to_le_bytes());
				data.extend_from_slice(recipient_address);
				create_command(0xC7, 0x07, 0x00, 0x00, data)
			}
			APDUCommands::ContinueEncryptingSlate { data } => {
				create_command(0xC7, 0x08, 0x00, 0x00, data.clone())
			}
			APDUCommands::FinishEncryptingSlate => create_command(0xC7, 0x09, 0x00, 0x00, vec![]),
			APDUCommands::StartDecryptingSlate {
				account,
				index,
				nonce,
				sender_address,
				salt,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(&index.to_le_bytes());
				data.extend_from_slice(nonce);
				data.extend_from_slice(sender_address);
				if let Some(s) = salt {
					data.extend_from_slice(s);
				}
				create_command(0xC7, 0x0A, 0x00, 0x00, data)
			}
			APDUCommands::ContinueDecryptingSlate { data } => {
				create_command(0xC7, 0x0B, 0x00, 0x00, data.clone())
			}
			APDUCommands::FinishDecryptingSlate { tag } => {
				create_command(0xC7, 0x0C, 0x00, 0x00, tag.to_vec())
			}
			APDUCommands::StartTransaction {
				account,
				index,
				output,
				input,
				fee,
				secret_nonce_index,
				address,
			} => {
				let mut data = account.to_le_bytes().to_vec();
				data.extend_from_slice(&index.to_le_bytes());
				data.extend_from_slice(&output.to_le_bytes());
				data.extend_from_slice(&input.to_le_bytes());
				data.extend_from_slice(&fee.to_le_bytes());
				data.push(*secret_nonce_index);
				if let Some(addr) = address {
					data.extend_from_slice(addr);
				}
				create_command(0xC7, 0x0D, 0x00, 0x00, data)
			}
			APDUCommands::ContinueTransactionIncludeOutput {
				identifier,
				value,
				switch_type,
			} => {
				let mut data = identifier.to_vec();
				data.extend_from_slice(&value.to_le_bytes());
				data.push(*switch_type);
				create_command(0xC7, 0x0E, 0x00, 0x00, data)
			}
			APDUCommands::ContinueTransactionIncludeInput {
				identifier,
				value,
				switch_type,
			} => {
				let mut data = identifier.to_vec();
				data.extend_from_slice(&value.to_le_bytes());
				data.push(*switch_type);
				create_command(0xC7, 0x0F, 0x00, 0x00, data)
			}
			APDUCommands::ContinueTransactionApplyOffset { offset } => {
				create_command(0xC7, 0x10, 0x00, 0x00, offset.to_vec())
			}
			APDUCommands::ContinueTransactionGetPublicKey => {
				create_command(0xC7, 0x11, 0x00, 0x00, vec![])
			}
			APDUCommands::ContinueTransactionGetPublicNonce => {
				create_command(0xC7, 0x12, 0x00, 0x00, vec![])
			}
			APDUCommands::ContinueTransactionGetMessageSignature { message } => {
				create_command(0xC7, 0x13, 0x00, 0x00, message.clone())
			}

			APDUCommands::FinishTransaction {
				address_type,
				public_nonce,
				public_key,
				kernel_type,
				kernel_commitment,
				payment_proof,
			} => {
				let address_type: u8 = match address_type {
					Some(a) => 0x01,
					None => 0x00,
				};
				let mut data = Vec::new();
				data.extend_from_slice(public_nonce);
				data.extend_from_slice(public_key);
				data.push(*kernel_type);
				if let Some(commitment) = kernel_commitment {
					data.extend_from_slice(commitment);
				}
				if let Some(proof) = payment_proof {
					data.extend_from_slice(proof);
				}
				create_command(0xC7, 0x14, address_type, 0x00, data)
			}

			APDUCommands::GetMQSChallengeSignature {
				account,
				index,
				timestamp,
				time_zone_offset,
			} => {
				let mut data = Vec::new();
				data.extend_from_slice(&account.to_le_bytes());
				data.extend_from_slice(&index.to_le_bytes());
				if let Some(ts) = timestamp {
					data.extend_from_slice(&ts.to_le_bytes());
				}
				if let Some(tz) = time_zone_offset {
					data.extend_from_slice(&tz.to_le_bytes());
				}
				create_command(0xC7, 0x15, 0x00, 0x00, data)
			}

			APDUCommands::GetLoginChallengeSignature {
				account,
				timestamp,
				time_zone_offset,
				identifier,
			} => {
				let mut data = Vec::new();
				data.extend_from_slice(&account.to_le_bytes());
				data.extend_from_slice(&timestamp.to_le_bytes());
				data.extend_from_slice(&time_zone_offset.to_le_bytes());
				data.extend_from_slice(&identifier);
				create_command(0xC7, 0x16, 0x00, 0x00, data)
			}
			APDUCommands::GetDeviceInfo => create_command(0xe0, 0x01, 0x00, 0x00, vec![]),
			APDUCommands::GetAppInfo => create_command(0xb0, 0x01, 0x00, 0x00, vec![]),
		}
	}
}
