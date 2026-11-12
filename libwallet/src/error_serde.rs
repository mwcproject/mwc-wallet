//! Serde compatibility adapters for error types whose upstream representations
//! are no longer serializable.

use mwc_wallet_util::mwc_core::{consensus, core::transaction, libtx, ser as core_ser};
use mwc_wallet_util::mwc_crates::{
	secp,
	serde::{self, ser::SerializeStructVariant, Deserialize, Deserializer, Serialize, Serializer},
};
use mwc_wallet_util::mwc_keychain;
use std::io;

#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
enum IoErrorKind {
	NotFound,
	PermissionDenied,
	ConnectionRefused,
	ConnectionReset,
	ConnectionAborted,
	NotConnected,
	AddrInUse,
	AddrNotAvailable,
	BrokenPipe,
	AlreadyExists,
	WouldBlock,
	InvalidInput,
	InvalidData,
	TimedOut,
	WriteZero,
	Interrupted,
	Other,
	UnexpectedEof,
}

impl From<io::ErrorKind> for IoErrorKind {
	fn from(kind: io::ErrorKind) -> Self {
		match kind {
			io::ErrorKind::NotFound => Self::NotFound,
			io::ErrorKind::PermissionDenied => Self::PermissionDenied,
			io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
			io::ErrorKind::ConnectionReset => Self::ConnectionReset,
			io::ErrorKind::ConnectionAborted => Self::ConnectionAborted,
			io::ErrorKind::NotConnected => Self::NotConnected,
			io::ErrorKind::AddrInUse => Self::AddrInUse,
			io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
			io::ErrorKind::BrokenPipe => Self::BrokenPipe,
			io::ErrorKind::AlreadyExists => Self::AlreadyExists,
			io::ErrorKind::WouldBlock => Self::WouldBlock,
			io::ErrorKind::InvalidInput => Self::InvalidInput,
			io::ErrorKind::InvalidData => Self::InvalidData,
			io::ErrorKind::TimedOut => Self::TimedOut,
			io::ErrorKind::WriteZero => Self::WriteZero,
			io::ErrorKind::Interrupted => Self::Interrupted,
			io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
			// Keep the legacy wire representation stable. `ErrorKind` is non-exhaustive,
			// so newer or unsupported kinds are intentionally represented as `Other`;
			// `core_ser_error::serialize` preserves the original error message separately.
			_ => Self::Other,
		}
	}
}

impl From<IoErrorKind> for io::ErrorKind {
	fn from(kind: IoErrorKind) -> Self {
		match kind {
			IoErrorKind::NotFound => Self::NotFound,
			IoErrorKind::PermissionDenied => Self::PermissionDenied,
			IoErrorKind::ConnectionRefused => Self::ConnectionRefused,
			IoErrorKind::ConnectionReset => Self::ConnectionReset,
			IoErrorKind::ConnectionAborted => Self::ConnectionAborted,
			IoErrorKind::NotConnected => Self::NotConnected,
			IoErrorKind::AddrInUse => Self::AddrInUse,
			IoErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
			IoErrorKind::BrokenPipe => Self::BrokenPipe,
			IoErrorKind::AlreadyExists => Self::AlreadyExists,
			IoErrorKind::WouldBlock => Self::WouldBlock,
			IoErrorKind::InvalidInput => Self::InvalidInput,
			IoErrorKind::InvalidData => Self::InvalidData,
			IoErrorKind::TimedOut => Self::TimedOut,
			IoErrorKind::WriteZero => Self::WriteZero,
			IoErrorKind::Interrupted => Self::Interrupted,
			IoErrorKind::Other => Self::Other,
			IoErrorKind::UnexpectedEof => Self::UnexpectedEof,
		}
	}
}

pub(crate) mod core_ser_error {
	use super::*;

	#[derive(Serialize, Deserialize)]
	#[serde(crate = "serde")]
	enum WireError {
		IOErr(String, IoErrorKind),
		SecpError(secp::Error),
		UnexpectedData {
			expected: Vec<u8>,
			received: Vec<u8>,
		},
		CorruptedData(String),
		DataOverflow(String),
		CountError(String),
		TooLargeWriteErr(String),
		TooLargeReadErr(String),
		HexError(String),
		SortError,
		DuplicateError,
		InvalidBlockVersion(String),
		Utf8Conversion(String),
		UnsupportedProtocolVersion(String),
	}

	pub(crate) fn serialize<S>(error: &core_ser::Error, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let wire = match error {
			core_ser::Error::IOErr(error) => {
				// Store the portable error kind and diagnostic message. Platform-specific
				// OS codes and custom sources are intentionally not part of the wire format.
				WireError::IOErr(error.to_string(), error.kind().into())
			}
			core_ser::Error::SecpError(error) => WireError::SecpError(*error),
			core_ser::Error::UnexpectedData { expected, received } => WireError::UnexpectedData {
				expected: expected.clone(),
				received: received.clone(),
			},
			core_ser::Error::CorruptedData(message) => WireError::CorruptedData(message.clone()),
			core_ser::Error::DataOverflow(message) => WireError::DataOverflow(message.clone()),
			core_ser::Error::CountError(message) => WireError::CountError(message.clone()),
			core_ser::Error::TooLargeWriteErr(message) => {
				WireError::TooLargeWriteErr(message.clone())
			}
			core_ser::Error::TooLargeReadErr(message) => {
				WireError::TooLargeReadErr(message.clone())
			}
			core_ser::Error::HexError(message) => WireError::HexError(message.clone()),
			core_ser::Error::SortError => WireError::SortError,
			core_ser::Error::DuplicateError => WireError::DuplicateError,
			core_ser::Error::InvalidBlockVersion(message) => {
				WireError::InvalidBlockVersion(message.clone())
			}
			core_ser::Error::Utf8Conversion(message) => WireError::Utf8Conversion(message.clone()),
			core_ser::Error::UnsupportedProtocolVersion(message) => {
				WireError::UnsupportedProtocolVersion(message.clone())
			}
		};
		wire.serialize(serializer)
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<core_ser::Error, D::Error>
	where
		D: Deserializer<'de>,
	{
		Ok(match WireError::deserialize(deserializer)? {
			WireError::IOErr(message, kind) => {
				core_ser::Error::IOErr(io::Error::new(io::ErrorKind::from(kind), message))
			}
			WireError::SecpError(error) => core_ser::Error::SecpError(error),
			WireError::UnexpectedData { expected, received } => {
				core_ser::Error::UnexpectedData { expected, received }
			}
			WireError::CorruptedData(message) => core_ser::Error::CorruptedData(message),
			WireError::DataOverflow(message) => core_ser::Error::DataOverflow(message),
			WireError::CountError(message) => core_ser::Error::CountError(message),
			WireError::TooLargeWriteErr(message) => core_ser::Error::TooLargeWriteErr(message),
			WireError::TooLargeReadErr(message) => core_ser::Error::TooLargeReadErr(message),
			WireError::HexError(message) => core_ser::Error::HexError(message),
			WireError::SortError => core_ser::Error::SortError,
			WireError::DuplicateError => core_ser::Error::DuplicateError,
			WireError::InvalidBlockVersion(message) => {
				core_ser::Error::InvalidBlockVersion(message)
			}
			WireError::Utf8Conversion(message) => core_ser::Error::Utf8Conversion(message),
			WireError::UnsupportedProtocolVersion(message) => {
				core_ser::Error::UnsupportedProtocolVersion(message)
			}
		})
	}
}

struct CoreSerErrorRef<'a>(&'a core_ser::Error);

impl Serialize for CoreSerErrorRef<'_> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		core_ser_error::serialize(self.0, serializer)
	}
}

pub(crate) mod transaction_error {
	use super::*;

	#[derive(Deserialize)]
	#[serde(crate = "serde")]
	enum WireError {
		Secp(secp::Error),
		Keychain(mwc_keychain::Error),
		KernelSumMismatch,
		TooHeavy,
		LockHeight(u64),
		RangeProof,
		MerkleProof,
		InvalidProofMessage,
		Committed(mwc_wallet_util::mwc_core::core::committed::Error),
		CutThrough,
		InvalidOutputFeatures,
		DuplicateOutput,
		DuplicateInput,
		DuplicateKernel,
		InvalidKernelFeatures,
		InvalidFeeFields(String),
		InvalidNRDRelativeHeight,
		NRDKernelNotEnabled,
		IncorrectSignature,
		Serialization(#[serde(with = "core_ser_error")] core_ser::Error),
		IO(String),
		DataOverflow(String),
		Generic(String),
	}

	pub(crate) fn serialize<S>(error: &transaction::Error, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match error {
			transaction::Error::Secp(error) => {
				serializer.serialize_newtype_variant("Error", 0, "Secp", error)
			}
			transaction::Error::Keychain(error) => {
				serializer.serialize_newtype_variant("Error", 1, "Keychain", error)
			}
			transaction::Error::KernelSumMismatch => {
				serializer.serialize_unit_variant("Error", 2, "KernelSumMismatch")
			}
			transaction::Error::TooHeavy => {
				serializer.serialize_unit_variant("Error", 3, "TooHeavy")
			}
			transaction::Error::LockHeight(height) => {
				serializer.serialize_newtype_variant("Error", 4, "LockHeight", height)
			}
			transaction::Error::RangeProof => {
				serializer.serialize_unit_variant("Error", 5, "RangeProof")
			}
			transaction::Error::MerkleProof => {
				serializer.serialize_unit_variant("Error", 6, "MerkleProof")
			}
			transaction::Error::InvalidProofMessage => {
				serializer.serialize_unit_variant("Error", 7, "InvalidProofMessage")
			}
			transaction::Error::Committed(error) => {
				serializer.serialize_newtype_variant("Error", 8, "Committed", error)
			}
			transaction::Error::CutThrough => {
				serializer.serialize_unit_variant("Error", 9, "CutThrough")
			}
			transaction::Error::InvalidOutputFeatures => {
				serializer.serialize_unit_variant("Error", 10, "InvalidOutputFeatures")
			}
			transaction::Error::DuplicateOutput => {
				serializer.serialize_unit_variant("Error", 11, "DuplicateOutput")
			}
			transaction::Error::DuplicateInput => {
				serializer.serialize_unit_variant("Error", 12, "DuplicateInput")
			}
			transaction::Error::DuplicateKernel => {
				serializer.serialize_unit_variant("Error", 13, "DuplicateKernel")
			}
			transaction::Error::InvalidKernelFeatures => {
				serializer.serialize_unit_variant("Error", 14, "InvalidKernelFeatures")
			}
			transaction::Error::InvalidFeeFields(message) => {
				serializer.serialize_newtype_variant("Error", 15, "InvalidFeeFields", message)
			}
			transaction::Error::InvalidNRDRelativeHeight => {
				serializer.serialize_unit_variant("Error", 16, "InvalidNRDRelativeHeight")
			}
			transaction::Error::NRDKernelNotEnabled => {
				serializer.serialize_unit_variant("Error", 17, "NRDKernelNotEnabled")
			}
			transaction::Error::IncorrectSignature => {
				serializer.serialize_unit_variant("Error", 18, "IncorrectSignature")
			}
			transaction::Error::Serialization(error) => serializer.serialize_newtype_variant(
				"Error",
				19,
				"Serialization",
				&CoreSerErrorRef(error),
			),
			transaction::Error::IO(error) => {
				// Only the error message is used after this serialization boundary.
				// Preserving `io::ErrorKind` while remaining compatible with legacy payloads
				// would add more wire-format complexity than the benefit warrants.
				serializer.serialize_newtype_variant("Error", 20, "IO", &error.to_string())
			}
			transaction::Error::DataOverflow(message) => {
				serializer.serialize_newtype_variant("Error", 21, "DataOverflow", message)
			}
			transaction::Error::Generic(message) => {
				serializer.serialize_newtype_variant("Error", 22, "Generic", message)
			}
		}
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<transaction::Error, D::Error>
	where
		D: Deserializer<'de>,
	{
		Ok(match WireError::deserialize(deserializer)? {
			WireError::Secp(error) => transaction::Error::Secp(error),
			WireError::Keychain(error) => transaction::Error::Keychain(error),
			WireError::KernelSumMismatch => transaction::Error::KernelSumMismatch,
			WireError::TooHeavy => transaction::Error::TooHeavy,
			WireError::LockHeight(height) => transaction::Error::LockHeight(height),
			WireError::RangeProof => transaction::Error::RangeProof,
			WireError::MerkleProof => transaction::Error::MerkleProof,
			WireError::InvalidProofMessage => transaction::Error::InvalidProofMessage,
			WireError::Committed(error) => transaction::Error::Committed(error),
			WireError::CutThrough => transaction::Error::CutThrough,
			WireError::InvalidOutputFeatures => transaction::Error::InvalidOutputFeatures,
			WireError::DuplicateOutput => transaction::Error::DuplicateOutput,
			WireError::DuplicateInput => transaction::Error::DuplicateInput,
			WireError::DuplicateKernel => transaction::Error::DuplicateKernel,
			WireError::InvalidKernelFeatures => transaction::Error::InvalidKernelFeatures,
			WireError::InvalidFeeFields(message) => transaction::Error::InvalidFeeFields(message),
			WireError::InvalidNRDRelativeHeight => transaction::Error::InvalidNRDRelativeHeight,
			WireError::NRDKernelNotEnabled => transaction::Error::NRDKernelNotEnabled,
			WireError::IncorrectSignature => transaction::Error::IncorrectSignature,
			WireError::Serialization(error) => transaction::Error::Serialization(error),
			WireError::IO(message) => {
				// The legacy wire payload deliberately carries no kind. `Other` is the
				// neutral reconstruction for a diagnostic-only, message-preserving error.
				transaction::Error::IO(io::Error::new(io::ErrorKind::Other, message))
			}
			WireError::DataOverflow(message) => transaction::Error::DataOverflow(message),
			WireError::Generic(message) => transaction::Error::Generic(message),
		})
	}
}

struct TransactionErrorRef<'a>(&'a transaction::Error);

impl Serialize for TransactionErrorRef<'_> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		transaction_error::serialize(self.0, serializer)
	}
}

mod consensus_error {
	use super::*;

	#[derive(Serialize)]
	#[serde(crate = "serde")]
	enum WireErrorRef<'a> {
		DataOverflow(&'a str),
		HistoryTooShort,
		HeaderIO(&'a str),
		InvalidEdgeBits(u8),
		AlreadyInitialized(&'a str),
		InvalidParameter(&'a str),
	}

	#[derive(Deserialize)]
	#[serde(crate = "serde")]
	enum WireError {
		DataOverflow(String),
		HistoryTooShort,
		HeaderIO(String),
		InvalidEdgeBits(u8),
		AlreadyInitialized(String),
		InvalidParameter(String),
	}

	pub(super) fn serialize<S>(error: &consensus::Error, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match error {
			consensus::Error::DataOverflow(message) => {
				WireErrorRef::DataOverflow(message).serialize(serializer)
			}
			consensus::Error::HistoryTooShort => {
				WireErrorRef::HistoryTooShort.serialize(serializer)
			}
			consensus::Error::HeaderIO(message) => {
				WireErrorRef::HeaderIO(message).serialize(serializer)
			}
			consensus::Error::InvalidEdgeBits(bits) => {
				WireErrorRef::InvalidEdgeBits(*bits).serialize(serializer)
			}
			consensus::Error::AlreadyInitialized(message) => {
				WireErrorRef::AlreadyInitialized(message).serialize(serializer)
			}
			consensus::Error::InvalidParameter(message) => {
				WireErrorRef::InvalidParameter(message).serialize(serializer)
			}
		}
	}

	pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<consensus::Error, D::Error>
	where
		D: Deserializer<'de>,
	{
		Ok(match WireError::deserialize(deserializer)? {
			WireError::DataOverflow(message) => consensus::Error::DataOverflow(message),
			WireError::HistoryTooShort => consensus::Error::HistoryTooShort,
			WireError::HeaderIO(message) => consensus::Error::HeaderIO(message),
			WireError::InvalidEdgeBits(bits) => consensus::Error::InvalidEdgeBits(bits),
			WireError::AlreadyInitialized(message) => consensus::Error::AlreadyInitialized(message),
			WireError::InvalidParameter(message) => consensus::Error::InvalidParameter(message),
		})
	}
}

struct ConsensusErrorRef<'a>(&'a consensus::Error);

impl Serialize for ConsensusErrorRef<'_> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		consensus_error::serialize(self.0, serializer)
	}
}

pub(crate) mod libtx_error {
	use super::*;

	#[derive(Deserialize)]
	#[serde(crate = "serde")]
	enum WireError {
		Secp {
			source: secp::Error,
		},
		Keychain {
			source: mwc_keychain::Error,
		},
		Transaction {
			#[serde(with = "transaction_error")]
			source: transaction::Error,
		},
		ZeroBlindingSum,
		Signature(String),
		RangeProof(String),
		DataOverflow(String),
		Other(String),
		ConsensusError(#[serde(with = "consensus_error")] consensus::Error),
	}

	pub(crate) fn serialize<S>(error: &libtx::Error, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match error {
			libtx::Error::Secp(error) => {
				let mut variant = serializer.serialize_struct_variant("Error", 0, "Secp", 1)?;
				variant.serialize_field("source", error)?;
				variant.end()
			}
			libtx::Error::Keychain { source } => {
				let mut variant = serializer.serialize_struct_variant("Error", 1, "Keychain", 1)?;
				variant.serialize_field("source", source)?;
				variant.end()
			}
			libtx::Error::Transaction { source } => {
				let mut variant =
					serializer.serialize_struct_variant("Error", 2, "Transaction", 1)?;
				variant.serialize_field("source", &TransactionErrorRef(source))?;
				variant.end()
			}
			libtx::Error::ZeroBlindingSum => {
				serializer.serialize_unit_variant("Error", 3, "ZeroBlindingSum")
			}
			libtx::Error::Signature(message) => {
				serializer.serialize_newtype_variant("Error", 4, "Signature", message)
			}
			libtx::Error::RangeProof(message) => {
				serializer.serialize_newtype_variant("Error", 5, "RangeProof", message)
			}
			libtx::Error::DataOverflow(message) => {
				serializer.serialize_newtype_variant("Error", 6, "DataOverflow", message)
			}
			libtx::Error::Other(message) => {
				serializer.serialize_newtype_variant("Error", 7, "Other", message)
			}
			libtx::Error::ConsensusError(error) => serializer.serialize_newtype_variant(
				"Error",
				8,
				"ConsensusError",
				&ConsensusErrorRef(error),
			),
		}
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<libtx::Error, D::Error>
	where
		D: Deserializer<'de>,
	{
		Ok(match WireError::deserialize(deserializer)? {
			WireError::Secp { source } => libtx::Error::Secp(source),
			WireError::Keychain { source } => libtx::Error::Keychain { source },
			WireError::Transaction { source } => libtx::Error::Transaction { source },
			WireError::ZeroBlindingSum => libtx::Error::ZeroBlindingSum,
			WireError::Signature(message) => libtx::Error::Signature(message),
			WireError::RangeProof(message) => libtx::Error::RangeProof(message),
			WireError::DataOverflow(message) => libtx::Error::DataOverflow(message),
			WireError::Other(message) => libtx::Error::Other(message),
			WireError::ConsensusError(error) => libtx::Error::ConsensusError(error),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Error;
	use mwc_wallet_util::mwc_crates::serde_json::{self, json, Value};

	fn assert_round_trip(error: Error, expected: Value) {
		let encoded = serde_json::to_value(&error).unwrap();
		assert_eq!(encoded, expected);

		// Error retains two legacy &'static str variants, so its derived
		// deserializer requires input that lives for the duration of the process.
		let encoded: &'static str =
			Box::leak(serde_json::to_string(&encoded).unwrap().into_boxed_str());
		let decoded: Error = serde_json::from_str(encoded).unwrap();
		assert_eq!(serde_json::to_value(decoded).unwrap(), expected);
	}

	#[test]
	fn wallet_error_keeps_externally_tagged_json() {
		assert_round_trip(
			Error::PaymentProofRetrieval(
				"Transaction ID or Slate UUID must be specified".to_owned(),
			),
			json!({
				"PaymentProofRetrieval": "Transaction ID or Slate UUID must be specified"
			}),
		);
	}

	#[test]
	fn wrapped_core_errors_keep_structured_json() {
		assert_round_trip(
			Error::LibTX(libtx::Error::Secp(secp::Error::InvalidRangeProof)),
			json!({
				"LibTX": {
					"Secp": {
						"source": "InvalidRangeProof"
					}
				}
			}),
		);
		assert_round_trip(
			Error::Transaction(transaction::Error::RangeProof),
			json!({"Transaction": "RangeProof"}),
		);
		assert_round_trip(
			Error::Deser(core_ser::Error::CorruptedData("invalid data".to_owned())),
			json!({"Deser": {"CorruptedData": "invalid data"}}),
		);
	}
}
