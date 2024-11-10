// Copyright 2021 The Mwc Developers
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

// A note on encoding efficiency: 0.75 for Base64, 0.744 for Base62, 0.732 for Base58
// slatepack uses a modified Base58Check encoding to create armored slate payloads:
// 1. Take first four bytes of SHA256(SHA256(slate.as_bytes()))
// 2. Concatenate result of step 1 and slate.as_bytes()
// 3. Base58 encode bytes from step 2
// Finally add armor framing and space/newline formatting as desired

use crate::Error;
use mwc_wallet_util::mwc_core::global::max_tx_weight;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::str;

// Framing and formatting for slate armor. Headers and footers better to be the same size, otherwise formatting makes it ugly

/// Header used for armored slatepack
pub static HEADER_ENC: &str = "BEGINSLATEPACK.";
static FOOTER_ENC: &str = ". ENDSLATEPACK.";
pub static HEADER_BIN: &str = "BEGINSLATE_BIN.";
static FOOTER_BIN: &str = ". ENDSLATE_BIN.";
const WORD_LENGTH: usize = 15;
const WORDS_PER_LINE: usize = 200;
const WEIGHT_RATIO: u64 = 32;

/// Maximum size for an armored Slatepack file
pub fn max_size() -> u64 {
	max_tx_weight()
		.saturating_mul(WEIGHT_RATIO)
		.saturating_add(HEADER_ENC.len() as u64)
		.saturating_add(FOOTER_ENC.len() as u64)
}

/// Minimum size for an armored Slatepack file or stream
pub fn min_size() -> u64 {
	HEADER_ENC.len() as u64
}

lazy_static! {
	static ref HEADER_REGEX_ENC: Regex =
		Regex::new(concat!(r"^[>\n\r\t ]*BEGINSLATEPACK[>\n\r\t ]*$")).unwrap();
	static ref FOOTER_REGEX_ENC: Regex =
		Regex::new(concat!(r"^[>\n\r\t ]*ENDSLATEPACK[>\n\r\t ]*$")).unwrap();
	static ref HEADER_REGEX_BIN: Regex =
		Regex::new(concat!(r"^[>\n\r\t ]*BEGINSLATE_BIN[>\n\r\t ]*$")).unwrap();
	static ref FOOTER_REGEX_BIN: Regex =
		Regex::new(concat!(r"^[>\n\r\t ]*ENDSLATE_BIN[>\n\r\t ]*$")).unwrap();
	static ref WHITESPACE_LIST: [u8; 5] = [b'>', b'\n', b'\r', b'\t', b' '];
}

/// Wrapper for associated functions
pub struct SlatepackArmor;

impl SlatepackArmor {
	/// Decode an armored Slatepack
	pub fn decode(armor_bytes: &[u8]) -> Result<(Vec<u8>, bool), Error> {
		// Collect the bytes up to the first period, this is the header
		let header_bytes = armor_bytes
			.iter()
			.take_while(|byte| **byte != b'.')
			.cloned()
			.collect::<Vec<u8>>();
		// Verify the header...
		let henc = check_header(&header_bytes)?;
		// Get the length of the header
		let header_len = header_bytes.len() + 1;
		if armor_bytes.len() <= header_len {
			return Err(Error::SlatepackDecodeError("Bad armor header".to_string()));
		}
		// Skip the length of the header to read for the payload until the next period
		let payload_bytes = armor_bytes[header_len as usize..]
			.iter()
			.take_while(|byte| **byte != b'.')
			.cloned()
			.collect::<Vec<u8>>();
		// Get length of the payload to check the footer framing
		let payload_len = payload_bytes.len();
		// Get footer bytes and verify them
		let consumed_bytes = header_len + payload_len + 1;
		if armor_bytes.len() <= consumed_bytes {
			return Err(Error::SlatepackDecodeError("Bad armor content".to_string()));
		}
		let footer_bytes = armor_bytes[consumed_bytes as usize..]
			.iter()
			.take_while(|byte| **byte != b'.')
			.cloned()
			.collect::<Vec<u8>>();
		let fenc = check_footer(&footer_bytes)?;
		if henc != fenc {
			return Err(Error::SlatepackDecodeError(
				"Non matched armor header and footer".to_string(),
			));
		}
		// Clean up the payload bytes to be deserialized
		let clean_payload = payload_bytes
			.iter()
			.filter(|byte| !WHITESPACE_LIST.contains(byte))
			.cloned()
			.collect::<Vec<u8>>();
		// Decode payload from base58
		let base_decode = bs58::decode(&clean_payload)
			.into_vec()
			.map_err(|_| Error::SlatepackDecodeError("Invalid armored data".into()))?;
		let error_code = &base_decode[0..4];
		let slatepack_bytes = &base_decode[4..];
		// Make sure the error check code is valid for the slate data
		error_check(error_code, slatepack_bytes)?;
		// Return slate as binary or string
		Ok((slatepack_bytes.to_vec(), henc))
	}

	/// Encode an armored slatepack
	pub fn encode(slatepack_bytes: &Vec<u8>, encrypted: bool) -> Result<String, Error> {
		let encoded_slatepack = base58check(&slatepack_bytes)?;

		let header = if encrypted { HEADER_ENC } else { HEADER_BIN };
		let footer = if encrypted { FOOTER_ENC } else { FOOTER_BIN };

		let formatted_slatepack = format_slatepack(&format!("{}{}", header, encoded_slatepack))?;
		Ok(format!("{}{}", formatted_slatepack, footer))
	}
}

// Takes an error check code and a slate binary and verifies that the code was generated from slate
fn error_check(error_code: &[u8], slate_bytes: &[u8]) -> Result<(), Error> {
	let new_check = generate_check(slate_bytes)?;
	if error_code.iter().eq(new_check.iter()) {
		Ok(())
	} else {
		Err(Error::SlatepackDecodeError(
			"Invalid armored data, some data was corrupted".to_string(),
		))
	}
}

// Checks header framing bytes and returns an error if they are invalid
fn check_header(header: &[u8]) -> Result<bool, Error> {
	let framing = str::from_utf8(header)
		.map_err(|_| Error::SlatepackDecodeError("Bad bytes at armored data".into()))?;
	if HEADER_REGEX_ENC.is_match(framing) {
		Ok(true)
	} else if HEADER_REGEX_BIN.is_match(framing) {
		Ok(false)
	} else {
		Err(Error::SlatepackDecodeError("Bad armor header".to_string()))
	}
}

// Checks footer framing bytes and returns an error if they are invalid
fn check_footer(footer: &[u8]) -> Result<bool, Error> {
	let framing = str::from_utf8(footer)
		.map_err(|_| Error::SlatepackDecodeError("Bad bytes at armored data".into()))?;
	if FOOTER_REGEX_ENC.is_match(framing) {
		Ok(true)
	} else if FOOTER_REGEX_BIN.is_match(framing) {
		Ok(false)
	} else {
		Err(Error::SlatepackDecodeError("Bad armor footer".to_string()))
	}
}

// MODIFIED Base58Check encoding for slate bytes
fn base58check(slate: &[u8]) -> Result<String, Error> {
	// Serialize the slate json string to a vector of bytes
	let mut slate_bytes: Vec<u8> = slate.to_vec();
	// Get the four byte checksum for the slate binary
	let mut check_bytes: Vec<u8> = generate_check(&slate_bytes)?;
	// Make a new buffer and concatenate checksum bytes and slate bytes
	let mut slate_buf = Vec::new();
	slate_buf.append(&mut check_bytes);
	slate_buf.append(&mut slate_bytes);
	// Encode the slate buffer containing the slate binary and checksum bytes as Base58
	let b58_slate = bs58::encode(slate_buf).into_string();
	Ok(b58_slate)
}

// Adds human readable formatting to the slate payload for armoring
fn format_slatepack(slatepack: &str) -> Result<String, Error> {
	let formatter = slatepack
		.chars()
		.enumerate()
		.flat_map(|(i, c)| {
			if i != 0 && i % WORD_LENGTH == 0 {
				if WORDS_PER_LINE != 0 && i % (WORD_LENGTH * WORDS_PER_LINE) == 0 {
					Some('\n')
				} else {
					Some(' ')
				}
			} else {
				None
			}
			.into_iter()
			.chain(std::iter::once(c))
		})
		.collect::<String>();
	Ok(formatter)
}

/// Returns the first four bytes of a double sha256 hash of some bytes
/// This method is reused for swaps for BSV, just don't want to duplicates
pub fn generate_check(payload: &[u8]) -> Result<Vec<u8>, Error> {
	let mut first_hash = Sha256::new();
	first_hash.update(payload);
	let mut second_hash = Sha256::new();
	second_hash.update(&first_hash.finalize());
	let checksum = second_hash.finalize();
	let check_bytes: Vec<u8> = checksum[0..4].to_vec();
	Ok(check_bytes)
}
