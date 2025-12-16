// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

//! Tor Configuration + Onion (Hidden) Service operations
use crate::Error;
use mwc_wallet_util::OnionV3Address;
use std::convert::TryFrom;

/// Validate if it is a tor address
pub fn is_tor_address(input: &str) -> Result<(), Error> {
	match OnionV3Address::try_from(input) {
		Ok(_) => Ok(()),
		Err(e) => Err(Error::NotOnion(format!("{}, {}", input, e)))?,
	}
}

/// Make sure that this address is a completer tor address
pub fn complete_tor_address(input: &str) -> Result<String, Error> {
	let input = if input.ends_with("/") {
		&input[..input.len() - 1]
	} else {
		input
	};
	is_tor_address(input)?;
	let mut input = input.to_uppercase();
	if !input.starts_with("HTTP://") && !input.starts_with("HTTPS://") {
		input = format!("HTTP://{}", input);
	}
	if !input.ends_with(".ONION") {
		input = format!("{}.ONION", input);
	}
	Ok(input.to_lowercase())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_is_tor_address() -> Result<(), Error> {
		assert!(is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok());
		assert!(is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok());
		assert!(is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_ok());
		assert!(is_tor_address(
			"http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_ok());
		assert!(is_tor_address(
			"https://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_ok());
		assert!(
			is_tor_address("http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid")
				.is_ok()
		);
		assert!(
			is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion")
				.is_ok()
		);
		// address too short
		assert!(is_tor_address(
			"http://kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_err());
		assert!(is_tor_address("kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_err());
		Ok(())
	}

	#[test]
	fn test_complete_tor_address() -> Result<(), Error> {
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid")
				.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid")
				.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion")
				.unwrap()
		);
		assert!(
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyi")
				.is_err()
		);
		Ok(())
	}
}
