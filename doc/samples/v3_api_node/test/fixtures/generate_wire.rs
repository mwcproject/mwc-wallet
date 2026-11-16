// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
// Public test data only. Run as an example of the mwc_wallet_api crate to regenerate wire.json.

use mwc_wallet_api::{EncryptedRequest, EncryptedResponse, JsonId};
use mwc_wallet_util::mwc_crates::{
	secp::{Secp256k1, key::SecretKey},
	serde_json,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
	let secp = Secp256k1::new().unwrap();
	let key = SecretKey::from_slice(&secp, &[42u8; 32]).unwrap();
	let id = JsonId::StrId("7".to_string());
	let request_value =
		serde_json::json!({"jsonrpc":"2.0","id":"7","method":"accounts","params":{"token":null}});
	let request = EncryptedRequest::from_json(&id, &request_value, &key)?;
	assert_eq!(request.decrypt(&key)?, request_value);
	let response_value = serde_json::json!({"jsonrpc":"2.0","id":"7","result":{"Ok":[{"label":"default","path":"m/0/0"}]}});
	let response = EncryptedResponse::from_json(&id, &response_value, &key)?;
	assert_eq!(response.decrypt(&key)?, response_value);
	println!(
		"{}",
		serde_json::to_string_pretty(&serde_json::json!({
			"source":"mwc_wallet_api::EncryptedRequest and EncryptedResponse, api/src/types.rs",
			"key_hex":"2a".repeat(32), "request_value":request_value, "request":request.as_json_value()?,
			"response_value":response_value, "response":response.as_json_value()?
		}))?
	);
	Ok(())
}
