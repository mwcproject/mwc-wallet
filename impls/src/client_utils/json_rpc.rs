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
// Derived from https://github.com/apoelstra/rust-jsonrpc

//! JSON RPC Client functionality
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;

/// Builds a request
pub fn build_request<'a, 'b>(name: &'a str, params: &'b serde_json::Value) -> Request<'a, 'b> {
	Request {
		method: name,
		params: params,
		id: From::from(1),
		jsonrpc: Some("2.0"),
	}
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(crate = "serde")]
/// A JSONRPC request object
pub struct Request<'a, 'b> {
	/// The name of the RPC call
	pub method: &'a str,
	/// Parameters to the RPC call
	pub params: &'b serde_json::Value,
	/// Identifier for this Request, which should appear in the response
	pub id: serde_json::Value,
	/// jsonrpc field, MUST be "2.0"
	pub jsonrpc: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(crate = "serde")]
/// A JSONRPC response object
pub struct Response {
	/// A result if there is one, or null
	pub result: Option<serde_json::Value>,
	/// An error if there is one, or null
	pub error: Option<RpcError>,
	/// Identifier for this Request, which should match that of the request
	pub id: serde_json::Value,
	/// jsonrpc field, expected to be "2.0" when present
	pub jsonrpc: Option<String>,
}

impl Response {
	fn check_jsonrpc_version(&self) -> Result<(), Error> {
		match self.jsonrpc.as_deref() {
			None | Some("2.0") => Ok(()),
			Some(_) => Err(Error::VersionMismatch),
		}
	}

	fn check_id(&self, expected_id: &serde_json::Value) -> Result<(), Error> {
		if &self.id == expected_id {
			Ok(())
		} else {
			Err(Error::IdMismatch)
		}
	}

	/// Extract the result from a response
	pub fn result<T: serde::de::DeserializeOwned>(
		&self,
		expected_id: &serde_json::Value,
	) -> Result<T, Error> {
		let malformed_result = || {
			Error::MalformedResponse(
				"RPC result must be an object containing exactly one Ok or Err field".to_string(),
			)
		};

		self.check_jsonrpc_version()?;
		self.check_id(expected_id)?;

		if let Some(ref e) = self.error {
			return Err(Error::Rpc(e.clone()));
		}

		let result = match self.result.as_ref() {
			Some(r) => {
				let result = r
					.as_object()
					.filter(|result| result.len() == 1)
					.ok_or_else(&malformed_result)?;
				match result.iter().next() {
					Some((variant, error)) if variant == "Err" => {
						Err(Error::GenericError(error.to_string()))
					}
					Some((variant, ok)) if variant == "Ok" => serde_json::from_value(ok.clone())
						.map_err(|e| Error::Json(format!("{}", e))),
					_ => Err(malformed_result()),
				}
			}
			None => Err(malformed_result()),
		}?;
		Ok(result)
	}

	/// Extract the result from a response, consuming the response
	pub fn into_result<T: serde::de::DeserializeOwned>(
		self,
		expected_id: &serde_json::Value,
	) -> Result<T, Error> {
		self.result(expected_id)
	}

	/// Return the RPC error, if there was one, but do not check the result
	pub fn _check_error(self) -> Result<(), Error> {
		if let Some(e) = self.error {
			Err(Error::Rpc(e))
		} else {
			Ok(())
		}
	}

	/// Returns whether or not the `result` field is empty
	pub fn _is_none(&self) -> bool {
		self.result.is_none()
	}
}

/// A library error
#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	/// Json error
	#[error("Unable to parse json, {0}")]
	Json(String),
	/// Error response
	#[error("RPC error: {0:?}")]
	Rpc(RpcError),
	/// Internal generic Error
	#[error("Client error: {0}")]
	GenericError(String),
	/// Response result did not match the expected RPC success wrapper
	#[error("Malformed RPC response: {0}")]
	MalformedResponse(String),
	/// Response declared an incompatible JSON-RPC version
	#[error("`jsonrpc` field set to non-\"2.0\"")]
	VersionMismatch,
	/// Response identifier did not match the corresponding request
	#[error("JSON-RPC response id does not match request id")]
	IdMismatch,
}

impl From<serde_json::Error> for Error {
	fn from(e: serde_json::Error) -> Error {
		Error::Json(format!("{}", e))
	}
}

impl From<RpcError> for Error {
	fn from(e: RpcError) -> Error {
		Error::Rpc(e)
	}
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(crate = "serde")]
/// A JSONRPC error object
pub struct RpcError {
	/// The integer identifier of the error
	pub code: i32,
	/// A string describing the error
	pub message: String,
	/// Additional data specific to the error
	pub data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn expected_id() -> serde_json::Value {
		serde_json::Value::from(1)
	}

	fn response(result: Option<serde_json::Value>, jsonrpc: Option<&str>) -> Response {
		Response {
			result,
			error: None,
			id: expected_id(),
			jsonrpc: jsonrpc.map(String::from),
		}
	}

	fn extract<T: serde::de::DeserializeOwned>(response: Response) -> Result<T, Error> {
		response.into_result(&expected_id())
	}

	fn assert_malformed(error: Error) {
		assert!(matches!(error, Error::MalformedResponse(_)));
	}

	#[test]
	fn into_result_accepts_valid_ok_response() {
		let response = response(Some(serde_json::json!({"Ok": 7})), Some("2.0"));

		assert_eq!(extract::<u64>(response).unwrap(), 7);
	}

	#[test]
	fn into_result_for_unit_requires_null_ok_payload() {
		let valid_response = response(Some(serde_json::json!({"Ok": null})), Some("2.0"));
		extract::<()>(valid_response).unwrap();

		let malformed_response = response(
			Some(serde_json::json!({"Ok": "unexpected payload"})),
			Some("2.0"),
		);

		assert!(extract::<()>(malformed_response).is_err());
	}

	#[test]
	fn into_result_rejects_mismatched_response_id() {
		let mut response = response(Some(serde_json::json!({"Ok": 7})), Some("2.0"));
		response.id = serde_json::Value::from(2);

		let error = extract::<u64>(response).unwrap_err();

		assert!(matches!(error, Error::IdMismatch));
	}

	#[test]
	fn into_result_rejects_missing_or_null_result() {
		assert_malformed(extract::<serde_json::Value>(response(None, Some("2.0"))).unwrap_err());
		assert_malformed(extract::<Option<u64>>(response(None, Some("2.0"))).unwrap_err());
		assert_malformed(extract::<()>(response(None, Some("2.0"))).unwrap_err());
	}

	#[test]
	fn into_result_rejects_malformed_result_wrapper() {
		assert_malformed(
			extract::<serde_json::Value>(response(
				Some(serde_json::json!({"unexpected": null})),
				Some("2.0"),
			))
			.unwrap_err(),
		);
		assert_malformed(
			extract::<Option<u64>>(response(Some(serde_json::json!(7)), Some("2.0"))).unwrap_err(),
		);
		assert_malformed(
			extract::<serde_json::Value>(response(
				Some(serde_json::json!({
					"Ok": 7,
					"Err": "API NotFound: kernel value for requested excess",
				})),
				Some("2.0"),
			))
			.unwrap_err(),
		);
		assert_malformed(
			extract::<serde_json::Value>(response(
				Some(serde_json::json!({
					"Err": "API NotFound: kernel value for requested excess",
					"metadata": null,
				})),
				Some("2.0"),
			))
			.unwrap_err(),
		);
	}

	#[test]
	fn into_result_treats_null_err_as_an_error() {
		let error = extract::<serde_json::Value>(response(
			Some(serde_json::json!({"Err": null})),
			Some("2.0"),
		))
		.unwrap_err();

		assert!(matches!(error, Error::GenericError(message) if message == "null"));
	}

	#[test]
	fn into_result_rejects_incompatible_jsonrpc_version() {
		let error =
			extract::<u64>(response(Some(serde_json::json!({"Ok": 7})), Some("1.0"))).unwrap_err();

		assert!(matches!(error, Error::VersionMismatch));
	}
}
