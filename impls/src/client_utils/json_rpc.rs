// Copyright 2020 The Grin Developers
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
use failure::Fail;
use hyper;
use serde_json;

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
/// A JSONRPC response object
pub struct Response {
	/// A result if there is one, or null
	pub result: Option<serde_json::Value>,
	/// An error if there is one, or null
	pub error: Option<RpcError>,
	/// Identifier for this Request, which should match that of the request
	pub id: serde_json::Value,
	/// jsonrpc field, MUST be "2.0"
	pub jsonrpc: Option<String>,
}

impl Response {
	/// Extract the result from a response
	pub fn result<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
		if let Some(ref e) = self.error {
			return Err(Error::Rpc(e.clone()));
		}

		let result = match self.result.clone() {
			Some(r) => {
				if !r["Err"].is_null() {
					// we get error. Let's respond as error
					return Err(Error::GenericError(r["Err"].to_string()));
				}
				serde_json::from_value(r["Ok"].clone()).map_err(|e| Error::Json(format!("{}", e)))
			}
			None => serde_json::from_value(serde_json::Value::Null)
				.map_err(|e| Error::Json(format!("{}", e))),
		}?;
		Ok(result)
	}

	/// Extract the result from a response, consuming the response
	pub fn into_result<T: serde::de::DeserializeOwned>(self) -> Result<T, Error> {
		if let Some(e) = self.error {
			return Err(Error::Rpc(e));
		}
		self.result()
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
#[derive(Debug, Fail, Clone)]
pub enum Error {
	/// Json error
	#[fail(display = "Unable to parse json, {}", _0)]
	Json(String),
	/// Client error
	#[fail(display = "Connection error, {}", _0)]
	Hyper(String),
	/// Error response
	#[fail(display = "RPC error: {:?}", _0)]
	Rpc(RpcError),
	/// Internal generic Error
	#[fail(display = "Client error: {}", _0)]
	GenericError(String),
}

impl From<serde_json::Error> for Error {
	fn from(e: serde_json::Error) -> Error {
		Error::Json(format!("{}", e))
	}
}

impl From<hyper::error::Error> for Error {
	fn from(e: hyper::error::Error) -> Error {
		Error::Hyper(format!("{}", e))
	}
}

impl From<RpcError> for Error {
	fn from(e: RpcError) -> Error {
		Error::Rpc(e)
	}
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
/// A JSONRPC error object
pub struct RpcError {
	/// The integer identifier of the error
	pub code: i32,
	/// A string describing the error
	pub message: String,
	/// Additional data specific to the error
	pub data: Option<serde_json::Value>,
}
