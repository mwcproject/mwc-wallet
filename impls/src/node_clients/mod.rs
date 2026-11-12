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

pub mod http;
pub mod resp_types;

pub use self::http::HTTPNodeClient;

use crate::json_rpc;
use mwc_wallet_libwallet::Error as WalletError;
use mwc_wallet_util::mwc_api::LocatedTxKernel;
use mwc_wallet_util::mwc_core::core::TxKernel;
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::serde_json;

const KERNEL_NOT_FOUND_ERROR: &str = "API NotFound: kernel value for requested excess";

/// Return true only for the node's precise legacy "requested kernel is absent"
/// response. Other protocol, transport and internal errors must remain errors.
pub fn is_kernel_not_found_error(error: &json_rpc::Error, params: &serde_json::Value) -> bool {
	let json_rpc::Error::GenericError(message) = error else {
		return false;
	};
	let Ok(message) = serde_json::from_str::<String>(message) else {
		return false;
	};
	if message == KERNEL_NOT_FOUND_ERROR {
		return true;
	}

	serde_json::to_string(params).is_ok_and(|params| {
		message == format!("get_kernel({}): {}", params, KERNEL_NOT_FOUND_ERROR)
	})
}

/// Validate that a successful kernel lookup answers the exact request before
/// the response is used to update wallet transaction state.
pub fn validate_located_kernel_response(
	excess: &pedersen::Commitment,
	min_height: Option<u64>,
	max_height: Option<u64>,
	response: LocatedTxKernel,
) -> Result<(TxKernel, u64, u64), WalletError> {
	if response.tx_kernel.excess != *excess {
		return Err(WalletError::Node(format!(
			"NodeClient::get_kernel, node returned a different kernel, requested_kernel={:?} returned_kernel={:?}",
			excess, response.tx_kernel.excess
		)));
	}
	if min_height.is_some_and(|min| response.height < min)
		|| max_height.is_some_and(|max| response.height > max)
	{
		return Err(WalletError::Node(format!(
			"NodeClient::get_kernel, node returned a kernel outside the requested height range, requested_min_height={:?} requested_max_height={:?} returned_height={}",
			min_height, max_height, response.height
		)));
	}

	Ok((response.tx_kernel, response.height, response.mmr_index))
}
