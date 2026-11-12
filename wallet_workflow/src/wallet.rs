// Copyright 2025 The MWC Developers
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

// mwc-wallet workflow

pub fn init_wallet_context(context_id: u32) {
	mwc_wallet_libwallet::foreign::foreign_clean_context(context_id);
	#[cfg(feature = "swaps")]
	mwc_wallet_libwallet::owner_swap::owner_swap_clean_context(context_id);
	mwc_wallet_libwallet::internal::scan::scan_clean_context(context_id);
	#[cfg(feature = "swaps")]
	mwc_wallet_libwallet::swap::trades::trades_clean_context(context_id);
	// Context initialization has no error return; explicit listener/owner stop
	// paths propagate this result to their callers.
	let _ = mwc_wallet_impls::adapters::reset_mwcmqs_brocker(context_id);
	mwc_wallet_libwallet::proof::tx_proof::clear_proofs_for_context(context_id);
	mwc_wallet_impls::tor::status::tor_status_clean_context(context_id);
	mwc_wallet_controller::controller::foreign_owner_api_clean_context(context_id);
	mwc_wallet_controller::controller::reset_foreign_api_health(context_id);
	mwc_wallet_libwallet::internal::scan::release_interrupt_scan(context_id);
}

/// Synchronously stop context-owned listeners, then clear wallet-scoped state.
///
/// Direct library calls, including listener startup, are caller-owned and must
/// have returned before this function is invoked.
/// Any MQS listener error is returned after the remaining cleanup has completed.
///
/// HTTP shutdown errors are intentionally reported through logs; Owner API
/// errors are also sent to its listener waiter. These errors do not skip the
/// remaining joins or context cleanup. Even a failed thread join means that
/// thread has terminated. Logging is the accepted diagnostic policy here:
/// this result reports MQS errors, and Ok does not promise an error-free HTTP
/// listener exit. Propagating HTTP diagnostics is not required for safe cleanup.
pub fn release_wallet_context(context_id: u32) -> Result<(), mwc_wallet_impls::Error> {
	// A context id is the lifetime identity of one wallet session. Stop and join
	// every context-owned listener before clearing any context-id-keyed state. A
	// join, rather than a stop signal alone, lets an already-dispatched request
	// finish its final persistence against the wallet that admitted it.
	// HTTP requests may still be awaiting an MQS response or persisting its
	// transport proof. Keep MQS and its proof-cache lease alive until they drain.
	mwc_wallet_controller::controller::foreign_owner_api_clean_context(context_id);
	let mqs_result = mwc_wallet_impls::adapters::reset_mwcmqs_brocker(context_id);
	mwc_wallet_libwallet::proof::tx_proof::clear_proofs_for_context(context_id);
	// Direct library calls are not owned by these listeners. Callers must finish
	// and join them before invoking context release.
	mwc_wallet_libwallet::foreign::foreign_clean_context(context_id);
	#[cfg(feature = "swaps")]
	mwc_wallet_libwallet::owner_swap::owner_swap_clean_context(context_id);
	mwc_wallet_libwallet::internal::scan::scan_clean_context(context_id);
	#[cfg(feature = "swaps")]
	mwc_wallet_libwallet::swap::trades::trades_clean_context(context_id);
	mwc_wallet_impls::tor::status::tor_status_clean_context(context_id);
	mwc_wallet_controller::controller::reset_foreign_api_health(context_id);
	mwc_wallet_libwallet::internal::scan::release_interrupt_scan(context_id);
	mqs_result
}
