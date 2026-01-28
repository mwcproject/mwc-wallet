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
	mwc_wallet_libwallet::owner_swap::owner_swap_clean_context(context_id);
	mwc_wallet_libwallet::internal::scan::scan_clean_context(context_id);
	mwc_wallet_libwallet::swap::trades::trades_clean_context(context_id);
	mwc_wallet_impls::adapters::reset_mwcmqs_brocker(context_id);
	mwc_wallet_impls::tor::status::tor_status_clean_context(context_id);
	mwc_wallet_controller::command::auto_swaps_clean_context(context_id);
	mwc_wallet_controller::controller::foreign_owner_api_clean_context(context_id);
	mwc_wallet_controller::controller::reset_foreign_api_health(context_id);
	mwc_wallet_libwallet::internal::scan::release_interrupt_scan(context_id);
}

pub fn release_wallet_context(context_id: u32) {
	mwc_wallet_libwallet::foreign::foreign_clean_context(context_id);
	mwc_wallet_libwallet::owner_swap::owner_swap_clean_context(context_id);
	mwc_wallet_libwallet::internal::scan::scan_clean_context(context_id);
	mwc_wallet_libwallet::swap::trades::trades_clean_context(context_id);
	mwc_wallet_impls::adapters::reset_mwcmqs_brocker(context_id);
	mwc_wallet_impls::tor::status::tor_status_clean_context(context_id);
	mwc_wallet_controller::command::auto_swaps_clean_context(context_id);
	mwc_wallet_controller::controller::foreign_owner_api_clean_context(context_id);
	mwc_wallet_controller::controller::reset_foreign_api_health(context_id);
	mwc_wallet_libwallet::internal::scan::release_interrupt_scan(context_id);
}
