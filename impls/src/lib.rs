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

//! Concrete implementations of types found in libwallet, organised this
//! way mostly to avoid any circular dependencies of any kind
//! Functions in this crate should not use the wallet api crate directly

use blake2_rfc as blake2;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate lazy_static;
use mwc_wallet_libwallet as libwallet;
use mwc_wallet_util::mwc_api as api;
use mwc_wallet_util::mwc_chain as chain;
use mwc_wallet_util::mwc_core as core;
pub use mwc_wallet_util::mwc_keychain as keychain;
use mwc_wallet_util::mwc_p2p;
use mwc_wallet_util::mwc_store as store;
use mwc_wallet_util::mwc_util as util;

use mwc_wallet_config as config;

pub mod adapters;
mod backends;
mod client_utils;
mod error;
pub mod lifecycle;
pub mod node_clients;
pub mod test_framework;
pub mod tor;

pub use crate::adapters::libp2p_messaging;
pub use crate::adapters::{
	create_sender, get_mwcmqs_brocker, init_mwcmqs_access_data, Address, AddressType, CloseReason,
	HttpDataSender, HttpsAddress, MWCMQPublisher, MWCMQSAddress, MWCMQSubscriber, MwcMqsChannel,
	PathToSlateGetter, PathToSlatePutter, Publisher, SlateGetter, SlatePutter, SlateReceiver,
	SlateSender, Subscriber, SubscriptionHandler, SwapMessageSender,
};
pub use crate::backends::{wallet_db_exists, LMDBBackend};
pub use crate::error::Error;
pub use crate::lifecycle::DefaultLCProvider;
pub use crate::node_clients::HTTPNodeClient;

use crate::keychain::{ExtKeychain, Keychain};

use libwallet::{NodeClient, WalletInst, WalletLCProvider};

/// Main wallet instance
pub struct DefaultWalletImpl<'a, C>
where
	C: NodeClient + 'a,
{
	lc_provider: DefaultLCProvider<'a, C, ExtKeychain>,
}

impl<'a, C> DefaultWalletImpl<'a, C>
where
	C: NodeClient + 'a,
{
	pub fn new(node_client: C) -> Result<Self, Error> {
		let lc_provider = DefaultLCProvider::new(node_client);
		Ok(DefaultWalletImpl {
			lc_provider: lc_provider,
		})
	}
}

impl<'a, L, C, K> WalletInst<'a, L, C, K> for DefaultWalletImpl<'a, C>
where
	DefaultLCProvider<'a, C, ExtKeychain>: WalletLCProvider<'a, C, K>,
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn lc_provider(
		&mut self,
	) -> Result<&mut (dyn WalletLCProvider<'a, C, K> + 'a), libwallet::Error> {
		Ok(&mut self.lc_provider)
	}
}
