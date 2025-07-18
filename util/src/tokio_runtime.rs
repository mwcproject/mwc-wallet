// Copyright 2024 The MWC Developers
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

//! Utilities and re-exports
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};

use tokio::runtime::{Builder, Runtime};

lazy_static! {
	/// Note: RUNTIME can be used in multiple crates, that is why it is declared in utils.
	/// Global Tokio runtime.
	/// Needs a `Mutex` because `Runtime::block_on` requires mutable access.
	/// Tokio v0.3 requires immutable self, but we are waiting on upstream
	/// updates before we can upgrade.
	/// See: https://github.com/seanmonstar/reqwest/pull/1076
	pub static ref RUNTIME: Arc<Mutex<Runtime>> = Arc::new(Mutex::new(
		Builder::new_multi_thread()
			.enable_all()
			.build()
			.unwrap()
	));
}
