// Copyright 2026 The MWC Developers
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

use mwc_wallet_util::mwc_crates::rand;
use std::convert::Infallible;

/// StepRng implementaiton that was dropped from rand crate.  StepRng is used for tests,
/// that is why are keeping it. Switching to another generator does make many tests invalid
#[derive(Clone)]
pub struct StepRng {
	value: u64,
	step: u64,
}

impl StepRng {
	/// Create a new instance
	pub fn new(value: u64, step: u64) -> Self {
		Self { value, step }
	}
}

impl rand::TryRng for StepRng {
	type Error = Infallible;

	fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
		let v = self.value as u32;
		self.value = self.value.wrapping_add(self.step);
		Ok(v)
	}

	fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
		let v = self.value;
		self.value = self.value.wrapping_add(self.step);
		Ok(v)
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
		for chunk in dest.chunks_mut(8) {
			let v = self.try_next_u64()?.to_le_bytes();
			let len = chunk.len();
			chunk.copy_from_slice(&v[..len]);
		}
		Ok(())
	}
}
