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

#![cfg(feature = "test-support")]

use mwc_wallet_util::mwc_crates::rand;
use std::convert::Infallible;

/// Legacy deterministic RNG retained for compatibility with existing test vectors.
/// This module is compiled only with `test-support`; production code must use a secure RNG.
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

	#[allow(
		clippy::cast_possible_truncation,
		reason = "TryRng::try_next_u32 intentionally returns the low 32 bits of the 64-bit step state"
	)]
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

#[cfg(test)]
mod tests {
	use super::StepRng;
	use mwc_wallet_util::mwc_crates::rand::TryRng;

	#[test]
	fn deterministic_stream_requires_test_support() {
		let mut rng = StepRng::new(1_234_567_890, 1);
		assert_eq!(rng.try_next_u64().unwrap(), 1_234_567_890);
		assert_eq!(rng.try_next_u64().unwrap(), 1_234_567_891);
	}
}
