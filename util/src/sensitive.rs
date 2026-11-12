// Copyright 2026 The Mwc Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helpers for keeping accumulated sensitive representations in allocations
//! that can be fully zeroized.

use mwc_crates::serde::Serialize;
use mwc_crates::serde_json;
use mwc_crates::zeroize::Zeroizing;
use std::io::{self, Write};

#[derive(Default)]
struct JsonSizeCounter {
	len: usize,
}

impl Write for JsonSizeCounter {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.len = self.len.checked_add(buf.len()).ok_or_else(|| {
			io::Error::new(io::ErrorKind::InvalidData, "sensitive JSON length overflow")
		})?;
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// Serialize JSON into one fixed, zeroizing heap allocation.
///
/// A first pass counts bytes without retaining them. A second pass writes into
/// an exactly sized boxed slice, which cannot reallocate. Consequently, the
/// returned `Zeroizing` wrapper owns the only output allocation that
/// accumulated the complete serialized plaintext and can erase it on every
/// return path. A serialization implementation whose output size changes
/// between passes is rejected rather than allowed to grow the buffer.
pub fn serialize_json<T>(value: &T) -> Result<Zeroizing<Box<[u8]>>, serde_json::Error>
where
	T: ?Sized + Serialize,
{
	let mut counter = JsonSizeCounter::default();
	serde_json::to_writer(&mut counter, value)?;

	let expected_len = counter.len;
	let mut plaintext = Zeroizing::new(vec![0u8; expected_len].into_boxed_slice());
	let position = {
		let mut writer = io::Cursor::new(&mut **plaintext);
		serde_json::to_writer(&mut writer, value)?;
		writer.position()
	};
	let actual_len = usize::try_from(position).map_err(|_| {
		serde_json::Error::io(io::Error::new(
			io::ErrorKind::InvalidData,
			"sensitive JSON length does not fit usize",
		))
	})?;
	if actual_len != expected_len {
		return Err(serde_json::Error::io(io::Error::new(
			io::ErrorKind::InvalidData,
			"sensitive JSON length changed between serialization passes",
		)));
	}

	Ok(plaintext)
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::serde::Serializer;
	use std::cell::Cell;

	struct GrowingSerialization<'a> {
		second_pass: &'a Cell<bool>,
	}

	impl Serialize for GrowingSerialization<'_> {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			if self.second_pass.replace(true) {
				serializer.serialize_str("longer second pass")
			} else {
				serializer.serialize_str("short")
			}
		}
	}

	#[test]
	fn sensitive_json_serialization_matches_serde_json() {
		let value = format!(
			"secret JSON with quotes: \" and controls: \n\u{0007}{}",
			"x".repeat(8_192)
		);
		let expected = serde_json::to_vec(&value).unwrap();
		let sensitive = serialize_json(&value).unwrap();

		assert_eq!(&sensitive[..], expected.as_slice());
	}

	#[test]
	fn growing_second_pass_is_rejected_instead_of_reallocating() {
		let second_pass = Cell::new(false);
		let value = GrowingSerialization {
			second_pass: &second_pass,
		};

		assert!(serialize_json(&value).is_err());
	}
}
