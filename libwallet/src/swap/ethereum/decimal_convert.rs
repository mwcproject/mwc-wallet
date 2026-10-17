// Copyright 2026 The Mwc Developers
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

use mwc_wallet_util::mwc_crates::bigdecimal::{BigDecimal, ParseBigDecimalError};
use std::collections::HashMap;
use std::str::FromStr;

/// convert expo
pub fn convert<'a>(
	value: &str,
	unit: &'a str,
) -> Result<HashMap<&'a str, String>, ParseBigDecimalError> {
	let v = to_norm(value, unit)?;
	let mut map: HashMap<&'a str, String> = HashMap::new();

	map.insert(unit, BigDecimal::from_str(&value)?.to_string());

	if unit != "18" {
		map.insert("18", s(&v, "1000000000000000000")?);
	}
	if unit != "15" {
		map.insert("15", s(&v, "1000000000000000")?);
	}
	if unit != "12" {
		map.insert("12", s(&v, "1000000000000")?);
	}
	if unit != "9" {
		map.insert("9", s(&v, "1000000000")?);
	}
	if unit != "8" {
		map.insert("8", s(&v, "100000000")?);
	}
	if unit != "6" {
		map.insert("6", s(&v, "1000000")?);
	}
	if unit != "3" {
		map.insert("3", s(&v, "1000")?);
	}
	if unit != "1" {
		map.insert("1", s(&v, "1")?);
	}
	if unit != "+3" {
		map.insert("+3", s(&v, "0.001")?);
	}
	if unit != "+6" {
		map.insert("+6", s(&v, "0.000001")?);
	}
	if unit != "+9" {
		map.insert("+9", s(&v, "0.000000001")?);
	}
	if unit != "+12" {
		map.insert("+12", s(&v, "0.000000000001")?);
	}

	Ok(map)
}

/// conver to 1
pub fn to_norm(value: &str, unit: &str) -> Result<BigDecimal, ParseBigDecimalError> {
	let v = BigDecimal::from_str(&value)?;

	if unit == "18" {
		return m(&v, "0.000000000000000001");
	}
	if unit == "15" {
		return m(&v, "0.000000000000001");
	}
	if unit == "12" {
		return m(&v, "0.000000000001");
	}
	if unit == "9" {
		return m(&v, "0.000000001");
	}
	if unit == "8" {
		return m(&v, "0.00000001");
	}
	if unit == "6" {
		return m(&v, "0.000001");
	}
	if unit == "3" {
		return m(&v, "0.001");
	}
	if unit == "1" {
		return m(&v, "1");
	}
	if unit == "+3" {
		return m(&v, "1000");
	}
	if unit == "+6" {
		return m(&v, "1000000");
	}
	if unit == "+9" {
		return m(&v, "1000000000");
	}
	if unit == "+12" {
		return m(&v, "1000000000000");
	}

	return Err(ParseBigDecimalError::Other(format!(
		"to_norm param error, unsupported unit {}",
		unit
	)));
}

/// convert to 9
pub fn to_gnorm(value: &str, unit: &str) -> Result<String, ParseBigDecimalError> {
	Ok(convert(&value, &unit)?
		.get("9")
		.ok_or(ParseBigDecimalError::Other(
			"Internal error, not found unit '9'".into(),
		))?
		.to_string())
}

fn m(v: &BigDecimal, u: &str) -> Result<BigDecimal, ParseBigDecimalError> {
	let u = BigDecimal::from_str(u)?;
	let (v_digits, v_scale) = v.as_bigint_and_scale();
	let (u_digits, u_scale) = u.into_bigint_and_scale();
	let scale = v_scale.checked_add(u_scale).ok_or_else(|| {
		ParseBigDecimalError::Other("Decimal scale overflow during multiplication".into())
	})?;

	// Multiply the coefficients directly to avoid unchecked scale arithmetic and
	// normalization in BigDecimal::mul, including when one of the factors is one.
	Ok(BigDecimal::from_bigint(v_digits.as_ref() * u_digits, scale))
}

fn s(v: &BigDecimal, u: &str) -> Result<String, ParseBigDecimalError> {
	Ok(t(m(v, u)?.to_string()))
}

// normalize decimal places
fn t(mut v: String) -> String {
	// Trim only the mantissa so trailing zeros in the exponent stay intact.
	let exponent_start = v.find(['e', 'E']).unwrap_or(v.len());
	if v[..exponent_start].contains('.') {
		let trimmed_len = v[..exponent_start]
			.trim_end_matches('0')
			.trim_end_matches('.')
			.len();
		v.replace_range(trimmed_len..exponent_start, "");
	}
	v
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn multiplication_rejects_scale_overflow() {
		for (value, factor) in [
			("1e-9223372036854775807", "0.000000000000000001"),
			("-1e-9223372036854775807", "0.001"),
			("1e9223372036854775808", "1e1"),
		] {
			let value = BigDecimal::from_str(value).unwrap();
			assert!(matches!(
				m(&value, factor),
				Err(ParseBigDecimalError::Other(_))
			));
			assert!(matches!(
				s(&value, factor),
				Err(ParseBigDecimalError::Other(_))
			));
		}
	}

	#[test]
	fn conversion_propagates_scale_overflow() {
		let value = "1e-9223372036854775807";
		for unit in ["18", "15", "12", "9", "8", "6", "3"] {
			assert!(matches!(
				to_norm(value, unit),
				Err(ParseBigDecimalError::Other(_))
			));
		}
		assert!(matches!(
			convert(value, "18"),
			Err(ParseBigDecimalError::Other(_))
		));
		assert!(matches!(
			to_gnorm(value, "18"),
			Err(ParseBigDecimalError::Other(_))
		));
	}

	#[test]
	fn multiplication_preserves_representable_scale_boundaries() {
		let upper = to_norm("1e-9223372036854775789", "18").unwrap();
		assert_eq!(upper.as_bigint_and_exponent(), (1.into(), i64::MAX));

		// Multiplying by one must not normalize trailing zeros past i64::MIN.
		let lower = to_norm("10e9223372036854775808", "1").unwrap();
		assert_eq!(lower.as_bigint_and_exponent(), (10.into(), i64::MIN));
	}

	#[test]
	fn multiplication_preserves_exact_amounts() {
		for (value, factor, expected) in [
			("-12.50", "1000", "-12500"),
			("0", "0.000000000000000001", "0"),
			("1.00", "0.001", "0.001"),
			("1.2300", "1", "1.23"),
			(
				"123456789012345678901234567890.123456789",
				"0.000000001",
				"123456789012345678901.234567890123456789",
			),
		] {
			let value = BigDecimal::from_str(value).unwrap();
			let expected = BigDecimal::from_str(expected).unwrap();
			assert_eq!(m(&value, factor).unwrap(), expected);
		}
	}

	#[test]
	fn multiplication_propagates_parse_errors() {
		let value = BigDecimal::from_str("1").unwrap();
		for factor in ["", "invalid", "1e-9223372036854775808"] {
			assert!(m(&value, factor).is_err());
		}
	}

	#[test]
	fn trim_fractional_zeros_preserves_exponents() {
		for (input, expected) in [
			("1.2000", "1.2"),
			("1200.000", "1200"),
			("1200", "1200"),
			("0.000", "0"),
			("-1.2000", "-1.2"),
			("1.2E-10", "1.2E-10"),
			("1.2000E-10", "1.2E-10"),
			("-1.2000E-20", "-1.2E-20"),
			("1.2000e+20", "1.2e+20"),
			("1.000E-10", "1E-10"),
			("1.2000E+0", "1.2E+0"),
			("1200E-10", "1200E-10"),
		] {
			assert_eq!(t(input.to_string()), expected, "input: {input}");
		}
	}

	#[test]
	fn convert_preserves_small_amounts() {
		for (value, unit, target, expected) in [
			("120000000", "18", "1", "0.00000000012"),
			("-120000000", "18", "1", "-0.00000000012"),
			("0.12", "1", "+9", "0.00000000012"),
		] {
			let converted = convert(value, unit).unwrap();
			assert_eq!(
				BigDecimal::from_str(converted.get(target).unwrap()).unwrap(),
				BigDecimal::from_str(expected).unwrap(),
				"convert({value:?}, {unit:?})[{target:?}]"
			);
		}
	}
}
