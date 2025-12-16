extern crate bigdecimal;
extern crate regex;

use bigdecimal::BigDecimal;
use regex::Regex;
use std::collections::HashMap;
use std::ops::Mul;
use std::process;
use std::str::FromStr;

/// convert expo
pub fn convert<'a>(value: &str, unit: &'a str) -> HashMap<&'a str, String> {
	let v = to_norm(value, unit);
	let mut map: HashMap<&'a str, String> = HashMap::new();

	map.insert(unit, BigDecimal::from_str(&value).unwrap().to_string());

	if unit != "18" {
		map.insert("18", s(&v, "1000000000000000000"));
	}
	if unit != "15" {
		map.insert("15", s(&v, "1000000000000000"));
	}
	if unit != "12" {
		map.insert("12", s(&v, "1000000000000"));
	}
	if unit != "9" {
		map.insert("9", s(&v, "1000000000"));
	}
	if unit != "8" {
		map.insert("8", s(&v, "100000000"));
	}
	if unit != "6" {
		map.insert("6", s(&v, "1000000"));
	}
	if unit != "3" {
		map.insert("3", s(&v, "1000"));
	}
	if unit != "1" {
		map.insert("1", s(&v, "1"));
	}
	if unit != "+3" {
		map.insert("+3", s(&v, "0.001"));
	}
	if unit != "+6" {
		map.insert("+6", s(&v, "0.000001"));
	}
	if unit != "+9" {
		map.insert("+9", s(&v, "0.000000001"));
	}
	if unit != "+12" {
		map.insert("+12", s(&v, "0.000000000001"));
	}

	return map;
}

/// conver to 1
pub fn to_norm(value: &str, unit: &str) -> BigDecimal {
	let v = BigDecimal::from_str(&value).unwrap();

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

	error!("unit not supported, fatal error!");
	println!("unit not supported");
	process::exit(1);
}

/// convert to 9
pub fn to_gnorm(value: &str, unit: &str) -> String {
	return convert(&value, &unit).get("9").unwrap().to_string();
}

fn m(v: &BigDecimal, u: &str) -> BigDecimal {
	return v.mul(&BigDecimal::from_str(u).unwrap());
}

fn s(v: &BigDecimal, u: &str) -> String {
	return t(v.mul(&BigDecimal::from_str(u).unwrap()).to_string());
}

// normalize decimal places
// TODO: better way
fn t(v: String) -> String {
	let re = Regex::new(r"(.*)\.0+$").unwrap();
	let v = re.replace_all(&v, "$1").to_string();
	let re = Regex::new(r"(.*\.\d+[1-9]+)(0+)$").unwrap();
	return re.replace_all(&v, "$1").to_string();
}
