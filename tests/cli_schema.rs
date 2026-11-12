// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

use mwc_wallet_util::mwc_crates::clap::{error::ErrorKind, parser::ValueSource, Command};
use mwc_wallet_util::mwc_crates::{shlex, yaml_rust2::YamlLoader};
use mwc_wallet_util::mwc_util::cli::{command_from_yaml, ArgMatchesExt};

fn wallet_command() -> Command {
	let yaml = YamlLoader::load_from_str(include_str!("../src/bin/mwc-wallet.yml")).unwrap();
	command_from_yaml(&yaml[0])
}

#[test]
fn embedded_commands_are_valid() {
	wallet_command().debug_assert();
}

#[test]
fn defaults_and_explicit_options_remain_distinct() {
	let matches = wallet_command()
		.try_get_matches_from(["mwc-wallet", "--pass", "", "send", "1"])
		.unwrap();
	assert_eq!(matches.value_of("pass"), Some(""));
	let send = matches.subcommand_matches("send").unwrap();
	assert_eq!(send.value_of("minimum_confirmations"), Some("10"));
	assert_eq!(send.value_of("method"), Some("http"));
	assert_eq!(send.value_source("method"), Some(ValueSource::DefaultValue));
	assert!(!send.is_present("proof"));
	assert!(!send.is_present("not_in_this_command"));
	assert_eq!(send.value_of("not_in_this_command"), None);

	let matches = wallet_command()
		.try_get_matches_from(["mwc-wallet", "send", "1", "--method", "http"])
		.unwrap();
	let send = matches.subcommand_matches("send").unwrap();
	assert_eq!(send.value_source("method"), Some(ValueSource::CommandLine));
}

#[test]
fn console_reuses_parser_without_retaining_previous_flags() {
	let mut command = wallet_command();
	let first = command
		.try_get_matches_from_mut(["mwc-wallet", "scan", "--delete_unconfirmed"])
		.unwrap();
	assert!(first
		.subcommand_matches("scan")
		.unwrap()
		.is_present("delete_unconfirmed"));
	assert!(command
		.try_get_matches_from_mut(["mwc-wallet", "send"])
		.is_err());
	let next = command
		.try_get_matches_from_mut(["mwc-wallet", "scan"])
		.unwrap();
	assert!(!next
		.subcommand_matches("scan")
		.unwrap()
		.is_present("delete_unconfirmed"));
}

#[test]
fn height_short_option_and_help_both_work() {
	let matches = wallet_command()
		.try_get_matches_from(["mwc-wallet", "scan", "-h", "120"])
		.unwrap();
	assert_eq!(
		matches
			.subcommand_matches("scan")
			.unwrap()
			.value_of("start_height"),
		Some("120")
	);
	assert_eq!(
		wallet_command()
			.try_get_matches_from(["mwc-wallet", "scan", "--help"])
			.unwrap_err()
			.kind(),
		ErrorKind::DisplayHelp
	);
}

#[test]
fn console_preserves_quoted_content_and_paths() {
	// Apply the console's existing backslash handling before shlex splitting.
	let input = r#"mwc-wallet send 1 --method file --dest 'C:\wallet files\tx.slate' --message 'hello, "MWC"'"#;
	let args = shlex::split(&input.replace(r"\", r"\\")).unwrap();
	let matches = wallet_command().try_get_matches_from(args).unwrap();
	let send = matches.subcommand_matches("send").unwrap();
	assert_eq!(send.value_of("message"), Some("hello, \"MWC\""));
	assert_eq!(send.value_of("dest"), Some(r"C:\\wallet files\\tx.slate"));
}
