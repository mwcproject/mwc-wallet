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

use crate::cmd::wallet_args;
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use clap::{App, AppSettings};
//use colored::Colorize;
use mwc_wallet_api::Owner;
use mwc_wallet_config::{MQSConfig, TorConfig, WalletConfig};
use mwc_wallet_controller::command::GlobalArgs;
use mwc_wallet_controller::Error;
use mwc_wallet_impls::DefaultWalletImpl;
use mwc_wallet_libwallet::{NodeClient, WalletInst, WalletLCProvider};
use mwc_wallet_util::mwc_keychain as keychain;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper, OutputStreamType};
use std::borrow::Cow::{self, Borrowed, Owned};
use std::sync::Arc;
use std::time::Duration;

const COLORED_PROMPT: &'static str = "\x1b[36mmwc-wallet>\x1b[0m ";
const PROMPT: &'static str = "mwc-wallet> ";
//const HISTORY_PATH: &str = ".history";

// static for keeping track of current stdin buffer contents
lazy_static! {
	static ref STDIN_CONTENTS: Mutex<String> = Mutex::new(String::from(""));
}

#[macro_export]
macro_rules! cli_message_inline {
	($fmt_string:expr, $( $arg:expr ),+) => {
			{
					use std::io::Write;
					let contents = STDIN_CONTENTS.lock();
					/* use crate::common::{is_cli, COLORED_PROMPT}; */
					/* if is_cli() { */
							print!("\r");
							print!($fmt_string, $( $arg ),*);
							print!(" {}", COLORED_PROMPT);
							print!("\x1B[J");
							print!("{}", *contents);
							std::io::stdout().flush().unwrap();
					/*} else {
							info!($fmt_string, $( $arg ),*);
					}*/
			}
	};
}

#[macro_export]
macro_rules! cli_message {
	($fmt_string:expr, $( $arg:expr ),+) => {
			{
					use std::io::Write;
					/* use crate::common::{is_cli, COLORED_PROMPT}; */
					/* if is_cli() { */
							//print!("\r");
							print!($fmt_string, $( $arg ),*);
							println!();
							std::io::stdout().flush().unwrap();
					/*} else {
							info!($fmt_string, $( $arg ),*);
					}*/
			}
	};
}

pub fn command_loop<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	mqs_config: &MQSConfig,
	global_wallet_args: &mut GlobalArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let editor = Config::builder()
		.history_ignore_space(true)
		.completion_type(CompletionType::List)
		.edit_mode(EditMode::Emacs)
		.output_stream(OutputStreamType::Stdout)
		.build();

	let mut reader = Editor::with_config(editor);
	reader.set_helper(Some(EditorHelper(
		FilenameCompleter::new(),
		MatchingBracketHighlighter::new(),
	)));

	/*let history_file = self
		.api
		.config()
		.get_data_path()
		.unwrap()
		.parent()
		.unwrap()
		.join(HISTORY_PATH);
	if history_file.exists() {
		let _ = reader.load_history(&history_file);
	}*/

	let yml = load_yaml!("../bin/mwc-wallet.yml");
	let mut app = App::from_yaml(yml)
		.version(crate_version!())
		.setting(AppSettings::VersionlessSubcommands);
	let mut keychain_mask = keychain_mask;

	// catch updater messages
	// mwc updater thread is better, it will be created for None
	let mut owner_api = Owner::new(wallet_inst, None, None);

	// start the automatic updater
	owner_api.start_updater((&keychain_mask).as_ref(), Duration::from_secs(60))?;
	let mut wallet_opened = false;
	loop {
		match reader.readline(PROMPT) {
			Ok(command) => {
				if command.is_empty() {
					continue;
				}
				// TODO tidy up a bit
				if command.to_lowercase().trim() == "exit" {
					break;
				}
				/* use crate::common::{is_cli, COLORED_PROMPT}; */

				// reset buffer
				{
					let mut contents = STDIN_CONTENTS.lock();
					*contents = String::from("");
				}

				// Just add 'mwc-wallet' to each command behind the scenes
				// so we don't need to maintain a separate definition file
				// shlex::split is escaping back slash, need to double it
				let augmented_command = format!("mwc-wallet {}", command).replace(r"\", r"\\");
				let command_split = match shlex::split(&augmented_command) {
					Some(command_split) => command_split,
					None => vec!["mwc-wallet".to_string()],
				};
				let args = app.get_matches_from_safe_borrow(command_split);
				let done = match args {
					Ok(args) => {
						// handle opening /closing separately
						keychain_mask = match args.subcommand() {
							("open", Some(args)) => {
								let mut wallet_lock = owner_api.wallet_inst.lock();
								let lc = wallet_lock.lc_provider().unwrap();

								let mask = match lc.open_wallet(
									None,
									wallet_args::prompt_password(&global_wallet_args.password),
									false,
									false,
									None,
								) {
									Ok(m) => {
										wallet_opened = true;
										m
									}
									Err(e) => {
										cli_message!("{}", e);
										None
									}
								};

								let wallet_inst = lc.wallet_inst()?;

								mwc_wallet_libwallet::swap::trades::init_swap_trade_backend(
									wallet_inst.get_data_file_dir(),
									&wallet_config.swap_electrumx_addr,
									&wallet_config.eth_swap_contract_address,
									&wallet_config.erc20_swap_contract_address,
									&wallet_config.eth_infura_project_id,
								);

								if wallet_opened {
									let wallet_inst = lc.wallet_inst()?;
									// Account name comes from open argument, next from global param, next 'default'
									let account_name: String = match args.value_of("account") {
										Some(account) => account.to_string(),
										None => match &global_wallet_args.account {
											Some(account) => account.clone(),
											None => "default".to_string(),
										},
									};
									wallet_inst.set_parent_key_id_by_name(account_name.as_str())?;
									global_wallet_args.account = Some(account_name);
								}
								mask
							}
							("close", Some(_)) => {
								let mut wallet_lock = owner_api.wallet_inst.lock();
								let lc = wallet_lock.lc_provider().unwrap();
								lc.close_wallet(None)?;
								None
							}
							_ => keychain_mask,
						};
						match wallet_args::parse_and_execute(
							&mut owner_api,
							keychain_mask.clone(),
							&wallet_config,
							&tor_config,
							&mqs_config,
							&global_wallet_args,
							&args,
							test_mode,
							true,
						) {
							Ok(_) => {
								cli_message!("Command '{}' completed", args.subcommand().0);
								false
							}
							Err(err) => {
								cli_message!("{}", err);
								false
							}
						}
					}
					Err(err) => {
						cli_message!("{}", err);
						false
					}
				};
				reader.add_history_entry(command);
				if done {
					println!();
					break;
				}
			}
			Err(err) => {
				println!("Unable to read line: {}", err);
				break;
			}
		}
	}
	Ok(())

	//let _ = reader.save_history(&history_file);
}

struct EditorHelper(FilenameCompleter, MatchingBracketHighlighter);

impl Completer for EditorHelper {
	type Candidate = Pair;

	fn complete(
		&self,
		line: &str,
		pos: usize,
		ctx: &Context<'_>,
	) -> std::result::Result<(usize, Vec<Pair>), ReadlineError> {
		self.0.complete(line, pos, ctx)
	}
}

impl Hinter for EditorHelper {
	fn hint(&self, line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
		let mut contents = STDIN_CONTENTS.lock();
		*contents = line.into();
		None
	}
}

impl Highlighter for EditorHelper {
	fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
		self.1.highlight(line, pos)
	}

	fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
		&'s self,
		prompt: &'p str,
		default: bool,
	) -> Cow<'b, str> {
		if default {
			Borrowed(COLORED_PROMPT)
		} else {
			Borrowed(prompt)
		}
	}

	fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
		Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
	}

	fn highlight_char(&self, line: &str, pos: usize) -> bool {
		self.1.highlight_char(line, pos)
	}
}
impl Validator for EditorHelper {}
impl Helper for EditorHelper {}
