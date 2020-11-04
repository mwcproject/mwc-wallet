// Copyright 2020 The MWC Developers
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

use super::types::{Address, Publisher, Subscriber, SubscriptionHandler};
use crate::adapters::types::MWCMQSAddress;
use crate::error::{Error, ErrorKind};
use crate::libwallet::proof::crypto;
use crate::libwallet::proof::crypto::Hex;
use crate::util::Mutex;

use crate::SlateSender;
use crate::SwapMessageSender;
use grin_core::core::amount_to_hr_string;
use grin_util::RwLock;
use grin_wallet_libwallet::proof::message::EncryptedMessage;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use grin_wallet_libwallet::proof::tx_proof::{push_proof_for_slate, TxProof};
use grin_wallet_libwallet::swap::message::Message;
use grin_wallet_libwallet::swap::message::SwapMessage;
use grin_wallet_libwallet::{Slate, VersionedSlate};
use grin_wallet_util::grin_util::secp::key::SecretKey;
use regex::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;
use std::{thread, time};

extern crate nanoid;

const TIMEOUT_ERROR_REGEX: &str = r"timed out";

// MQS enforced to have a single instance. And different compoments migth manage
// instances separatlly.
// Also all dependent components want to use MQS and they need interface.
// Since instance is single, interface will be global
lazy_static! {
	static ref MWCMQS_BROKER: RwLock<Option<(MWCMQPublisher, MWCMQSubscriber)>> = RwLock::new(None);
}

/// Init mwc mqs objects for the access.
pub fn init_mwcmqs_access_data(publisher: MWCMQPublisher, subscriber: MWCMQSubscriber) {
	MWCMQS_BROKER.write().replace((publisher, subscriber));
}

/// Init mwc mqs objects for the access.
pub fn get_mwcmqs_brocker() -> Option<(MWCMQPublisher, MWCMQSubscriber)> {
	MWCMQS_BROKER.read().clone()
}

/// Reset Broker (listener is stopped)
pub fn reset_mwcmqs_brocker() {
	MWCMQS_BROKER.write().take();
}

pub struct MwcMqsChannel {
	des_address: String,
}

impl MwcMqsChannel {
	pub fn new(des_address: String) -> Self {
		Self {
			des_address: des_address,
		}
	}

	fn send_tx_to_mqs(
		&self,
		slate: &Slate,
		mwcmqs_publisher: MWCMQPublisher,
		rx_slate: Receiver<Slate>,
	) -> Result<Slate, Error> {
		let des_address = MWCMQSAddress::from_str(self.des_address.as_ref()).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Invalid destination address, {}", e))
		})?;
		mwcmqs_publisher
			.post_slate(&slate, &des_address)
			.map_err(|e| {
				ErrorKind::MqsGenericError(format!(
					"MQS unable to transfer slate {} to the worker, {}",
					slate.id, e
				))
			})?;

		println!(
			"slate [{}] for [{}] MWCs sent to [{}]",
			slate.id.to_string(),
			amount_to_hr_string(slate.amount, false),
			des_address,
		);

		//expect to get slate back.
		let slate_returned = rx_slate
			.recv_timeout(Duration::from_secs(120))
			.map_err(|e| {
				ErrorKind::MqsGenericError(format!(
					"MQS unable to process slate {}, {}",
					slate.id, e
				))
			})?;
		return Ok(slate_returned);
	}

	fn send_swap_to_mqs(
		&self,
		swap_message: &Message,
		mwcmqs_publisher: MWCMQPublisher,
		_rs_message: Receiver<Message>,
	) -> Result<(), Error> {
		let des_address = MWCMQSAddress::from_str(self.des_address.as_ref()).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Invalid destination address, {}", e))
		})?;
		mwcmqs_publisher
			.post_take(swap_message, &des_address)
			.map_err(|e| {
				ErrorKind::MqsGenericError(format!(
					"MQS unable to transfer swap message {} to the worker, {}",
					swap_message.id, e
				))
			})?;
		Ok(())
	}
}

impl SlateSender for MwcMqsChannel {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		if let Some((mwcmqs_publisher, mwcmqs_subscriber)) = get_mwcmqs_brocker() {
			// Creating channels for notification
			let (tx_slate, rx_slate) = channel(); //this chaneel is used for listener thread to send message to other thread

			mwcmqs_subscriber.set_notification_channels(&slate.id, tx_slate);
			let res = self.send_tx_to_mqs(slate, mwcmqs_publisher, rx_slate);
			mwcmqs_subscriber.reset_notification_channels(&slate.id);
			res
		} else {
			return Err(ErrorKind::MqsGenericError(format!(
				"MQS is not started, not able to send the slate {}",
				slate.id
			))
			.into());
		}
	}
}

impl SwapMessageSender for MwcMqsChannel {
	/// Send a swap message. Return true is message delivery acknowledge can be set (message was delivered and procesed)
	fn send_swap_message(&self, message: &Message) -> Result<bool, Error> {
		if let Some((mwcmqs_publisher, _mwcmqs_subscriber)) = get_mwcmqs_brocker() {
			let (_ts_message, rs_message) = channel();

			self.send_swap_to_mqs(message, mwcmqs_publisher, rs_message)?;
			// MQS is async protocol, message might never be delivered, so no ack can be granted.
			Ok(false)
		} else {
			return Err(ErrorKind::MqsGenericError(format!(
				"MQS is not started, not able to send the swap message {}",
				message.id
			))
			.into());
		}
	}
}

#[derive(Clone)]
pub struct MWCMQPublisher {
	address: MWCMQSAddress,
	broker: MWCMQSBroker,
	secret_key: SecretKey,
}

impl MWCMQPublisher {
	// Note, Publisher must initialize controller with self
	pub fn new(
		address: MWCMQSAddress,
		secret_key: &SecretKey,
		mwcmqs_domain: String,
		mwcmqs_port: u16,
		print_to_log: bool,
		handler: Box<dyn SubscriptionHandler + Send>,
	) -> Self {
		Self {
			address,
			broker: MWCMQSBroker::new(mwcmqs_domain, mwcmqs_port, print_to_log, handler),
			secret_key: secret_key.clone(),
		}
	}
}
impl Publisher for MWCMQPublisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error> {
		let to_address_raw = format!("mwcmqs://{}", to.get_stripped());
		let to_address = MWCMQSAddress::from_str(&to_address_raw)?;
		self.broker
			.post_slate(slate, &to_address, &self.address, &self.secret_key)?;
		Ok(())
	}

	fn encrypt_slate(&self, slate: &Slate, to: &dyn Address) -> Result<String, Error> {
		let to_address_raw = format!("mwcmqs://{}", to.get_stripped());
		let to_address = MWCMQSAddress::from_str(&to_address_raw)?;
		self.broker
			.encrypt_slate(slate, &to_address, &self.address, &self.secret_key)
	}

	fn decrypt_slate(
		&self,
		from: String,
		mapmessage: String,
		signature: String,
		source_address: &ProvableAddress,
	) -> Result<String, Error> {
		let r1 = str::replace(&mapmessage, "%22", "\"");
		let r2 = str::replace(&r1, "%7B", "{");
		let r3 = str::replace(&r2, "%7D", "}");
		let r4 = str::replace(&r3, "%3A", ":");
		let r5 = str::replace(&r4, "%2C", ",");
		let r5 = r5.trim().to_string();

		let from = MWCMQSAddress::from_str(&from)?;

		let (slate, _tx_proof) = TxProof::from_response(
			&from.address,
			r5.clone(),
			"".to_string(),
			signature.clone(),
			&self.secret_key,
			&source_address,
		)
		.map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable to build txproof from the payload, {}", e))
		})?;

		let slate = serde_json::to_string(&slate).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
		})?;
		Ok(slate)
	}

	fn post_take(&self, message: &Message, to: &dyn Address) -> Result<(), Error> {
		let to_address_raw = format!("mwcmqs://{}", to.get_stripped());
		let to_address = MWCMQSAddress::from_str(&to_address_raw)?;
		self.broker
			.post_take(message, &to_address, &self.address, &self.secret_key)?;
		Ok(())
	}

	// Address of this publisher (from address)
	fn get_publisher_address(&self) -> Result<Box<dyn Address>, Error> {
		Ok(Box::new(self.address.clone()))
	}
}

#[derive(Clone)]
pub struct MWCMQSubscriber {
	address: MWCMQSAddress,
	broker: MWCMQSBroker,
	secret_key: SecretKey,
}

impl MWCMQSubscriber {
	pub fn new(publisher: &MWCMQPublisher) -> Self {
		Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
		}
	}
}
impl Subscriber for MWCMQSubscriber {
	fn start(&mut self) -> Result<(), Error> {
		self.broker
			.subscribe(&self.address.address, &self.secret_key);
		Ok(())
	}

	fn stop(&mut self) -> bool {
		if let Ok(client) = reqwest::Client::builder()
			.timeout(Duration::from_secs(60))
			.build()
		{
			let mut params = HashMap::new();
			params.insert("mapmessage", "nil");
			let response = client
				.post(&format!(
					"https://{}:{}/sender?address={}",
					self.broker.mwcmqs_domain,
					self.broker.mwcmqs_port,
					str::replace(&self.address.get_stripped(), "@", "%40")
				))
				.form(&params)
				.send();

			let response_status = response.is_ok();
			self.broker.stop();
			reset_mwcmqs_brocker();
			response_status
		} else {
			error!("Unable to stop mwcmqs threads");
			false
		}
	}

	fn is_running(&self) -> bool {
		self.broker.is_running()
	}

	fn set_notification_channels(&self, slate_id: &uuid::Uuid, slate_send_channel: Sender<Slate>) {
		self.broker
			.handler
			.lock()
			.set_notification_channels(slate_id, slate_send_channel);
	}

	fn reset_notification_channels(&self, slate_id: &uuid::Uuid) {
		self.broker
			.handler
			.lock()
			.reset_notification_channels(slate_id);
	}
}

#[derive(Clone)]
struct MWCMQSBroker {
	running: Arc<AtomicBool>,
	pub mwcmqs_domain: String,
	pub mwcmqs_port: u16,
	pub print_to_log: bool,
	pub handler: Arc<Mutex<Box<dyn SubscriptionHandler + Send>>>,
}

impl MWCMQSBroker {
	fn new(
		mwcmqs_domain: String,
		mwcmqs_port: u16,
		print_to_log: bool,
		handler: Box<dyn SubscriptionHandler + Send>,
	) -> Self {
		Self {
			running: Arc::new(AtomicBool::new(false)),
			mwcmqs_domain,
			mwcmqs_port,
			print_to_log,
			handler: Arc::new(Mutex::new(handler)),
		}
	}

	fn encrypt_slate(
		&self,
		slate: &Slate,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
	) -> Result<String, Error> {
		let pkey = to.address.public_key()?;
		let skey = secret_key.clone();
		let version = slate.lowest_version();
		let slate = VersionedSlate::into_version(slate.clone(), version);
		let serde_json = serde_json::to_string(&slate).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
		})?;

		let message = EncryptedMessage::new(serde_json, &to.address, &pkey, &skey)
			.map_err(|e| ErrorKind::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable convert Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key)?;
		let signature = signature.to_hex();

		let mser: &str = &message_ser;
		let mser: &str = &str::replace(mser, "{", "%7B");
		let mser: &str = &str::replace(mser, "}", "%7D");
		let mser: &str = &str::replace(mser, ":", "%3A");
		let mser: &str = &str::replace(mser, ",", "%2C");
		let mser: &str = &str::replace(mser, "\"", "%22");
		let mser: &str = &mser.trim().to_string();

		let fromstripped = from.get_stripped();

		Ok(format!(
			"mapmessage={}&from={}&signature={}",
			mser, &fromstripped, &signature
		))
	}

	fn post_slate(
		&self,
		slate: &Slate,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		if !self.is_running() {
			return Err(ErrorKind::ClosedListener("mwcmqs".to_string()).into());
		}
		let pkey = to.address.public_key()?;
		let skey = secret_key.clone();
		let version = slate.lowest_version();
		let slate = VersionedSlate::into_version(slate.clone(), version);

		let message = EncryptedMessage::new(
			serde_json::to_string(&slate).map_err(|e| {
				ErrorKind::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
			})?,
			&to.address,
			&pkey,
			&skey,
		)
		.map_err(|e| ErrorKind::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable convert Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key)?;
		let signature = signature.to_hex();

		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(120))
			.build()
			.map_err(|e| ErrorKind::GenericError(format!("Failed to build a client, {}", e)))?;

		let mser: &str = &message_ser;
		let fromstripped = from.get_stripped();

		let mut params = HashMap::new();
		params.insert("mapmessage", mser);
		params.insert("from", &fromstripped);
		params.insert("signature", &signature);

		let url = format!(
			"https://{}:{}/sender?address={}",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			&str::replace(&to.get_stripped(), "@", "%40")
		);
		let response = client.post(&url).form(&params).send();

		if !response.is_ok() {
			return Err(ErrorKind::MqsInvalidRespose("mwcmqs connection error".to_string()).into());
		} else {
			let mut response = response.unwrap();
			let mut resp_str = "".to_string();
			let read_resp = response.read_to_string(&mut resp_str);

			if !read_resp.is_ok() {
				return Err(ErrorKind::MqsInvalidRespose("mwcmqs i/o error".to_string()).into());
			} else {
				let data: Vec<&str> = resp_str.split(" ").collect();
				if data.len() <= 1 {
					return Err(ErrorKind::MqsInvalidRespose("mwcmqs".to_string()).into());
				} else {
					let last_seen = data[1].parse::<i64>();
					if !last_seen.is_ok() {
						return Err(ErrorKind::MqsInvalidRespose("mwcmqs".to_string()).into());
					} else {
						let last_seen = last_seen.unwrap();
						if last_seen > 10000000000 {
							self.do_log_warn(format!("\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the slate.",
													 to.get_stripped()));
						} else if last_seen > 150000 {
							let seconds = last_seen / 1000;
							self.do_log_warn(format!("\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the slate.",
													 to.get_stripped(), seconds));
						}
					}
				}
			}
		}

		Ok(())
	}

	fn post_take(
		&self,
		swapmessage: &Message,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		if !self.is_running() {
			return Err(ErrorKind::ClosedListener("mwcmqs".to_string()).into());
		}
		let pkey = to.address.public_key()?;
		let skey = secret_key.clone();

		let message = EncryptedMessage::new(
			serde_json::to_string(&swapmessage).map_err(|e| {
				ErrorKind::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
			})?,
			&to.address,
			&pkey,
			&skey,
		)
		.map_err(|e| ErrorKind::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable to convert Swap Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key);
		let signature = signature.unwrap().to_hex();

		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(60))
			.build()
			.map_err(|e| {
				ErrorKind::GenericError(format!("Failed to build a client for post_take, {}", e))
			})?;

		let mser: &str = &message_ser;
		let fromstripped = from.get_stripped();

		let mut params = HashMap::new();
		params.insert("swapmessage", mser);
		params.insert("from", &fromstripped);
		params.insert("signature", &signature);

		let url = format!(
			"https://{}:{}/sender?address={}",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			&str::replace(&to.get_stripped(), "@", "%40")
		);
		let response = client.post(&url).form(&params).send();

		if !response.is_ok() {
			return Err(ErrorKind::MqsInvalidRespose(format!(
				"mwcmqs connection error, {:?}",
				response
			))
			.into());
		} else {
			let mut response = response.unwrap();
			let mut resp_str = "".to_string();
			let read_resp = response.read_to_string(&mut resp_str);

			if !read_resp.is_ok() {
				return Err(ErrorKind::MqsInvalidRespose("mwcmqs i/o error".to_string()).into());
			} else {
				let data: Vec<&str> = resp_str.split(" ").collect();
				if data.len() <= 1 {
					return Err(ErrorKind::MqsInvalidRespose("mwcmqs".to_string()).into());
				} else {
					let last_seen = data[1].parse::<i64>();
					if !last_seen.is_ok() {
						return Err(ErrorKind::MqsInvalidRespose("mwcmqs".to_string()).into());
					} else {
						let last_seen = last_seen.unwrap();
						if last_seen > 10000000000 {
							println!("\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the swap message.",
									 to.get_stripped());
						} else if last_seen > 150000 {
							let seconds = last_seen / 1000;
							println!("\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the swap message.",
									 to.get_stripped(), seconds);
						}
					}
				}
			}
		}

		Ok(())
	}

	fn print_error(&mut self, messages: Vec<&str>, error: &str, code: i16) {
		self.do_log_error(format!(
			"ERROR: messages=[{:?}] produced error: {} (code={})",
			messages, error, code
		));
	}
	fn do_log_info(&self, message: String) {
		if self.print_to_log {
			info!("{}", message);
		} else {
			println!("{}", message);
		}
	}

	fn do_log_warn(&self, message: String) {
		if self.print_to_log {
			warn!("{}", message);
		} else {
			println!("{}", message);
		}
	}

	fn do_log_error(&self, message: String) {
		if self.print_to_log {
			error!("{}", message);
		} else {
			println!("{}", message);
		}
	}

	fn subscribe(&mut self, source_address: &ProvableAddress, secret_key: &SecretKey) -> () {
		let address = MWCMQSAddress::new(
			source_address.clone(),
			Some(self.mwcmqs_domain.clone()),
			Some(self.mwcmqs_port),
		);

		let nanoid = nanoid::simple();
		self.running.store(true, Ordering::SeqCst);

		let mut resp_str = "".to_string();
		let secret_key = secret_key.clone();
		let cloned_address = address.clone();
		let cloned_running = self.running.clone();
		let mut count = 0;
		let mut connected = false;
		let mut isnginxerror = false;
		let mut delcount = 0;
		let mut is_in_warning = false;

		// get time from server
		let mut time_now = "";
		let mut is_error = false;
		let secs = 30;
		let cl = reqwest::Client::builder()
			.timeout(Duration::from_secs(secs))
			.build();
		if cl.is_ok() {
			let client = cl.unwrap();
			let resp_result = client
				.get(&format!(
					"https://{}:{}/timenow?address={}",
					self.mwcmqs_domain,
					self.mwcmqs_port,
					str::replace(&cloned_address.get_stripped(), "@", "%40"),
				))
				.send();

			if !resp_result.is_ok() {
				is_error = true;
			} else {
				let mut resp = resp_result.unwrap();
				let read_resp = resp.read_to_string(&mut resp_str);
				if !read_resp.is_ok() {
					is_error = true;
				} else {
					time_now = &resp_str;
				}
			}
		} else {
			is_error = true;
		}

		let mut time_now_signature = String::new();
		if let Ok(time_now_sign) = crypto::sign_challenge(&format!("{}", time_now), &secret_key) {
			let time_now_sign = str::replace(&format!("{:?}", time_now_sign), "Signature(", "");
			let time_now_sign = str::replace(&time_now_sign, ")", "");
			time_now_signature = time_now_sign;
		}

		if time_now_signature.is_empty() {
			is_error = true;
		}

		let mut url = String::from(&format!(
			"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			str::replace(&cloned_address.get_stripped(), "@", "%40"),
			"nil".to_string(),
			time_now,
			time_now_signature
		));

		let first_url = String::from(&format!(
			"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}&first=true",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			str::replace(&cloned_address.get_stripped(), "@", "%40"),
			"nil".to_string(),
			time_now,
			time_now_signature
		));

		if is_error {
			print!(
				"ERROR: Failed to start mwcmqs subscriber. Error connecting to {}:{}",
				self.mwcmqs_domain, self.mwcmqs_port
			);
		} else {
			let mut is_error = false;
			let mut loop_count = 0;
			loop {
				loop_count = loop_count + 1;
				if is_error {
					break;
				}
				let mut resp_str = "".to_string();
				count = count + 1;
				let cloned_cloned_address = cloned_address.clone();

				if !cloned_running.load(Ordering::SeqCst) {
					break;
				}

				let secs = if !connected { 2 } else { 120 };
				let cl = reqwest::Client::builder()
					.timeout(Duration::from_secs(secs))
					.build();
				let client = if cl.is_ok() {
					cl.unwrap()
				} else {
					self.print_error([].to_vec(), "couldn't instantiate client", -101);
					is_error = true;
					continue;
				};

				let mut first_response = true;
				let resp_result = if loop_count == 1 {
					client.get(&*first_url).send()
				} else {
					client.get(&*url).send()
				};

				if !resp_result.is_ok() {
					let err_message = format!("{:?}", resp_result);
					let re = Regex::new(TIMEOUT_ERROR_REGEX).unwrap();
					let captures = re.captures(&err_message);
					if captures.is_none() {
						// This was not a timeout. Sleep first.
						if connected {
							is_in_warning = true;
							self.do_log_warn(format!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
													 cloned_cloned_address.get_stripped(), nanoid ));
						}

						let second = time::Duration::from_millis(5000);
						thread::sleep(second);

						connected = false;
					} else if count == 1 {
						delcount = 0;
						self.do_log_warn(format!(
							"\nmwcmqs listener started for [{}] tid=[{}]",
							cloned_cloned_address.get_stripped(),
							nanoid
						));
						connected = true;
					} else {
						delcount = 0;
						if !connected {
							if is_in_warning {
								self.do_log_info(format!(
									"INFO: mwcmqs listener [{}] reestablished connection. tid=[{}]",
									cloned_cloned_address.get_stripped(),
									nanoid
								));
								is_in_warning = false;
								isnginxerror = false;
							}
						}
						connected = true;
					}
				} else {
					if count == 1 {
						self.do_log_warn(format!(
							"\nmwcmqs listener started for [{}] tid=[{}]",
							cloned_cloned_address.get_stripped(),
							nanoid
						));
					} else if !connected && !isnginxerror {
						if is_in_warning {
							self.do_log_info(format!(
								"INFO: listener [{}] reestablished connection.",
								cloned_cloned_address.get_stripped()
							));
							is_in_warning = false;
							isnginxerror = false;
						}
						connected = true;
					} else if !isnginxerror {
						connected = true;
					}

					let mut resp = resp_result.unwrap();
					let read_resp = resp.read_to_string(&mut resp_str);
					if !read_resp.is_ok() {
						// read error occured. Sleep and try again in 5 seconds
						self.do_log_info(format!("io error occured while trying to connect to {}. Will sleep for 5 second and will reconnect.",
												 &format!("https://{}:{}", self.mwcmqs_domain, self.mwcmqs_port)));
						self.do_log_error(format!("Error: {:?}", read_resp));
						let second = time::Duration::from_millis(5000);
						thread::sleep(second);
						continue;
					}

					let mut break_out = false;

					let msgvec: Vec<&str> = if resp_str.starts_with("messagelist: ") {
						let mut ret: Vec<&str> = Vec::new();
						let lines: Vec<&str> = resp_str.split("\n").collect();
						for i in 1..lines.len() {
							let params: Vec<&str> = lines[i].split(" ").collect();
							if params.len() >= 2 {
								let index = params[1].find(';');
								if index.is_some() {
									// new format
									let index = index.unwrap();
									let mut last_message_id = &params[1][0..index];
									let start = last_message_id.find(' ');
									if start.is_some() {
										last_message_id = &last_message_id[1 + start.unwrap()..];
									}

									url = String::from(format!(
										"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
										self.mwcmqs_domain,
										self.mwcmqs_port,
										str::replace(&cloned_address.get_stripped(), "@", "%40"),
										&last_message_id,
										time_now,
										time_now_signature
									));
									ret.push(&params[1][index + 1..]);
								} else if params[1] == "closenewlogin" {
									if cloned_running.load(Ordering::SeqCst) {
										self.do_log_error(format!(
											"\nERROR: new login detected. mwcmqs listener will stop!"
										));
									}
									break; // stop listener
								} else {
									self.print_error([].to_vec(), "message id expected", -103);
									is_error = true;
									continue;
								}
							}
						}
						ret
					} else {
						let index = resp_str.find(';');
						if index.is_some() {
							// new format
							let index = index.unwrap();

							let mut last_message_id = &resp_str[0..index];
							let start = last_message_id.find(' ');
							if start.is_some() {
								last_message_id = &last_message_id[1 + start.unwrap()..];
							}

							url = String::from(format!(
								"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
								self.mwcmqs_domain,
								self.mwcmqs_port,
								str::replace(&cloned_address.get_stripped(), "@", "%40"),
								&last_message_id,
								time_now,
								time_now_signature
							));

							vec![&resp_str[index + 1..]]
						} else {
							if resp_str.find("nginx").is_some() {
								// this is common for nginx to return if the server is down.
								// so we don't print. We also add a small sleep here.
								connected = false;
								if !isnginxerror {
									is_in_warning = true;
									self.do_log_warn(format!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
															 cloned_cloned_address.get_stripped(),
															 nanoid));
								}
								isnginxerror = true;
								let second = time::Duration::from_millis(5000);
								thread::sleep(second);
								continue;
							} else {
								if resp_str == "message: closenewlogin\n" {
									if cloned_running.load(Ordering::SeqCst) {
										self.do_log_error(format!(
											"\nERROR: new login detected. mwcmqs listener will stop!",
										));
									}
									break; // stop listener
								} else if resp_str == "message: mapmessage=nil" {
									// our connection message
									continue;
								} else {
									self.print_error([].to_vec(), "message id expected", -102);
									is_error = true;
									continue;
								}
							}
						}
					};

					for itt in 0..msgvec.len() {
						if break_out {
							break;
						}
						if msgvec[itt] == "message: closenewlogin\n"
							|| msgvec[itt] == "closenewlogin"
						{
							if cloned_running.load(Ordering::SeqCst) {
								print!("\nERROR: new login detected. mwcmqs listener will stop!",);
							}
							break_out = true;
							break; // stop listener
						} else if msgvec[itt] == "message: mapmessage=nil\n"
							|| msgvec[itt] == "mapmessage=nil"
							|| msgvec[itt] == "mapmessage=nil\n"
						{
							if first_response {
								delcount = 1;
								first_response = false;
							} else {
								delcount = delcount + 1;
							}
							// this is our exit message. Just ignore.
							continue;
						}
						let split = msgvec[itt].split(" ");
						let vec: Vec<&str> = split.collect();
						let splitx = if vec.len() == 1 {
							vec[0].split("&")
						} else if vec.len() >= 2 {
							vec[1].split("&")
						} else {
							self.print_error(msgvec.clone(), "too many spaced messages", -1);
							is_error = true;
							continue;
						};

						let splitxvec: Vec<&str> = splitx.collect();
						let splitxveclen = splitxvec.len();
						if splitxveclen != 3 {
							if msgvec[itt].find("nginx").is_some() {
								// this is common for nginx to return if the server is down.
								// so we don't print. We also add a small sleep here.
								connected = false;
								if !isnginxerror {
									is_in_warning = true;
									self.do_log_warn(format!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
															 cloned_cloned_address.get_stripped(),
															 nanoid));
								}
								isnginxerror = true;
								let second = time::Duration::from_millis(5000);
								thread::sleep(second);
							} else {
								self.print_error(msgvec.clone(), "splitxveclen != 3", -2);
								is_error = true;
							}
							continue;
						} else if isnginxerror {
							isnginxerror = false;
							connected = true;
						}

						let mut from = "".to_string();
						for i in 0..3 {
							if splitxvec[i].starts_with("from=") {
								let vec: Vec<&str> = splitxvec[i].split("=").collect();
								if vec.len() <= 1 {
									self.print_error(msgvec.clone(), "vec.len <= 1", -3);
									is_error = true;
									continue;
								}
								from = str::replace(
									&vec[1].to_string().trim().to_string(),
									"%40",
									"@",
								);
							}
						}
						let mut signature = "".to_string();
						for i in 0..3 {
							if splitxvec[i].starts_with("signature=") {
								let vec: Vec<&str> = splitxvec[i].split("=").collect();
								if vec.len() <= 1 {
									self.print_error(msgvec.clone(), "vec.len <= 1", -4);
									is_error = true;
									continue;
								}
								signature = vec[1].to_string().trim().to_string();
							}
						}

						for i in 0..3 {
							if splitxvec[i].starts_with("mapmessage=")
								|| splitxvec[i].starts_with("swapmessage=")
							{
								let slate_or_swap = if splitxvec[i].starts_with("mapmessage") {
									"slate"
								} else {
									"swap"
								};

								let split2 = splitxvec[i].split("=");
								let vec2: Vec<&str> = split2.collect();
								if vec2.len() <= 1 {
									self.print_error(msgvec.clone(), "vec2.len <= 1", -5);
									is_error = true;
									continue;
								}
								let r1 = str::replace(vec2[1], "%22", "\"");
								let r2 = str::replace(&r1, "%7B", "{");
								let r3 = str::replace(&r2, "%7D", "}");
								let r4 = str::replace(&r3, "%3A", ":");
								let r5 = str::replace(&r4, "%2C", ",");
								let r5 = r5.trim().to_string();

								if first_response {
									delcount = 1;
									first_response = false;
								} else {
									delcount = delcount + 1;
								}

								let from = MWCMQSAddress::from_str(&from);
								let from = if !from.is_ok() {
									self.print_error(msgvec.clone(), "error parsing from", -12);
									is_error = true;
									continue;
								} else {
									from.unwrap()
								};

								if slate_or_swap == "slate" {
									let (mut slate, tx_proof) = match TxProof::from_response(
										&from.address,
										r5.clone(),
										"".to_string(),
										signature.clone(),
										&secret_key,
										&source_address,
									) {
										Ok(x) => x,
										Err(err) => {
											self.do_log_error(format!("{}", err));
											continue;
										}
									};
									push_proof_for_slate(&slate.id, tx_proof);
									self.handler.lock().on_slate(&from, &mut slate);
								} else if slate_or_swap == "swap" {
									let swap_message = match SwapMessage::from_received(
										&from.address,
										r5.clone(),
										"".to_string(),
										signature.clone(),
										&secret_key,
									) {
										Ok(x) => x,
										Err(err) => {
											self.do_log_error(format!("{}", err));
											continue;
										}
									};
									let ack_message =
										self.handler.lock().on_swap_message(swap_message);
									if let Some(ack_message) = ack_message {
										let mqs_cannel = MwcMqsChannel::new(from.to_string());
										if let Err(e) = mqs_cannel.send_swap_message(&ack_message) {
											self.do_log_error(format!(
												"Unable to send back ack message, {}",
												e
											));
										}
									}
								}

								break;
							}
						}
					}

					if break_out {
						break;
					}
				}
			}
		}

		if !is_error {
			self.do_log_info(format!(
				"\nmwcmqs listener [{}] stopped. tid=[{}]",
				address.get_stripped(),
				nanoid
			));
		}

		cloned_running.store(false, Ordering::SeqCst);
	}

	fn stop(&self) {
		self.running.store(false, Ordering::SeqCst);
	}

	fn is_running(&self) -> bool {
		self.running.load(Ordering::SeqCst)
	}
}
