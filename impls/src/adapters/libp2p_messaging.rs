// Copyright 2021 The MWC Developers
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

use crate::grin_p2p::libp2p_connection;
use crate::util::RwLock;
use crate::{Error, ErrorKind};
use chrono::Utc;
use grin_wallet_libwallet::IntegrityContext;
use grin_wallet_util::grin_util::secp::Secp256k1;
use libp2p::gossipsub::IdentTopic as Topic;
use std::thread;
use uuid::Uuid;

/// Publishing message
#[derive(Clone, Debug)]
pub struct PublishingMessage {
	/// This message uuid
	pub uuid: Uuid,
	/// Topic to broadcast
	pub topic: Topic,
	/// message to broadcast. Must be json string
	pub message: String,
	/// Broadcasting time period (sec)
	pub broadcasting_interval: u32,
	/// Last published time stamp
	pub last_time_published: i64,
	/// Integrity context to sign the message
	pub integrity_ctx: IntegrityContext,
	/// Last time when IntegrityContext expiration time was checked. Expected to be checked at least once per hour
	pub integrity_ctx_expiration_check: i64,
}
// required to check at least once in an hour. Without checking will not send it
const INTEGRITY_CTX_CHECK_INTERVAL: i64 = 3600;

lazy_static! {
	/// Messages that are broadcasting
	static ref MESSAGING_BROADCASTING: RwLock<Vec<PublishingMessage>> = RwLock::new(Vec::new());

	/// Flag if broadcasting tread is already running
	static ref BROADCASTING_RUNNUNG: RwLock<bool> = RwLock::new(false);
}

/// Get messages that are broadcast
pub fn get_broadcasting_messages() -> Vec<PublishingMessage> {
	MESSAGING_BROADCASTING.read().clone()
}

/// Remove broadcasting message
pub fn remove_broadcasting_message(uuid: &Uuid) -> bool {
	let mut broadcasting = MESSAGING_BROADCASTING.write();
	let len0 = broadcasting.len();
	broadcasting.retain(|msg| msg.uuid != *uuid);
	broadcasting.len() != len0
}

/// Start broadcasting for the message
pub fn add_broadcasting_messages(
	topic: &String,
	message: &String,
	interval: u32,
	integrity_ctx: IntegrityContext,
) -> Result<Uuid, Error> {
	let mut broadcasting = MESSAGING_BROADCASTING.write();
	// Delete first if it is already in the list
	broadcasting.retain(|m| m.message != *message);

	// Check if integrity_ctx is not duplicated
	if broadcasting
		.iter()
		.filter(|m| m.integrity_ctx.sec_key == integrity_ctx.sec_key)
		.next()
		.is_some()
	{
		return Err(ErrorKind::ArgumentError(format!(
			"Message with integrity_ctx {} is already exist",
			integrity_ctx.tx_uuid
		))
		.into());
	}

	// we are good to add a new message
	let uuid = Uuid::new_v4();
	broadcasting.push(PublishingMessage {
		uuid: uuid.clone(),
		topic: Topic::new(topic),
		message: message.clone(),
		broadcasting_interval: interval,
		last_time_published: 0,
		integrity_ctx,
		integrity_ctx_expiration_check: Utc::now().timestamp() + INTEGRITY_CTX_CHECK_INTERVAL,
	});

	// Start the thread is needed
	{
		let mut running = BROADCASTING_RUNNUNG.write();
		if *running == false {
			let _thread = thread::Builder::new()
				.name("broadcasting_messages".to_string())
				.spawn(|| {
					let secp = Secp256k1::new();
					loop {
						thread::sleep(core::time::Duration::from_secs(1));
						let cur_time = Utc::now().timestamp();
						{
							let mut messages = MESSAGING_BROADCASTING.write();
							if messages.is_empty() {
								break; // No messages - let's not keep the thread
							}
							// Processing 1 message at a time. Most of the time it is expected that nothing will be found
							if let Some(msg) = messages
								.iter_mut()
								.filter(|m| {
									(m.last_time_published + (m.broadcasting_interval as i64)
										< cur_time) && (m.integrity_ctx_expiration_check > cur_time)
								})
								.next()
							{
								// Broadcasting the message
								if let Some(peer_id) = libp2p_connection::get_this_peer_id() {
									let tor_pk = peer_id.as_dalek_pubkey().unwrap(); // It has to be Dalek PK, we don't use any other types
									match msg.integrity_ctx.calc_kernel_excess(&secp, &tor_pk) {
										Ok((excess, signature)) => {
											match libp2p_connection::build_integrity_message(
												&excess,
												&tor_pk,
												&signature,
												msg.message.as_bytes(),
												&secp,
											) {
												Ok(enc_data) => {
													if libp2p_connection::publish_message(
														&msg.topic, enc_data,
													)
													.is_none()
													{
														error!(
															"gossipsub message {} wasn't published",
															msg.message
														);
													}
												}
												Err(e) => error!(
													"Unable to build integrity message, {}",
													e
												),
											};
										}
										Err(e) => error!("Unable to sign integrity kernel, {}", e),
									}
								}
								msg.last_time_published = cur_time;
							}
						}
					}

					// not running any more....
					*BROADCASTING_RUNNUNG.write() = false;
				})
				.map_err(|e| {
					ErrorKind::GenericError(format!(
						"Unable to start broadcasting_messages thread, {}",
						e
					))
				})?;

			*running = true;
		}
	}
	Ok(uuid)
}

/// Check if integrity Context is expired. Function return the list of the messages that contexts need to be updated
pub fn check_integrity_context_expiration(tip_height: u64, delete: bool) -> Vec<PublishingMessage> {
	let expired_msgs = {
		let mut broadcasting = MESSAGING_BROADCASTING.write();
		let mut expired_msgs: Vec<PublishingMessage> = Vec::new();
		let cur_time = Utc::now().timestamp();
		for msg in &mut *broadcasting {
			if msg.integrity_ctx.expiration_height < tip_height {
				expired_msgs.push(msg.clone());
			} else {
				msg.integrity_ctx_expiration_check = cur_time + INTEGRITY_CTX_CHECK_INTERVAL;
			}
		}
		expired_msgs
	};

	if delete {
		let mut broadcasting = MESSAGING_BROADCASTING.write();
		broadcasting.retain(|msg| msg.integrity_ctx.expiration_height >= tip_height);
	}

	expired_msgs
}
