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

use crate::swap::fsm::state::{Input, State, StateEtaInfo, StateId, StateProcessRespond};
use crate::swap::types::SwapTransactionsConfirmations;
use crate::swap::{Context, Error, Swap};
use mwc_wallet_util::mwc_util::secp::Secp256k1;
use std::collections::HashMap;

/// Swap State machine
pub struct StateMachine<'a> {
	/// Available States
	state_map: HashMap<StateId, Box<dyn State + 'a>>,
}

impl<'a> StateMachine<'a> {
	/// Create
	pub fn new(states: Vec<Box<dyn State + 'a>>) -> Self {
		let mut state_map: HashMap<StateId, Box<dyn State>> = HashMap::new();
		for st in states {
			let _ = state_map.insert(st.get_state_id(), st);
		}

		#[cfg(debug_assertions)]
		for st in state_map.values() {
			assert!(state_map.contains_key(&st.get_state_id()));
			if let Some(state) = st.get_prev_swap_state() {
				assert!(state_map.contains_key(&state));
			}
			if let Some(state) = st.get_next_swap_state() {
				assert!(state_map.contains_key(&state));
			}
		}

		StateMachine { state_map }
	}

	/// Check if this trade can be cancelled.
	pub fn is_cancellable(&self, swap: &Swap) -> Result<bool, Error> {
		let state = self
			.state_map
			.get(&swap.state)
			.ok_or(Error::SwapStateMachineError(format!(
				"Unknown state {:?}",
				swap.state
			)))?;
		Ok(state.is_cancellable())
	}

	/// Verify if the state is valid for this machine
	pub fn has_state(&self, state: &StateId) -> bool {
		self.state_map.contains_key(state)
	}

	/// Process the step
	pub fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		debug!(
			"Swap {} processing state {:?} for Input {:?}",
			swap.id, swap.state, input
		);

		let state = self
			.state_map
			.get_mut(&swap.state)
			.ok_or(Error::SwapStateMachineError(format!(
				"Unknown state {:?}",
				swap.state
			)))?;
		let mut respond = state.process(input, swap, context, tx_conf, secp)?;

		while respond.next_state_id != swap.state {
			debug!("New state: {:?}", swap.state);
			swap.state = respond.next_state_id.clone();
			let state = self
				.state_map
				.get_mut(&swap.state)
				.ok_or(Error::SwapStateMachineError(format!(
					"Unknown state {:?}",
					swap.state
				)))?;
			respond = state.process(Input::Check, swap, context, tx_conf, secp)?;
		}
		respond.journal = swap.journal.clone();

		debug!("Responding with {:?}", respond);
		Ok(respond)
	}

	/// Build a roadmap for the swap process
	pub fn get_swap_roadmap(
		&self,
		swap: &Swap,
		secp: &Secp256k1,
	) -> Result<Vec<StateEtaInfo>, Error> {
		let state = self
			.state_map
			.get(&swap.state)
			.ok_or(Error::SwapStateMachineError(format!(
				"Unknown state {:?}",
				swap.state
			)))?;

		let mut result: Vec<StateEtaInfo> = Vec::new();

		// go backward first
		let mut prev_state_id = state.get_prev_swap_state();
		while let Some(psid) = prev_state_id {
			let prev_state = self
				.state_map
				.get(&psid)
				.ok_or(Error::SwapStateMachineError(format!(
					"Unknown state {:?}",
					psid
				)))?;
			if let Some(info) = prev_state.get_eta(swap, secp) {
				result.insert(0, info);
			}
			prev_state_id = prev_state.get_prev_swap_state();
		}
		// current state
		if let Some(info) = state.get_eta(swap, secp) {
			result.push(info.active());
		}
		// going forward
		let mut next_state_id = state.get_next_swap_state();
		while let Some(nsid) = next_state_id {
			let next_state = self
				.state_map
				.get(&nsid)
				.ok_or(Error::SwapStateMachineError(format!(
					"Unknown state {:?}",
					nsid
				)))?;
			if let Some(info) = next_state.get_eta(swap, secp) {
				result.push(info);
			}
			next_state_id = next_state.get_next_swap_state();
		}

		Ok(result)
	}
}
