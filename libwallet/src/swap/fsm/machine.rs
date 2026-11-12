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
use mwc_wallet_util::mwc_crates::log::debug;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use std::collections::{HashMap, HashSet};

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
			// These assertions validate the state graph assembled immediately above from
			// locally defined state objects. No serialized swap or other external input
			// can add a state or transition to this map.
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
		Ok(state.is_cancellable(swap))
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
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		self.process_with_persist(input, swap, context, tx_conf, secp, &|_| Ok(()))
	}

	/// Run a step with durable storage before an MWC lock or buyer redemption is sent.
	pub(crate) fn process_with_persist(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
		persist: &dyn Fn(&Swap) -> Result<(), Error>,
	) -> Result<StateProcessRespond, Error> {
		debug!(
			"Swap {} processing state {:?} for Input {:?}",
			swap.id, swap.state, input
		);
		if !tx_conf.supports_state(swap) {
			return Err(Error::SwapStateMachineError(
				"Missing chain observations required for this swap state".into(),
			));
		}

		// A caller may submit Cancel directly without first querying eligibility.
		// Chain observations also count as exposure even if a local broadcast
		// timestamp has not yet been recorded.
		if matches!(input, Input::Cancel)
			&& (!self.is_cancellable(swap)?
				|| (!swap.is_seller() && tx_conf.mwc_redeem_conf.is_some()))
		{
			return Err(Error::InvalidSwapStateInput(
				"Swap trade is not cancellable at the current stage".to_string(),
			));
		}

		// Each Check uses the same confirmation snapshot. Revisiting a state can
		// otherwise loop indefinitely when a fresh node lookup disagrees after a
		// reorg. Other inputs may mutate the trade before its first Check, so do
		// not count those as a visit to the state's Check branch.
		let mut checked_states = HashSet::new();
		if matches!(input, Input::Check) {
			checked_states.insert(swap.state.clone());
		}

		let state = self
			.state_map
			.get_mut(&swap.state)
			.ok_or(Error::SwapStateMachineError(format!(
				"Unknown state {:?}",
				swap.state
			)))?;
		let mut respond =
			state.process_with_persist(input, swap, context, tx_conf, secp, persist)?;

		while respond.next_state_id != swap.state {
			if !checked_states.insert(respond.next_state_id.clone()) {
				return Err(Error::SwapStateMachineError(format!(
					"State transition cycle at {:?}; retry with fresh transaction confirmations",
					respond.next_state_id
				)));
			}
			debug!("New state: {:?}", respond.next_state_id);
			swap.state = respond.next_state_id.clone();
			if !tx_conf.supports_state(swap) {
				// Recovery can leave the branch supported by this snapshot. Save
				// that transition, then obtain the missing chain before processing it.
				respond.action = None;
				respond.time_limit = None;
				break;
			}
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
