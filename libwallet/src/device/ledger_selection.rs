
use crate::device::adpu::APDUCommands;
use crate::device::ledger::{self, get_bulletproof_components, get_commitment, parse_bp, parse_response};
use crate::error::Error;
use crate::grin_core::libtx::proof::ProofBuild;
use crate::grin_keychain::{Identifier, Keychain};
use crate::proof::message;
use secp256k1zkp::{ContextFlag, PublicKey, Secp256k1};
use util::secp::pedersen::{Commitment, RangeProof};
use grin_wallet_util::grin_core::core::{Output, OutputFeatures, Transaction};
use grin_wallet_util::grin_keychain::{BlindSum, SwitchCommitmentType};
use grin_wallet_util::grin_util as util;

use super::ledger::{get_rewind_nonce, proof_message, rewind_hash};

pub struct Context<'a, K, B>
where
	K: Keychain,
	B: ProofBuild,
{
	/// The keychain used for key derivation
	pub keychain: &'a K,
	/// The bulletproof builder
	pub builder: &'a B,
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum) tuple into another, given the provided context.
/// Will return an Err if seomthing went wrong at any point during transaction building.
pub type Append<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	Result<(Transaction, BlindSum), Error>,
) -> Result<(Transaction, BlindSum), Error>;


pub fn output<K, B>(value: u64, rpk: Vec<u8>,key_id: Identifier) -> Box<Append<K, B>>
where
    K: Keychain,
    B: ProofBuild,
{
    Box::new(
        move |build, acc| -> Result<(Transaction, BlindSum), Error> {
            let (tx, sum) = acc?;
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			
            // Initialize HID API and create transport
            let api = ledger::initialize_hid_api().unwrap();
            let transport = ledger::create_transport(&api).unwrap();

            // Set switch commitment type
            let switch = SwitchCommitmentType::Regular;
            let commit = get_commitment(&transport, key_id, value, switch).unwrap();
            let (tau_x, t_one, t_two) = get_bulletproof_components(&secp, &transport, key_id, value, switch).unwrap();
			let rewind_hash = rewind_hash(&secp, PublicKey::from_slice(&secp, &rpk).unwrap());
			let rewind_nonce = get_rewind_nonce(&secp, commit, rewind_hash).unwrap();
			let message = proof_message(&secp, key_id, switch).unwrap();
			let proof = secp.bullet_proof_multisig(
				value, 
				None,
				rewind_nonce, 
				None,
				Some(message),
				Some(&mut tau_x), 
				Some(&mut t_one), 
				Some(&mut t_two),
				vec![commit], 
				None, 
				0
			).unwrap();
			let _verify = secp.verify_bullet_proof(commit, proof, None).unwrap();
            Ok((
                tx.with_output(Output::new(OutputFeatures::Plain, commit, proof)),
                sum.add_key_id(key_id.to_value_path(value)),
            ))
        }
    )
}

/*Creates a new output in the wallet for the recipient,
returning the key of the fresh output
Also creates a new transaction containing the output
Note: key_id & output_amounts needed for secure claims.
*/

/*

pub fn hardware_build_recipient_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	address: Option<String>,
	parent_key_id: Identifier,
	participant_id: usize,
	key_id_opt: Option<&str>,
	use_test_rng: bool,
	is_initiator: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
	message: Option<String>,
) -> Result<(Identifier, Context, TxLogEntry), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Keeping keys with amounts because context want that ( <id>, <amount> )

	// building transaction, apply provided key.
	let amount = slate.amount;
    let output_amount: u64 = amount;
	assert!(num_outputs > 0);
	let key_id = if key_id_opt.is_some() {
		// Note! No need to handle so far, that is why we have one key_id_opt, so num_outputs can be only 1
		// If it is not true - likely use case was changed.
		assert!(num_outputs == 1);
		let key_str = key_id_opt.unwrap();
		Identifier::from_hex(key_str)?
	} else {
		keys::next_available_key(wallet, keychain_mask)?
	};
	
	let key_amounts = (key_id.clone(), output_amount);

	// Note, it is not very critical, has to match for all normal case,
	// might fail for edge case if we send very smaller coins amount
	//debug_assert!(key_vec_amounts.len() == num_outputs);

	if slate.amount == 0 || num_outputs == 0 {
		return Err(ErrorKind::GenericError(format!(
			"Unable to build transaction for amount {} and outputs number {}",
			slate.amount, num_outputs
		))
		.into());
	}

	let keychain = wallet.keychain(keychain_mask)?;
	let amount = slate.amount;
	let height = current_height;

	let slate_id = slate.id.clone();

	let mut out_vec = output(key_amounts.1, key_amounts.0.clone());
	
    
    
    let blinding =
		slate.add_transaction_elements(&keychain, &ProofBuilder::new(&keychain), out_vec)?;

	// Add blinding sum to our context
	let mut context = if slate.compact_slate {
		Context::new(
			keychain.secp(),
			&parent_key_id,
			use_test_rng,
			is_initiator,
			participant_id,
			amount,
			slate.fee,
			message,
		)
	} else {
		// Legacy model
		Context::with_excess(
			keychain.secp(),
			blinding.secret_key()?,
			&parent_key_id,
			use_test_rng,
			participant_id,
			amount,
			slate.fee,
			message,
		)
	};

	for kva in &key_vec_amounts {
		context.add_output(&kva.0, &None, kva.1);
	}

	let messages = Some(slate.participant_messages());

	let mut commit_vec = Vec::new();
	let mut commit_ped = Vec::new();
	for kva in &key_vec_amounts {
		let commit = wallet.calc_commit_for_cache(keychain_mask, kva.1, &kva.0)?;
		if let Some(cm) = commit.clone() {
			commit_ped.push(Commitment::from_vec(util::from_hex(&cm).map_err(|e| {
				ErrorKind::GenericError(format!("Output commit parse error, {}", e))
			})?));
		}
		commit_vec.push(commit);
	}

	let mut batch = wallet.batch(keychain_mask)?;
	let log_id = batch.next_tx_log_id(&parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);
	t.tx_slate_id = Some(slate_id);
	t.amount_credited = amount;
	t.address = address;
	t.num_outputs = key_vec_amounts.len();
	t.output_commits = commit_ped;
	t.messages = messages;
	t.ttl_cutoff_height = slate.ttl_cutoff_height;
	//add the offset to the database tx record.
	let offset_skey = slate.tx.offset.secret_key()?;
	let offset_commit = keychain.secp().commit(0, offset_skey)?;
	t.kernel_offset = Some(offset_commit);

	if t.ttl_cutoff_height == Some(0) {
		t.ttl_cutoff_height = None;
	}

	// when invoicing, this will be invalid
	if let Ok(e) = slate.calc_excess(Some(&keychain)) {
		t.kernel_excess = Some(e)
	}
	t.kernel_lookup_min_height = Some(current_height);
	batch.save_tx_log_entry(t.clone(), &parent_key_id)?;

	let mut i = 0;
	for kva in &key_vec_amounts {
		batch.save(OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: kva.0.clone(),
			mmr_index: None,
			n_child: kva.0.to_path().last_path_index(),
			commit: commit_vec[i].clone(),
			value: kva.1,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(log_id),
		})?;
		i = i + 1;
	}
	batch.commit()?;

	// returning last key that was used in the chain.
	// That suppose to satisfy all caller needs
	Ok((key_vec_amounts.last().unwrap().0.clone(), context, t))
}

*/