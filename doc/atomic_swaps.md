# Contents : #
  * [Overview](./atomic_swaps.md/#Overview)
  * [Marketplace winner selection](#marketplace-winner-selection)
  * [Ethereum transaction safety assumptions](./atomic_swaps.md/#Ethereum-transaction-safety-assumptions)
  * [Configuration](./atomic_swaps.md/#Configuration )
  * [Workflow / Guide](./atomic_swaps.md/#Atomic-swap-workflow)
  * [Cancellation](./atomic_swaps.md/#Cancellation)
  * [Discontinuing Auto-Swap](./atomic_swaps.md/#Discontinuing-Auto-Swap)
  * [Secondary Currency List](./atomic_swaps.md/#Secondary-Currency-List)
  
# Overview #

As of mwc-wallet 3.2.2, atomic swaps are supported by the mwc-wallet. This feature will allow users to exchange MWC coins for 
any Secondary currency from the supported currency list. The swap trade workflow is controlled by the wallet and is driven 
step by step: either with the individual `swap` commands (manual mode), or with `swap --autoswap --json_format`, which 
executes a single step of a trade per invocation and prints the trade status as a JSON line.

This document explains how Atomic Swaps are done. 

# Marketplace winner selection #

The wallet selects one local peer per marketplace offer while competing
candidates wait. New selections have a ten-minute lease; expiry permits chain
checks before replacement. A visible lock preserves the winner, and a lookup
error defers replacement. Acknowledged legacy trades retain a longer hold to
avoid prematurely selecting another peer.

Before saving a replacement, the wallet checks the current winner again so
overlapping requests cannot select two peers. If the replaced trade has a
recorded ETH or ERC20 deposit, it keeps monitoring that deposit and follows the
refund workflow. Refund trades release their marketplace reservation while
retaining the transaction information needed for recovery.

Compatibility details and the limits of local cancellation are documented beside
`probe_or_claim_marketplace_lease` in
[owner_swap.rs](../libwallet/src/swap/owner_swap.rs).

# Restoring swap backups #

Import keeps a seller trade on the refund path when its record shows a submitted
MWC lock but the lock is not confirmed. If the lock confirms later, the wallet
can recover the funds once the refund becomes available. A backup that discards
the seller's recorded lock submission is rejected when importing over a live or
archived trade.

After a seller processes InitRedeem, import rejects backups that discard or
replace its adaptor signature, redeem public key or participant signing data.
This protection also applies to file-based exchanges and legacy records without
incoming-message receipts, before the buyer's MWC redemption is observed.

Once a seller has observed the buyer's MWC redeem transaction, import rejects
backups that discard or replace it. That evidence allows the seller to derive
the secondary redemption secret even if a reorg hides the transaction.

Import keeps an exposed buyer MWC redemption on its recovery path, even when the
transaction or secondary deposit is no longer visible. Legacy backups whose
state records a published or completed redemption retain the same protection.
Expired ETH/ERC20 deposits and deposits still awaiting confirmation remain on
the refund path. Import does not prepare a new BTC refund plan.

When a live trade already exists, import rejects backups that lose its redeem
exposure, replace its exposed signed MWC transaction, or discard or change its
saved BTC refund recovery. BTC recovery includes the complete batch inventory,
signed replacement attempts and intermediate outputs used by later batches.
Rejected backups leave the live record unchanged; retain that record or use a
backup with matching recovery data.

When restoring a deleted trade, import intentionally does not cross-check either
archive directory, leaving trade and archive management under user control. This
applies to both BTC and Ethereum trades. An older backup may omit later transaction
recovery data, including pending Ethereum approvals and their nonce and allowance
reservations; this is an accepted tradeoff. Import still validates against an
existing active record. A successfully imported record supersedes its archives.

# Ethereum transaction safety assumptions #

ETH and ERC20 locks must match the agreed trade terms in both current contract
state and the node's finalized state before the seller authorizes redemption or
the buyer first publishes its MWC redemption. The wallet pins the finalized
contract query to the block hash returned by the node. One mined block is no
longer sufficient for lock acceptance.

Successful ETH/ERC20 redeems and refunds also remain in the confirmation workflow
until their receipt's block is canonical and finalized. This applies even when
recovery skips lock-finality checks. If a receipt disappears before finality, the
wallet retains its transaction recovery and can retry; a finality lookup failure
does not mark the trade complete.

New ETH/ERC20 offers reserve at least 15 minutes for finality in their existing
timing field (75 twelve-second slots, plus the existing 10% scheduling margin).
Elapsed time never substitutes for the finalized-state check. Stored trades keep
their negotiated deadlines; delayed finality can cause a trade to expire and
follow its refund workflow.

Unfinalized deposits remain visible to balance checks and cancellation/refund
recovery. Recovery after MWC redemption has already been exposed also continues
without waiting for lock finality again. New trades and new deposits require an
endpoint with finality support; existing recovery remains available. The current
client enables this policy on Ethereum mainnet and rejects legacy Ropsten for new
trades.

Ethereum and ERC20 swap transactions are submitted under the following explicit
operating assumptions. These are accepted product risks, not guarantees provided
by the protocol:

* A single wallet process is the only process submitting transactions from a
  given Ethereum account. Contract calls and ordinary transfers are serialized
  inside that process and use the pending account nonce. Running two wallet
  processes against the same account can still create a nonce race.
* The wallet process is expected to remain alive, and durable swap storage is
  expected to succeed, between node acceptance of a transaction and persistence
  of its hash. The wallet records both successful and ambiguous submission hashes
  and reconciles them before retrying. Approvals, resets, deposits, redeems, and refunds retain their
  signed bytes, account nonce, and replacement hashes in the encrypted trade record. This
  record is saved after submission returns, not before contacting the node.
* Consequently, a process crash, forced termination, or storage failure in that
  narrow post-broadcast/pre-persistence interval can lose the transaction hash.
  A later retry can then replace or duplicate the original transaction. This
  residual crash-recovery risk is knowingly tolerated by the implementation.

After abnormal termination during an Ethereum-family submission, an operator
should inspect the account's pending and confirmed transaction history before
manually retrying the swap. Trade import itself is read-only with respect to the
Ethereum network: it restores recorded hashes but does not broadcast redeem or
refund calls.

Unmined ERC20 approvals/resets and Ethereum deposits, redeems, and refunds are retried with the same account nonce.
After the retry interval, the wallet rebroadcasts the signed bytes or raises the gas price while
preserving the contract call. A changed gas budget permits an immediate retry;
all replacements must fit that budget. Both original and replacement hashes are
checked for receipts. RPC errors retain recovery data, and another trade cannot
allocate a reserved nonce. Other account submissions wait while an approval, reset, deposit, redeem, or refund
is missing from the node's pending sequence, avoiding gaps and conflicting queued
transactions. Reservations are restored before swap execution and ordinary
Ethereum transfers. A mined revert permits a new transaction at a fresh
nonce. An older record containing only a hash requires reconciliation if that
hash has no receipt; the wallet cannot safely guess its nonce.

Cancelling a trade or reaching its funding deadline keeps a recorded ETH or
ERC20 deposit in the refund workflow, even while the contract balance is zero.
The wallet continues checking the deposit after a restart and offers a refund
once the funds arrive and the refund deadline permits it. It does not submit a
new deposit after cancellation. A reverted deposit ends this wait only when its
failure is finalized; a missing receipt or a failed lookup does not establish
that no funds can arrive.

Direct ETH and ERC20 transfers also reserve their nonce and retain signed recovery
before broadcasting, including when submission returns an ambiguous error. All
account operations respect these reservations. If the node drops a transfer from
its pending sequence, a new payment waits rather than reusing that nonce or
creating a gap. The Rust owner API `eth_retry_transfer` retries an original or
replacement hash at the same nonce, preserving the destination and amount. Its
optional gas budget is in gwei; omitting it retains the recorded budget. Retries
use the existing retry interval and fee-bump rules, and report a mined revert
separately from success. Recovery records survive mined-but-unfinalized receipts
and are retired as finalized account nonces advance during subsequent submissions.
For a seller's private-wallet redirect, swap status checks copy the original and
replacement hashes into the trade record and check each for a receipt. Finalized
recovery remains available until those hashes have been saved. Saved hashes survive
a restart and stale-backup import; the original redirect marker still prevents
another full-value payment.
Signed direct-transfer recovery records are process-local: a new client in the same process
can retry them, but a wallet restart loses them. After restarting, reconcile the
account's transaction history before sending again; retrying an unknown hash
returns a missing-recovery error without allocating a new nonce.

ERC20 funding reserves the account/token/spender allowance for one trade through
its deposit. The wallet reuses sufficient allowance, or confirms an approval of
zero before replacing an insufficient nonzero allowance (required by USDT).
Resetting adds one Ethereum transaction; each reset, approval, and deposit uses
the configured per-transaction gas budget. Other trades using that allowance
wait until the deposit settles or the owner cancels. Cancellation does not discard
an unresolved transaction: its receipt must be reconciled before releasing the
reservation. Funding progress is stored in the encrypted swap record, including
ambiguous submission hashes. Before another ERC20 funding step, the wallet
restores reservations from active and archived cancelled records. This preserves
the submission/persistence assumptions above and does not introduce automatic
revocation transactions on cancellation or import.

Use `swap --swap_id <id> --adjust retry_erc20_approval` to reconcile or retry only
an outstanding ERC20 approval/reset, including for a cancelled or deleted trade.
The action preserves the original nonce, spender, and amount, and can use a new
`--secondary_fee` gas budget for a fee replacement. It never advances to a new
approval or deposit. Recovering a deleted trade saves an active record with its
final state intact; that record supersedes the archived copy. Submission errors
still save the recovery record. Older records containing only a transaction hash
report missing recovery when no receipt is available; their nonce is not guessed.

Mined resets and approvals retain their signed recovery records until their
receipt blocks are canonical and finalized. Networks without finality support
retain that history. If a reorganization removes an earlier approval or reset,
funding retries it at its original nonce before retrying a later deposit.
`retry_erc20_approval` also repairs this history after funding advances or the
trade is cancelled. It processes the earliest missing nonce first.

Use `swap --swap_id <id> --adjust retry_erc20_deposit` to retry an existing
deposit for an active trade. Its original deadline and calldata are preserved,
including after that deadline expires; no new deposit is constructed.
If the deposit has mined with a failure receipt, the command reports the failure
and resets funding so the normal swap workflow can make a fresh attempt. Earlier
approval history remains available for reorganization recovery.
For a cancelled or expired trade, use `--adjust cancel_erc20_deposit` to submit
a zero-value self-transfer at the deposit's nonce. This action is available
during funding, while waiting for lock confirmations or refund time, and for
cancelled or deleted trades. It does not interrupt redemption or a submitted
refund. Both actions accept a new `--secondary_fee` budget and save recovery
data even when submission fails. Signing a cancellation stops automated funding
for that trade while its outcome is unresolved.

Repeat `cancel_erc20_deposit` to reconcile the outcome or retry the cancellation.
The original deposit can still win the race: if it mines and the contract holds
the buyer's tokens, the trade enters the refund workflow. If cancellation wins,
the trade remains cancelled and the allowance reservation is released. The
original and cancellation records remain separate and are rechecked after a
restart or reorganization; a successful cancellation is never treated as funding.

A completed ERC20 deposit records the last observed receipt, not permanent
finality. Funding calls and other trades sharing its allowance recheck that
receipt, including after restart. If a reorganization removes it, the wallet
retains the reservation and retries the recorded deposit at the same nonce.
A mined revert clears the deposit recovery and permits a fresh funding attempt.

# Configuration #

The configuration includes some parameters in the mwc-wallet.toml.  Every secondary supported currency will require 
it's own node to monitor the blockchain and process transactions with a secondary currency. Default values point to the 
community node, you can install your own to get more security. 

```

# ElectrumX Node URI needed for atomic swap. For every coin expected 4 instances:
# mainnet primary, mainnet secondary, testnet primary, testnet secondary,
# Key: <coin>_[main|test]_[1|2]
# value: URI  
swap_electrumx_addr = [ ("btc_test_1", "52.23.248.83:8000"), 
                    ("btc_test_2", "52.23.248.83:8000") ]

```

# Atomic swap workflow #

First, the Seller (the person who is selling MWC coins) and the Buyer (the person who is buying  MWC coins) need to contact each other to define the
exchange rate and amounts of coins to exchange. They will also need to exchange wallet addresses (atomic swaps can use mwcmqs or tor for 
communications). 

The Atomic swap is started by the Seller (the person who want to sell MWC coins and buy some other type of coin). The seller should specify 
the swap trade parameters and Buyer destination address. The seller can use the `swap_start` command to create a swap trade.
Please note, this command will not start the atomic swap trade.

This example creates an atomic swap trade where 5.6 MWC traded to 0.087 BTC. MWC transactions will require 500 confirmations, and
BTC transactions will require 6 confirmations. The time interval required for the message exchange and redeem are 1 hour (60 minutes).
The BTC redeem address is n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6. The seller will lock the funds first.

```
$ mwc-wallet cli
mwc-wallet> help swap_start
    ...
mwc-wallet> open
Password:
Command 'open' completed

mwc-wallet> swap_start --mwc_amount 5.6 --secondary_currency BTC --secondary_amount 0.087  --mwc_confirmations 500 --secondary_confirmations 6 --message_exchange_time 60 --redeem_time 60 --secondary_address n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6 --who_lock_first seller
20200804 12:19:27.863 WARN mwc_wallet_controller::command - Seller Swap trade is created: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
Command 'swap_start' completed
```
This command successfully created trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5

* Make sure the Buyer has the listener up and running.

```
$ mwc-wallet cli
mwc-wallet> open
Password:
Command 'open' completed
mwc-wallet> listen -m mwcmqs
20200804 12:25:55.310 WARN mwc_wallet_controller::controller - Starting MWCMQS Listener
20200804 12:25:56.207 WARN mwc_wallet_impls::adapters::mwcmq -
mwcmqs listener started for [xmgHFXM1ryJ1ug7kGPsjmDj8Gd7XC18cfhQ8n8uyjxL3JzAq9r73] tid=[tr3MClzoqB1ecFnH0kHBH]
```

* As a Seller, execute the steps of the atomic swap trade with the `swap --autoswap` command. Each invocation performs a single step and prints the trade status (add `--json_format` for a JSON status line); run it again for the next step, or drive the trade with the individual `swap` commands.  <br>
Please specify a big enough transaction fee for the redeem transaction, to ensure it will not get stuck in the memory pool. <br>
Keep in mind, **if your redeem transaction is stuck in the memory pool, the Buyer will be able to get all the coins**.

```
$ mwc-wallet cli
mwc-wallet> open
Password:
Command 'open' completed
mwc-wallet> listen -m mwcmqs
20200804 12:25:55.310 WARN mwc_wallet_controller::controller - Starting MWCMQS Listener
20200804 12:25:56.207 WARN mwc_wallet_impls::adapters::mwcmq -
mwcmqs listener started for [xmgHFXM1ryJ1ug7kGPsjmDj8Gd7XC18cfhQ8n8uyjxL3JzAq9r73] tid=[tr3MClzoqB1ecFnH0kHBH]
mwc-wallet> swap --autoswap --json_format --secondary_fee 30 -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
JSON: {"swap_id":"975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5","stateCmd":"...","last_process_error":null,"currentAction":"...","currentState":"...","roadmap":[...],"journal_records":[...]}
```

* Buyer awaits the message indicating a swap offer was received.
```
You get an offer to swap BTC to MWC. SwapID is 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
```

* The Buyer should carefully reviews the trade details. <br>
If something is wrong, just cancel the trade and notify the Seller about the problem. <br>
The Seller will need to cancel it's own swap tarde and create a new trade with fixed parameters. 

```
mwc-wallet> swap --check -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5

    Swap ID: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
    Buying 5.6 MWC for 0.087 BTC
    Requied lock confirmations: 500 for MWC and 6 for BTC
    Time limits: 60 minutes for messages exchange and 60 minutes for redeem/refund
    Locking order: Seller lock MWC first
    MWC funds locked until block 508701, expected to be mined in 21 hours and 9 minutes
    BTC funds locked for 33 hours and 23 minutes

-------- Execution plan --------
    Get an Offer at August  4 12:19:27
--> Send Accept Offer Message                 required by August  4 13:19:27
        Sending Accept Offer message, expired in 47 minutes
    Wait for seller to start locking MWC      required by August  4 13:46:57
    Post BTC to lock account                  required by August  4 13:46:57
    Wait for Locking funds confirmations      required by August  4 23:29:27
    Send Init Redeem Message                  required by August  4 23:29:27
    Wait For Redeem response message          required by August  4 23:29:27
    Redeem MWC                                required by August  5 00:29:27
    Wait For Redeem Tx Confirmations
    Swap is completed

-------- Trade Journal --------
    August  4 12:30:29  Get a Swap offer

-------- Required Action --------
    Sending Accept Offer message, expired in 47 minutes

Command 'swap' completed
```

* If the Buyer agrees with the Swap offer, he can execute the steps of the atomic swap trade with the `swap --autoswap` command (a single step per invocation, `--json_format` for JSON status output). 
Please specify a big enough transaction fee for the redeem transaction to ensure it will not get stuck in the memory pool. <br>
Keep in mind, **if your redeem transaction is stuck in the memory pool, the Seller will be able to get all the coins**.

```
mwc-wallet> swap --autoswap --json_format --buyer_refund_address mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No --secondary_fee 30 -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
JSON: {"swap_id":"975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5","stateCmd":"...","last_process_error":null,"currentAction":"...","currentState":"...","roadmap":[...],"journal_records":[...]}
```

* The Seller should get a message that the swap has been accepted. Both parties drive the remaining steps by repeating `swap --autoswap --json_format` (one step per invocation) or by entering the individual `swap` commands, until the Atomic Swap has finished. <br>
Both parties need to keep their wallets available until the Atomic Swap has finished. If a party doesn't act in a reasonable and timely manner, the swap trade can be cancelled and refunded.

```
Processed Offer Accept message
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: MWC lock slate is posted
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: MWC Lock transaction, waiting for 500 MWC lock confirmations, has 0
```

Progress messages like these appear in the trade journal; check the current state of a trade at any time with `swap --check -i <swap_id>`.

* As a Buyer the next step will be to deposit the Secondary (for example BTC) coins to a multisig lock account. <br>
After the swap was accepted and the lock is confirmed, the Buyer will see a message `Please deposit exactly XXXXXX BTC at <address>` in the trade journal.

```
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Please deposit exactly 0.087 BTC at 2N4YMbGBzP39WjhJMEFtrMhCxLz8iifcepW
```

* Once the message was received, the Buyer should post **the exact amount** of funds required to that address. <br>
Please specify enough transaction fees as the Transation must be mined before expiration time or the swap will be canceled.

* At this moment the Buyer needs to keep the wallet available until the swap is finished, executing the remaining steps with `swap --autoswap --json_format` or the individual `swap` commands. <br>
If the Seller didn't act in a reasonable and timely manner, the swap trade can be cancelled and refunded.


# Cancellation #

The swap trade can be cancelled at the starting stage, until the buyer has posted a redeem transaction. Depending on the stage of this transaction,
waiting for refund might be required.

Once a seller enters the MWC refund workflow, status checks and refund publication
require only the MWC node. An unavailable Electrum or Ethereum service does not
block that refund. If the buyer's MWC redemption is observed, the wallet returns
to the redemption workflow and obtains both chains' status before proceeding.

The reverse direction is also supported: secondary refunds can proceed once the
buyer is in the refund workflow, and secondary redemption can proceed once the
seller has recovered the redemption secret. An unavailable MWC node does not
block those actions. MWC observations remain required before entering those
recovery states; an unavailable MWC lock-time estimate is shown as unknown
(`null` for `mwcLockTime` in JSON output).

If a seller's lock attempt expires or fails before any submission, the wallet
cancels its local transaction reservations. Submitted locks, including attempts
with an uncertain network response, retain their reservations and refund recovery.

In this example the Buyer didn't lock any funds yet, so his trade is cancelled immediately. 
```
mwc-wallet> swap --adjust cancel  -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
Swap trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5 was successfully adjusted. New state: Buyer swap was cancelled, nothing was locked, no need to refund
Command 'swap' completed
mwc-wallet> Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Swap trade is finished
```

The Seller already locked MWC, so he will need to wait about 20 hours and 55 minutes to redeem the funds after canceling the swap.
```
mwc-wallet> swap --adjust cancel -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
Swap trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5 was successfully adjusted. New state: Waiting when refund Slate can be posted
Command 'swap' completed successfully

mwc-wallet> swap --check  -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
Password:

    Swap ID: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
    Selling 5.6 MWC for 0.087 BTC. BTC redeem address: n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6
    Requied lock confirmations: 500 for MWC and 6 for BTC
    Time limits: 60 minutes for messages exchange and 60 minutes for redeem/refund
    Locking order: Seller lock MWC first
    MWC funds locked until block 508701, expected to be mined in 20 hours and 55 minutes
    BTC funds locked for 33 hours and 6 minutes

-------- Execution plan --------
--> Wait for MWC refund to unlock             required by August  5 09:43:53
        Waiting when locked MWC can be refunded. About 1255 minutes are left, expired in 20 hours 55 minutes
    Post MWC Refund Slate                     started August  5 09:43:53  required by August  5 10:43:53
    Wait for MWC Refund confirmations
    Swap is cancelled, MWC are refunded

-------- Trade Journal --------
    August  4 12:19:27  Swap offer is created
    August  4 12:30:13  Offer message was sent
    August  4 12:35:24  Processed Offer Accept message
    August  4 12:35:27  MWC lock slate is posted
    August  4 12:47:52  Cancelled by user

Command 'swap' completed successfully
```
