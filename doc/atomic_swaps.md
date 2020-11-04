# Contents : #
  * [Overview](./atomic_swaps.md/#Overview)
  * [Configuration](./atomic_swaps.md/#Configuration )
  * [Workflow / Guide](./atomic_swaps.md/#Atomic-swap-workflow)
  * [Cancellation](./atomic_swaps.md/#Cancellation)
  * [Discontinuing Auto-Swap](./atomic_swaps.md/#Discontinuing-Auto-Swap)
  * [Secondary Currency List](./atomic_swaps.md/#Secondary-Currency-List)
  
# Overview #

As of mwc-wallet 3.2.2, atomic swaps are supported by the mwc-wallet. This feature will allow users to exchange MWC coins for 
any Secondary currency from the supported currency list. The swap trade workflow is controlled by the wallet and can be run in 
manual or automatic mode. 

This document explains how Atomic Swaps can be done in automatic mode. Please note, there is also a manual mode that allows 
the user to run a swap trade step by step and use files for message exchanges. 

We strongly recommend the use of automatic mode for the standard swaps.

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

This example creates an atomic swap trade where 5.6 MWC traded to 0.087 BCH. MWC transactions will require 500 confirmations, and
BCH transactions will require 6 confirmations. The time interval required for the message exchange and redeem are 1 hour (60 minutes).
The BCH redeem address is n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6. The seller will lock the funds first.

```
$ mwc-wallet cli
mwc-wallet> help swap_start
    ...
mwc-wallet> open
Password:
Command 'open' completed

mwc-wallet> swap_start --mwc_amount 5.6 --secondary_currency BCH --secondary_amount 0.087  --mwc_confirmations 500 --secondary_confirmations 6 --message_exchange_time 60 --redeem_time 60 --secondary_address n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6 --who_lock_first seller
20200804 12:19:27.863 WARN grin_wallet_controller::command - Seller Swap trade is created: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
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
20200804 12:25:55.310 WARN grin_wallet_controller::controller - Starting MWCMQS Listener
20200804 12:25:56.207 WARN grin_wallet_impls::adapters::mwcmq -
mwcmqs listener started for [xmgHFXM1ryJ1ug7kGPsjmDj8Gd7XC18cfhQ8n8uyjxL3JzAq9r73] tid=[tr3MClzoqB1ecFnH0kHBH]
```

* As a Seller, start atomic swap trades in automatic mode with the `swap --autoswap` command.  <br>
Please specify a big enough transaction fee for the redeem transaction, to ensure it will not get stuck in the memory pool. <br>
Keep in mind, **if your redeem transaction is stuck in the memory pool, the Buyer will be able to get all the coins**.

```
$ mwc-wallet cli
mwc-wallet> open
Password:
Command 'open' completed
mwc-wallet> listen -m mwcmqs
20200804 12:25:55.310 WARN grin_wallet_controller::controller - Starting MWCMQS Listener
20200804 12:25:56.207 WARN grin_wallet_impls::adapters::mwcmq -
mwcmqs listener started for [xmgHFXM1ryJ1ug7kGPsjmDj8Gd7XC18cfhQ8n8uyjxL3JzAq9r73] tid=[tr3MClzoqB1ecFnH0kHBH]
mwc-wallet> swap --autoswap --method mwcmqs --dest xmggm9xA2ryzDARaRKNEdbw9rmSHxyLTMCqNua8iSPjCQAvsyx6s --secondary_fee 30 -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5

    Swap ID: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
    Selling 5.6 MWC for 0.087 BCH. BCH redeem address: n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6
    Requied lock confirmations: 500 for MWC and 6 for BCH
    Time limits: 60 minutes for messages exchange and 60 minutes for redeem/refund
    Locking order: Seller lock MWC first
    MWC funds locked until block 508701, expected to be mined in 21 hours and 11 minutes
    BCH funds locked for 33 hours and 25 minutes

-------- Execution plan --------
    Offer Created at August  4 12:19:27
--> Sending Offer to Buyer                    required by August  4 13:19:27
        Sending Offer message, expired in 49 minutes
    Waiting For Buyer to accept the offer     required by August  4 13:19:27
    Locking MWC funds                         required by August  4 13:46:57
    Waiting for Lock funds confirmations      required by August  4 23:29:27
    Waiting For Init Redeem message           required by August  4 23:29:27
    Sending back Redeem Message               required by August  4 23:29:27
    Wait For Buyer to redeem MWC              required by August  5 09:41:12
    Post Secondary Redeem Transaction         required by August  5 20:49:27
    Wait For Redeem Tx Confirmations
    Swap completed

-------- Trade Journal --------
    August  4 12:19:27  Swap offer is created

-------- Required Action --------
    Sending Offer message, expired in 49 minutes


WARNING: [xmggm9xA2ryzDARaRKNEdbw9rmSHxyLTMCqNua8iSPjCQAvsyx6s] has not been connected to mwcmqs for 72666 seconds. This user might not receive the swap message.
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Offer message was sent
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Waiting for Accept Offer message
```

* Once the Buyer received the offer, the offer Swap Id will be printed out.
```
You get an offer to swap BCH to MWC. SwapID is 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
```

* The Buyer should carefully reviews the trade details. <br>
If something is wrong, just cancel the trade and notify the Seller about the problem. <br>
The Seller will need to cancel it's own swap tarde and create a new trade with fixed parameters. 

```
mwc-wallet> swap --check -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5

    Swap ID: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
    Buying 5.6 MWC for 0.087 BCH
    Requied lock confirmations: 500 for MWC and 6 for BCH
    Time limits: 60 minutes for messages exchange and 60 minutes for redeem/refund
    Locking order: Seller lock MWC first
    MWC funds locked until block 508701, expected to be mined in 21 hours and 9 minutes
    BCH funds locked for 33 hours and 23 minutes

-------- Execution plan --------
    Get an Offer at August  4 12:19:27
--> Send Accept Offer Message                 required by August  4 13:19:27
        Sending Accept Offer message, expired in 47 minutes
    Wait for seller to start locking MWC      required by August  4 13:46:57
    Post BCH to lock account                  required by August  4 13:46:57
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

* If the Buyer agrees with the Swap offer, he can start the atomic swap trade in atomatic mode with a `swap --autoswap` command. 
Please specify a big enough transaction fee for the redeem transaction to ensure it will not get stuck in the memory pool. <br>
Keep in mind, **if your redeem transaction is stuck in the memory pool, the Seller will be able to get all the coins**.

```
mwc-wallet> swap --autoswap --method mwcmqs --dest xmgHFXM1ryJ1ug7kGPsjmDj8Gd7XC18cfhQ8n8uyjxL3JzAq9r73 --buyer_refund_address mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No --secondary_fee 30 -i 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5

    Swap ID: 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5
    Buying 5.6 MWC for 0.087 BCH
    Requied lock confirmations: 500 for MWC and 6 for BCH
    Time limits: 60 minutes for messages exchange and 60 minutes for redeem/refund
    Locking order: Seller lock MWC first
    MWC funds locked until block 508701, expected to be mined in 21 hours and 7 minutes
    BCH funds locked for 33 hours and 20 minutes

-------- Execution plan --------
    Get an Offer at August  4 12:19:27
--> Send Accept Offer Message                 required by August  4 13:19:27
        Sending Accept Offer message, expired in 44 minutes
    Wait for seller to start locking MWC      required by August  4 13:46:57
    Post BCH to lock account                  required by August  4 13:46:57
    Wait for Locking funds confirmations      required by August  4 23:29:27
    Send Init Redeem Message                  required by August  4 23:29:27
    Wait For Redeem response message          required by August  4 23:29:27
    Redeem MWC                                required by August  5 00:29:27
    Wait For Redeem Tx Confirmations
    Swap is completed

-------- Trade Journal --------
    August  4 12:30:29  Get a Swap offer

-------- Required Action --------
    Sending Accept Offer message, expired in 44 minutes

Command 'swap' completed
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Response to offer message was sent back
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Seller locking funds, waiting for 1 MWC lock confirmations, has 0
```

* The Seller should get a message that the swap has been accepted and automactic mode will process the next steps. <br>
Both parties need to keep the wallets running until the Atomic Swap has finished. 
There is no need for the Seller to be around anymore tho, the swap for the Seller will continue in automatic mode.
If the Buyer didn't act in a reasonable and timely manner, the swap trade will be cancelled and refunded automatically.

```
Processed Offer Accept message
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: MWC lock slate is posted
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: MWC Lock transaction, waiting for 500 MWC lock confirmations, has 0
```

* As a Buyer the next step will be to deposit the Secondary (for example BCH) coins to a multisig lock account. <br>
A few minutes after the swap was accepted, the Buyer should see a message `Please deposit exactly XXXXXX BCH at <address>`
 
```
Swap Trade 975ab0c2-27f5-45bd-99f2-2c3b01ce0fa5: Please deposit exactly 0.087 BCH at 2N4YMbGBzP39WjhJMEFtrMhCxLz8iifcepW
``` 
 
* Once the message was received, the Buyer should post **the exact amount** of funds required to that address. <br>
Please specify enough transaction fees as the Transation must be mined before expiration time or the swap will be canceled.

* At this moment the Buyer needs to keep the wallet running until the swap is finished. <br>
There is no need for the Buyer to be around anymore tho, the swap will continue in automatic mode. <br>
If the Seller didn't act in a reasonable and timely manner, the swap trade will be cancelled and refunded automatically.


# Cancellation #

The swap trade can be cancelled at the starting stage, until the buyer has posted a redeem transaction. Depending on the stage of this transaction,
waiting for refund might be required.

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
    Selling 5.6 MWC for 0.087 BCH. BCH redeem address: n4GUrta1qhA1Zgy4DUkmDgxULtJKjDhEc6
    Requied lock confirmations: 500 for MWC and 6 for BCH
    Time limits: 60 minutes for messages exchange and 60 minutes for redeem/refund
    Locking order: Seller lock MWC first
    MWC funds locked until block 508701, expected to be mined in 20 hours and 55 minutes
    BCH funds locked for 33 hours and 6 minutes

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


# Discontinuing Auto-Swap
To stop auto-swap, do:
```asm
mwc-wallet> swap --stop_auto_swap
This command is going to stop all the ongoing auto-swap threads. You can continue with the swap manually by entering commands step by step.
Do you want to continue? Please answer Yes/No
Yes
Stopping.....
Command 'swap' completed
```

# Secondary Currency List #
 * BCH - BitcoinCashABC
