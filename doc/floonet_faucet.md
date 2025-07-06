
# MWC Floonet Faucet / MWC Testnet Faucet

If you need some coins to test with the MWC Floonet network, feel free to use the faucet. It can send up to **5 MWC** per request on the Floonet testnet.

Testnet coins can be requested using `mwc-wallet` with the command:

```shell
> mwc-wallet faucet_request --amount <amount>
```

You can download the `mwc-wallet` from the official releases page:  
👉 https://github.com/mwcproject/mwc-wallet/releases

We assume you have already downloaded, installed, and initialized your `mwc-wallet`. Here’s how to request test coins.  
🔹 **Note:** The maximum amount you can request at once is **5 MWC**.

---

### 💸 How to Request Coins

```shell
> mwc-wallet --floonet faucet_request -a 1.2
Password:
20250705 19:02:06.812 WARN mwc_wallet_controller::controller - Starting MWCMQS Listener
20250705 19:02:08.474 WARN mwc_wallet_impls::adapters::mwcmq -
mwcmqs listener started for [xmh3yzhnBj4pxyo2N1upV6FYmqo5QpzM8YHv8HRMghTwm8ht5JR2] tid=[Mg1RKMoenGTULgK_XjBFC]
slate [c0d202d4-0989-4a3b-a684-97514f84f25e] for [1.200000000] MWCs sent to [mwcmqs://xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU]
Get invoice finalize slate [c0d202d4-0989-4a3b-a684-97514f84f25e] for [1.200000000] MWCs, processing...
Invoice slate [c0d202d4-0989-4a3b-a684-97514f84f25e] for [1.200000000] MWCs was processed and sent back for posting.
Command 'faucet_request' completed successfully

> mwc-wallet --floonet info
Password:
updater: the current_height is 1489662

____ Wallet Summary Info - Account 'default' as of height 1489662 ____

 Confirmed Total                  | 4.200000000
 Awaiting Confirmation (< 10)     | 3.000000000
 Awaiting Finalization            | 11.200000000
 Locked by previous transaction   | 0.000000000
 -------------------------------- | -------------
 Currently Spendable              | 1.200000000

Command 'info' completed successfully 
```

🕒 **Note:** If the faucet hasn't been used for a while, it may take a few minutes to wake up and resynchronize with the blockchain.  
If your invoice fails, please wait a couple of minutes and try again.

📣 If the faucet appears to be offline for an extended time, feel free to ping a moderator in the `#developers` channel on [Discord](https://discord.gg/n5dZaty).

---

### 🔁 How to Return Coins

Once you’re done testing, please return the test coins to the faucet:

```shell
> mwc-wallet --floonet send -m mwcmqs -d xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU <amount_to_send_back>
Password:
20250705 19:06:49.864 WARN mwc_wallet_controller::controller - Starting MWCMQS Listener
20250705 19:06:52.488 WARN mwc_wallet_impls::adapters::mwcmq -
mwcmqs listener started for [xmh3yzhnBj4pxyo2N1upV6FYmqo5QpzM8YHv8HRMghTwm8ht5JR2] tid=[RWSevePqTdwCumGfY99it]
20250705 19:06:52.501 WARN mwc_wallet_controller::controller - Get back slate c0d202d4-0989-4a3b-a684-97514f84f25e. Because slate arrive too late, wallet not processing it
slate [131a2cc5-cefa-4381-bdc5-e7e4b9abf788] for [1.100000000] MWCs sent to [mwcmqs://xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU]
slate [131a2cc5-cefa-4381-bdc5-e7e4b9abf788] finalized successfully
Command 'send' completed successfully
```

Thank you for testing with MWC Floonet!
