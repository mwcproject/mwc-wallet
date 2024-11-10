# MWC Slatepacks

## Contents : #
  * [About](./slatepack_data_format.md/#About)
  * [Community-level explanation](./slatepack_data_format.md/#Community-level-explanation)
  * [Reference-level explanation](./slatepack_data_format.md/#Reference-level-explanation)
    * [Slatepack Address](./slatepack_data_format.md/#Slatepack-Address )
    * [Message Armor](./slatepack_data_format.md/#Message-Armor)
    * [Encryption/Decryption](./slatepack_data_format.md/#EncryptionDecryption)
    * [Binary Data Format](./slatepack_data_format.md/#Binary-Data-Format)

# About

Slatepacks are intented to simplify the exchange process for Slates in a secure and userfriendly way. Current file based methods have the following cons:
* Files content is well readable, because of that it is not secure.
* Files are susceptible to man in the middle attack because files are not addressed to specific wallet.
* Users don't like files for exchanges. Sting with content is more friendly.

To address those issues MWC adopts mwc's Slatepacks:  https://docs.mwc.mw/wiki/transactions/slatepack/ <br>
Altho MWC slatepacks look very similar, the implementation is very different.
This document desribes the Slatepack format and our deviation from mwcs Implementation.

# Community-level explanation
Slatepacks Simplify the existing transaction process so that a transaction can be built using a copy and pastable SlatepackMessage string asynchronously.
So in easier words this simplyfies transactions alot as it's usable by a simple copy paste without the requirement to be online or to exchange files.

An Example to elaborate;

```mwc-wallet send -d SlatepackAddress 1.337``` will generate an armored encrypted SlatepackMessage string that only you and the recipient can decipher if a TOR address was used as SlatepackAddress. In the case of MQS it will generate a non encrypted SlatepackMessage. <br>
If a counterparty is unwilling or unable to provide a SlatepackAddress, an unencrypted plain text SlatepackMessage can still be exchanged
This SlatepackMessage can then be exchanged manually by copy and paste.
Example SlatepackAddress: f4ujdq2hzidsrwljst4mfxoaogolqzhwzbu4uxjke6w4ibclqgxaowid

Sending a mobile MWC transaction should be as easy as scanning a simple QR code encoded from a bech32 SlatepackAddress
Or as easy as pasting the SlatepackAddress of your counterparty into your wallet for any other device.
Then the SlatepackMessage can be exchanged easily via copy and paste with a counterparty in an alternative communication channel (email, forum, social media, instant messenger, generic web text box, carrier pigeon etc.)


# Reference-level explanation
## Slatepack Address

MWC has a 'ProvableAddress' that includes a TOR or MQS address. For Slatepacks we will continue to use them. For encrypted Slatepacks only TOR 
addresses can be used because of encryption/decryption internals.  If the ProvableAddress is a MQS Address it can't be used for encrypted slatepacks, but will generate an unencrypted SlatepackMessage instead.

Please note, ProvableAddress is applicable to encrypted slatepack only.

## Message Armor

Mwc Armor does binary to Base58 conversion and it works great for us. This part works as it is, the only change is the header and footer.
https://docs.mwc.mw/wiki/transactions/slatepack/#armor

For normal encrypted slatepacks the header/footer are: BEGINSLATEPACK / ENDSLATEPACK

For non encrypted slatepacks in binary format the header/footer are: BEGINSLATE_BIN / ENDSLATE_BIN

## Encryption/Decryption

Mwc's original design is using the 'age' rust library for encryption/decryption. The Age library had a huge data overhead on data size.
The header is about 350 bytes. For example, initial send message size less then 150 bytes. Such overhead is not acceptable.
Also it is not clear if age will allow to read the message that was archived. 

In MWC's implementation we don't use age, encryption/decryption is done with the same primitives as described below;

### Encryption (sender side)

* Sender supply it's own ed25519 secret and receiver ed25519 public key.
* sender's ed25519 SecretKey and recipient's ed25519 PublicKey are converted to x25519 StaticKey and x25519 PublicKey
* calculating Diffie Hellman Shared Secret value.
* Encrypt the data with this Shared Secret using symmetrical AEAD CHACHA20_POLY1305 algorithm. 
* Resulting data is 16 bytes larger then original one.

## Decryption (recipient side)

* Read sender ed25519 PublicKey from unencrypted part of the payload. The recipient supply it's own ed25519 SecretKey.
* recipient's ed25519 SecretKey and sender's ed25519 PublicKey are converted to x25519 StaticKey and x25519 PublicKey
* calculating Diffie Hellman Shared Secret value.
* Decrypt the data with this Shared Secret using symmetrical AEAD CHACHA20_POLY1305 algorithm. 
* Resulting data is 16 bytes smaller then original one.

## Slatepack Binary Data Format

Users working with armored message, but underneath it is a pure binary format. Here we describe the format, so it will be easier to understand it. 

MWC slate data is using bit streaming as a format for data serialization. The serialization/deserialization functions are symmetrical and
aren't using serde because we want full control to maintain compatibility. Backward compatibility will be maintained. The forward compatibility is nice to have, but it is not guaranteed.

### Slate package binary (not encrypted) header

Data | Size | Descryption 
---- | ---- | ----------- |
Version             | 1 byte    | The slatepack binary format version. This version is global for all parts.
Sender Public Key   | 30 bytes  | Sender public key. Needed to decode the encrypted data by receiver
Receiver Public Key | 30 bytes  | Receiver Public key. Needed to decode encryptrd by sender (archived data)
Nonce               | 12 bytes  | AEAD message nonce 
Encrypted Data Size | 2 bytes   | Length of the encrypted data in bytes

### Slate package encrypted data.

Data | Size | Descryption 
---- | ---- | ----------- |
content             | 3 bit     |  The content of the salte. Currently support: SendInitial, SendResponse, InvoiceInitial, InvoiceResponse, FullSlate values
Slate UUID          | 16 bytes  |  UUID of the slate. Need to identify transaction
Network             | 1 bit     |  1 for mainnet and 0 for floonet/testnet
amount              | Varibale  |  Optional, Amount of the slate, nano coints
fee                 | Varibale  |  Optional, Transaction fee, nano coints
height              | Varibale  |  slate height
lock_height         | Varibale  |  locking height
Option ttl_cutoff_height | Varibale | TTL value of the slate
Slate offset        | 32 bytes  | Optional, Transaction offset (blinding factor)
Inputs types        | 1 bit     | Optional, 1 for commit + feature per input. 0 - just commits
Input feature       | 1 bit     | Optional, 0 for Plain, 1 for Coinbase 
Input commit        | 33 bytes  | Optional, Input commit 
Input stop bit      | 1 bit     | Optional, 1 if has another input. O if no more inputs left to read
Output commit       | 33 bytes  | Optional, Output commit
Output Range proof size    | 10 bits   | Optional, Length of thange proof data 
Output Range proof  | length    | Optional, Range proff content
Output stop bit     | 1 bit     | Optional, 1 if has another output. O if no more outputs left to read
Kernel commit       | 33 bytes  | Optional, Kernel commit.  
Kernel signature    | 64 bytes  | Optional, Kernel signature
Kernel stop bit     | 1 bit     | Optional, 1 if has another kernel. O if no more kernels left to read
Participant blind Excess size | 7 bits | Optional, size of the blind excess public key
Participant blind Excess | length | Optional, blind excess PK data
Participant Nonce size | 7 bits | Optional, size of the nonce
Participant Nonce    | length | Optional, nonce data
Participant signature flag | 1 bit | Optional, 1 if signature present, 0 if not
Participant signature | 64 bytes | Optional,  participant signature
Participant message flag | 1 bit | Optional, 1 if message present, 0 if not
Participant Message size | 16 bits | Size of the compressed text message
Participant message      | length  | Message compressed with smaz algorithm
Another participant data |          | Optional, another participant data.
Proof flag          | 1 bit     | Optional, 1 if proof data present, 0 if not
Proof Sender Address    | variable | Optional, the sender address saved as binary Dalek PK or secp256k1 PK
Proof Receiver address  | variable | Optional, the receiver address saved as binary Dalek PK or secp256k1 PK
Proof Signature flag    | 1 bit  | Optional, 1 if signature data present, 0 if not
Proof Signature len delta | 4 bit   | Optional, length can be longet then 64 byte (can be 70). Len is 64 + this_value 
Proof Signature         | 64 bytes | Optional, signature data
Future usage        | any       | Here we can write encrypted frontward compatible data.
CRC32               | last 4 bytes | The check sum for Unencrypoted and Encrypted data. It allow to verify is unencrypted or encrypted data was adjusted

## Slate package binary (not encrypted) tail

Currently nothing, can be used for frontward compatible data.
