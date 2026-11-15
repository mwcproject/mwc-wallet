# MWC Slatepacks

## Contents : #
  * [About](#about)
  * [Community-level explanation](#community-level-explanation)
  * [Reference-level explanation](#reference-level-explanation)
    * [Slatepack Address](#slatepack-address)
    * [Message Armor](#message-armor)
    * [Encryption/Decryption](#encryptiondecryption)
    * [Binary Data Format](#slatepack-binary-data-format)

# About

Slatepacks carry compact transaction data as copyable text, allowing sender and
recipient to exchange messages asynchronously. Encryption is optional: an
unencrypted Slatepack is readable by anyone who has the message. File transport
is not itself insecure; confidentiality depends on message encryption and the
channel used to exchange it.

# Community-level explanation

The sender creates an initial message, the recipient receives it and returns a
response, then the sender finalizes. The CLI supports a `slatepack` send method;
use `mwc-wallet send --help` for destination and file options. A Tor/Ed25519
recipient address permits encryption. An MQS address is not an encryption key
for this format. Do not assume `send -d ADDRESS` alone selects a manual exchange
rather than an online transport.

MWC uses its own compact binary serialization and armor. It does not use a
bech32 Grin Slatepack address as its standard recipient representation. Current
implementation and tests are in `libwallet/src/slatepack/`.

# Reference-level explanation
## Slatepack Address

MWC has a 'ProvableAddress' that includes a TOR or MQS address. For Slatepacks we will continue to use them. For encrypted Slatepacks only TOR 
addresses can be used because of encryption/decryption internals.  If the ProvableAddress is a MQS Address it can't be used for encrypted slatepacks, but will generate an unencrypted SlatepackMessage instead.

Please note, ProvableAddress is applicable to encrypted slatepack only.

## Message Armor

Armor Base58-encodes a four-byte checksum followed by the binary message. The
checksum is the first four bytes of double SHA-256 of that binary message.
Framing uses `BEGINSLATEPACK.` / `. ENDSLATEPACK.` for encrypted messages and
`BEGINSLATE_BIN.` / `. ENDSLATE_BIN.` for unencrypted messages. The decoder
checks matching framing, checksum and size limits. See `armor.rs` for whitespace
handling and exact encoding; armor is not encryption.

## Encryption/Decryption

The earlier Grin design used the 'age' rust library for encryption/decryption. The Age library had a huge data overhead on data size.
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

### Plaintext header of an encrypted Slatepack

Data | Size | Descryption 
---- | ---- | ----------- |
Version             | 1 byte    | The slatepack binary format version. This version is global for all parts.
Sender Public Key   | 32 bytes  | Sender public key. Needed to decode the encrypted data by receiver
Receiver Public Key | 32 bytes  | Receiver Public key. Needed to decode encryptrd by sender (archived data)
Nonce               | 12 bytes  | AEAD message nonce 
Encrypted Data Size | 2 bytes   | Length of the encrypted data in bytes

For an **unencrypted** Slatepack, the binary header is only the one-byte version
and two-byte payload length, followed by the payload. It has no sender/recipient
keys, nonce or inner CRC32. Both forms still have the outer armor checksum.

### Slate payload

In version 0, input, output, and kernel sections use a continuation bit after
each element. If a section is included for the message's purpose, it must contain
at least one element; an empty list has no representation and is rejected during
encoding. Omitted sections, such as outputs in `InvoiceInitial`, may be empty.
Consequently, an exact-payment compact invoice response with no change outputs
cannot be encoded in version 0.

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
Proof Signature         | 64 + length delta bytes | Optional, signature data
Future usage        | any       | Here we can write encrypted frontward compatible data.
CRC32 | last 4 plaintext bytes, encrypted form only | Checksum over version + sender/recipient keys + aligned plaintext payload, appended before AEAD encryption

## Slate package binary (not encrypted) tail

No separate tail is currently written. Length/framing and bounded payload decoding are enforced; do not append arbitrary data and assume it will be accepted.
