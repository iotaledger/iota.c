# v0.3.0 - 2021-10-06

* Crypto module supports mbedtls library on Linux.
* Implemented mnemonic APIs that are compatible with Firefly address derivation.

## Changes

* Core - refactor unlock block methods [#142](https://github.com/iotaledger/iota.c/pull/142)
* wallet - don't consume all outputs [#144](https://github.com/iotaledger/iota.c/pull/144)
* Crypto - sha256/sha512 interface [#145](https://github.com/iotaledger/iota.c/pull/145)
* Crypto - support mbedtls on Linux. [#149](https://github.com/iotaledger/iota.c/pull/149)
* Tests - slip10 clean up. [#150](https://github.com/iotaledger/iota.c/pull/150)
* Examples - Update and add README. [#151](https://github.com/iotaledger/iota.c/pull/151)

## Breaking changes

* Wallet - support mnemonic [#147](https://github.com/iotaledger/iota.c/pull/147)
* Wallet - refactoring, mnemonic support. [#154](https://github.com/iotaledger/iota.c/pull/154)
  - introduce `IOTA_WALLET_ENABLE` and remove `IOTA_WALLET_BIP39` option.
* Wallet - introduce `BIP39_ENGLISH_ONLY` option. [49d46f2](https://github.com/iotaledger/iota.c/commit/49d46f258da9f1af13f1c4b964a068f101b0ab15)


# v0.2.0 - 2021-07-07

* Support Zephyr RTOS and nRF-Connect SDK development frameworks
* Breaking - HTTP client refactored for a better compatibility

# v0.1.0-beta - 2021-05-25

This is the first C client library release for the [Chrysalis](https://chrysalis.docs.iota.org/introduction/what_is_chrysalis.html) network aka IOTA 1.5.  
The IOTA C Client documentation can be found in [here](https://iota-c-client.readthedocs.io/en/latest/index.html)  

Supported [REST Node APIs](https://github.com/iotaledger/protocol-rfcs/pull/27):  
* GET health
* GET /api/v1/info
* GET /api/v1/tips
* POST /api/v1/messages
* GET /api/v1/messages/{messageId}
* GET /api/v1/messages/{messageId}/metadata
* GET /api/v1/messages/{messageId}/children
* GET /api/v1/outputs/{outputId}
* GET /api/v1/addresses/ed25519/{address}
* GET /api/v1/addresses/ed25519/{address}/outputs
