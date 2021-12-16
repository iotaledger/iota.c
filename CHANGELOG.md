# v0.4.0 - 2021-12-16

- Added libsodium support on Linux
- Implemented Event(MQTT) API subscribers
- Modularity enhancement, the user can build one of Crypto, Core, Client layers by CMake options
  - `WITH_IOTA_CORE`
  - `WITH_IOTA_CLIENT`
  - `IOTA_WALLET_ENABLE`
  - `MQTT_CLIENT_ENABLE`

## New Features

- Client - added ledgerIndex into get_output [#162](https://github.com/iotaledger/iota.c/pull/162)
- Client - added dustAllowed and ledgerIndex to get_balance response [#164](https://github.com/iotaledger/iota.c/pull/164)
- Crypto - implemented PBKDF2 SHA512 with libsodium [#](https://github.com/iotaledger/iota.c/pull/165)
- Client - Added tests for milestones/latest topic subscription [#183](https://github.com/iotaledger/iota.c/pull/183)
- Client - added milestones confirmed event API [#185](https://github.com/iotaledger/iota.c/pull/185)
- Client - added messages/referenced event [#186](https://github.com/iotaledger/iota.c/pull/186)
- Client - Added event_stop method for disconnecting mqtt [#184](https://github.com/iotaledger/iota.c/pull/184)
- Client - implemented event address outputs [#190](https://github.com/iotaledger/iota.c/pull/190)
- Client - Subscribe outputs/outputId topic. [#192](https://github.com/iotaledger/iota.c/pull/192)
- Client - Messages hex payload [#197](https://github.com/iotaledger/iota.c/pull/197)
- Client - Esp32 MQTT wrapper [#203](https://github.com/iotaledger/iota.c/pull/203)

## Breaking changes

- Client - accept bech32 address for get_balance method [#158](https://github.com/iotaledger/iota.c/pull/158)
  - `get_balance` parameters are changed
- Client - Get output address changes [#167](https://github.com/iotaledger/iota.c/pull/167)
  - `get_outputs_from_address` parameters are changed
- Mqtt abstraction layer for subscribing to node event api's [#170](https://github.com/iotaledger/iota.c/pull/170)
  - support Node Event APIs
- CMake - added module options [#182](https://github.com/iotaledger/iota.c/pull/182)
  - introduce `WITH_IOTA_CLIENT` and `WITH_IOTA_CORE` CMake options

## Changes

- Fixing typo [#163](https://github.com/iotaledger/iota.c/pull/163)
- Tests - fixed memory leaks [0d048813](https://github.com/iotaledger/iota.c/commit/0d048813d53367eada2ab2c44b6623538c517595)
- CI - fixed code style check on tests and examples [d5538e3b](https://github.com/iotaledger/iota.c/commit/d5538e3bf8ccd6407681818b4f9e7de02f61ec95)
- Client - fixed http client for zephyr v2.7.0 [a1b32f74](https://github.com/iotaledger/iota.c/commit/a1b32f74d91e676c666e96b3a58fe093b8cf1f53)
- Doc - added Node events and updated block diagrams [#188](https://github.com/iotaledger/iota.c/pull/188)
- Client - config freed in node event [#189](https://github.com/iotaledger/iota.c/pull/189)
- CI - added event API tests. [#191](https://github.com/iotaledger/iota.c/pull/191)
- Client - event metadata subscriber [#187](https://github.com/iotaledger/iota.c/pull/187)
- Doc - Added events APIs [#206](https://github.com/iotaledger/iota.c/pull/206)

# v0.3.0 - 2021-10-06

- Crypto module supports mbedtls library on Linux.
- Implemented mnemonic APIs that are compatible with Firefly address derivation.

## Changes

- Core - refactor unlock block methods [#142](https://github.com/iotaledger/iota.c/pull/142)
- wallet - don't consume all outputs [#144](https://github.com/iotaledger/iota.c/pull/144)
- Crypto - sha256/sha512 interface [#145](https://github.com/iotaledger/iota.c/pull/145)
- Crypto - support mbedtls on Linux. [#149](https://github.com/iotaledger/iota.c/pull/149)
- Tests - slip10 clean up. [#150](https://github.com/iotaledger/iota.c/pull/150)
- Examples - Update and add README. [#151](https://github.com/iotaledger/iota.c/pull/151)

## Breaking changes

- Wallet - support mnemonic [#147](https://github.com/iotaledger/iota.c/pull/147)
- Wallet - refactoring, mnemonic support. [#154](https://github.com/iotaledger/iota.c/pull/154)
  - introduce `IOTA_WALLET_ENABLE` and remove `IOTA_WALLET_BIP39` option.
- Wallet - introduce `BIP39_ENGLISH_ONLY` option. [49d46f2](https://github.com/iotaledger/iota.c/commit/49d46f258da9f1af13f1c4b964a068f101b0ab15)

# v0.2.0 - 2021-07-07

- Support Zephyr RTOS and nRF-Connect SDK development frameworks
- Breaking - HTTP client refactored for a better compatibility

# v0.1.0-beta - 2021-05-25

This is the first C client library release for the [Chrysalis](https://chrysalis.docs.iota.org/introduction/what_is_chrysalis.html) network aka IOTA 1.5.  
The IOTA C Client documentation can be found in [here](https://iota-c-client.readthedocs.io/en/latest/index.html)

Supported [REST Node APIs](https://github.com/iotaledger/protocol-rfcs/pull/27):

- GET health
- GET /api/v1/info
- GET /api/v1/tips
- POST /api/v1/messages
- GET /api/v1/messages/{messageId}
- GET /api/v1/messages/{messageId}/metadata
- GET /api/v1/messages/{messageId}/children
- GET /api/v1/outputs/{outputId}
- GET /api/v1/addresses/ed25519/{address}
- GET /api/v1/addresses/ed25519/{address}/outputs
