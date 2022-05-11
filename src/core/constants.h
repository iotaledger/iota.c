// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_CONSTANTS_H__
#define __CORE_CONSTANTS_H__

#include <stdint.h>

#include "crypto/constants.h"

/****** Constants related to messages ******/
// Message ID length in binary form
#define IOTA_MESSAGE_ID_BYTES 32

/****** Constants related to transactions ******/
// Transaction ID bytes
#define IOTA_TRANSACTION_ID_BYTES 32
// OUTPUT ID bytes = 34 (IOTA_TRANSACTION_ID + OUTPUT INDEX)
#define IOTA_OUTPUT_ID_BYTES (IOTA_TRANSACTION_ID_BYTES + sizeof(uint16_t))
// Have one transaction essence type only which is 1
#define TRANSACTION_ESSENCE_TYPE 1

/****** Constants related to addresses ******/
// An Ed25519 address is the Blake2b-256 hash of an Ed25519 public key.
#define ED25519_PUBKEY_BYTES ED_PUBLIC_KEY_BYTES
// An Alias address is the Blake2b-256 hash of the OutputID which created it.
#define ALIAS_ID_BYTES CRYPTO_BLAKE2B_256_HASH_BYTES
// A NFT address is the Blake2b-256 hash of the OutputID which created it.
#define NFT_ID_BYTES CRYPTO_BLAKE2B_256_HASH_BYTES
// Maximum number of bytes an address can hold.
#define ADDRESS_MAX_BYTES ED25519_PUBKEY_BYTES
// Minimum number of bytes an address can hold.
#define ADDRESS_MIN_BYTES ALIAS_ID_BYTES
// Maximum number of bytes a serialized address can hold.
#define ADDRESS_SERIALIZED_MAX_BYTES (1 + ED25519_PUBKEY_BYTES)

/****** Constants related to unlock blocks ******/
// ed25519 signature block  = signature type + public key + signature
#define ED25519_SIGNATURE_BLOCK_BYTES (1 + ED_PUBLIC_KEY_BYTES + ED_SIGNATURE_BYTES)  // 97 bytes
// unlock_type_t + reference = 1 + 2
#define UNLOCK_REFERENCE_SERIALIZE_BYTES (1 + sizeof(uint16_t))
//  unlock_type_t + signature type + pub_key + signature
#define UNLOCK_SIGNATURE_SERIALIZE_BYTES (1 + ED25519_SIGNATURE_BLOCK_BYTES)
// unlock_type_t + alias index = 1 + 2
#define UNLOCK_ALIAS_SERIALIZE_BYTES (1 + sizeof(uint16_t))
// unlock_type_t + NFT index = 1 + 2
#define UNLOCK_NFT_SERIALIZE_BYTES (1 + sizeof(uint16_t))

/****** Constants related to tagged data ******/
// Maximum length of tag in bytes
#define TAGGED_DATA_TAG_MAX_LENGTH_BYTES 64

/****** Constants related to feature blocks ******/
// Maximum possible length in bytes of a Tag
#define MAX_INDEX_TAG_BYTES 64
// Maximun possible length in bytes of Metadata
#define MAX_METADATA_LENGTH_BYTES 8192
// Maximun Feature Blocks in a list
#define MAX_FEATURE_BLOCK_COUNT 4

/****** Constants related to native tokens ******/
// Maximum number of Native Tokens in an output
#define NATIVE_TOKENS_MAX_COUNT 64
// Native Token ID length in bytes
#define NATIVE_TOKEN_ID_BYTES 38
// Serialized bytes = token ID(38 bytes) + amount(uint256_t)
#define NATIVE_TOKENS_SERIALIZED_BYTES (NATIVE_TOKEN_ID_BYTES + 32)

/****** Constants related to foundry output ******/
// The concatenation of Address || Serial Number || Token Scheme Type
#define FOUNDRY_ID_BYTES 26

/****** Constants related to UTXO output ******/
// Maximum number of outputs in a transaction payload.
#define UTXO_OUTPUT_MAX_COUNT 128
// Maximum IOTA token supply
static const uint64_t MAX_IOTA_SUPPLY = 2779530283277761;

/****** Constants related to unlock conditions ******/
// Maximun Unlock Condition Blocks in a list
#define MAX_UNLOCK_CONDITION_BLOCK_COUNT 4

/****** Constants related to UTXO inputs ******/
// Maximum number of inputs in a transaction payload.
#define UTXO_INPUT_MAX_COUNT 128

#endif
