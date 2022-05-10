// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CRYPTO_CONSTANTS_H__
#define __CRYPTO_CONSTANTS_H__

#define ED_SEED_BYTES 32         // ed25519 seed bytes
#define ED_PUBLIC_KEY_BYTES 32   // ed2519 public key bytes
#define ED_PRIVATE_KEY_BYTES 64  // ed25519 secret/private key bytes
#define ED_SIGNATURE_BYTES 64    // ed25519 signature bytes

#define CRYPTO_SHA512_KEY_BYTES 32        // crypto_auth_hmacsha512_KEYBYTES
#define CRYPTO_SHA512_HASH_BYTES 64       // crypto_auth_hmacsha512_BYTES
#define CRYPTO_SHA256_KEY_BYTES 32        // crypto_auth_hmacsha256_KEYBYTES
#define CRYPTO_SHA256_HASH_BYTES 32       // crypto_auth_hmacsha256_BYTES
#define CRYPTO_BLAKE2B_256_HASH_BYTES 32  // crypto_generichash_blake2b_BYTES
#define CRYPTO_BLAKE2B_160_HASH_BYTES 20  // crypto_generichash_blake2b-160_BYTES

#endif
