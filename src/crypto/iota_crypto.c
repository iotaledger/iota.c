// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <sodium.h>

#include "crypto/iota_crypto.h"

void iota_crypto_randombytes(uint8_t *const buf, const size_t len) { randombytes_buf((void *const)buf, len); }

// get ed25519 public and private key from address
void iota_crypto_keypair(uint8_t const seed[], iota_keypair_t *keypair) {
  crypto_sign_seed_keypair(keypair->pub, keypair->priv, seed);
}

int iota_crypto_sign(uint8_t const priv_key[], uint8_t msg[], size_t msg_len, uint8_t signature[]) {
  unsigned long long sign_len = ED_SIGNATURE_BYTES;
  return crypto_sign(signature, &sign_len, msg, msg_len, priv_key);
}

int iota_crypto_hmacsha256(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]) {
  return crypto_auth_hmacsha256(auth, msg, msg_len, secret_key);
}

int iota_crypto_hmacsha512(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]) {
  return crypto_auth_hmacsha512(auth, msg, msg_len, secret_key);
}
