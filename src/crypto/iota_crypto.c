// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifdef CRYPTO_USE_SODIUM
#include <sodium.h>
#else
#include <openssl/hmac.h>
#include <string.h>
#include <sys/random.h>
#include "blake2.h"
#include "ed25519.h"
#endif

#include "crypto/iota_crypto.h"

void iota_crypto_randombytes(uint8_t *const buf, const size_t len) {
#if CRYPTO_USE_SODIUM
  randombytes_buf((void *const)buf, len);
#else
  ssize_t ret = -1;
  while (ret == -1) {
    ret = getrandom(buf, len, GRND_NONBLOCK);
  }
#endif
}

// get ed25519 public and private key from address
void iota_crypto_keypair(uint8_t const seed[], iota_keypair_t *keypair) {
#if CRYPTO_USE_SODIUM
  crypto_sign_seed_keypair(keypair->pub, keypair->priv, seed);
#else
  ed25519_public_key pub;
  ed25519_publickey(seed, pub);
  memcpy(keypair->priv, seed, 32);
  memcpy(keypair->priv + 32, pub, 32);
  memcpy(keypair->pub, pub, 32);
#endif
}

int iota_crypto_sign(uint8_t const priv_key[], uint8_t msg[], size_t msg_len, uint8_t signature[]) {
#if CRYPTO_USE_SODIUM
  unsigned long long sign_len = ED_SIGNATURE_BYTES;
  return crypto_sign_ed25519_detached(signature, &sign_len, msg, msg_len, priv_key);
#else
  ed25519_sign(msg, msg_len, priv_key, priv_key + 32, signature);
  return 0;
#endif
}

int iota_crypto_hmacsha256(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]) {
#if CRYPTO_USE_SODIUM
  return crypto_auth_hmacsha256(auth, msg, msg_len, secret_key);
#else
  uint8_t *hash = HMAC(EVP_sha256(), secret_key, 32, (const unsigned char *)msg, msg_len, NULL, NULL);
  memcpy(auth, hash, 32);
  return 0;
#endif
}

int iota_crypto_hmacsha512(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]) {
#if CRYPTO_USE_SODIUM
  return crypto_auth_hmacsha512(auth, msg, msg_len, secret_key);
#else
  uint8_t *hash = HMAC(EVP_sha512(), secret_key, 32, (const unsigned char *)msg, msg_len, NULL, NULL);
  memcpy(auth, hash, 64);
  return 0;
#endif
}

int iota_blake2b_sum(uint8_t const msg[], size_t msg_len, uint8_t out[], size_t out_len) {
#if CRYPTO_USE_SODIUM
  return crypto_generichash_blake2b(out, out_len, msg, msg_len, NULL, 0);
#else
  return blake2b(out, out_len, msg, msg_len, NULL, 0);
#endif
}
