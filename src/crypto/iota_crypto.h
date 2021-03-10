// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CRYPTO_IOTA_H__
#define __CRYPTO_IOTA_H__

#include <stdint.h>
#include <stdlib.h>

#define ED_SEED_BYTES 32         // ed25519 seed bytes
#define ED_PUBLIC_KEY_BYTES 32   // ed2519 public key bytes
#define ED_PRIVATE_KEY_BYTES 64  // ed25519 secret/private key bytes
#define ED_SIGNATURE_BYTES 64    // ed25519 signature bytes

#define CRYPTO_SHA512_KEY_BYTES 32   // crypto_auth_hmacsha512_KEYBYTES
#define CRYPTO_SHA512_HASH_BYTES 64  // crypto_auth_hmacsha512_BYTES

#define CRYPTO_BLAKE2B_HASH_BYTES 32  // crypto_generichash_blake2b_BYTES

/**
 * @brief Ed25519 Keypair
 *
 */
typedef struct {
  uint8_t pub[ED_PUBLIC_KEY_BYTES];    ///< 32 bytes public key
  uint8_t priv[ED_PRIVATE_KEY_BYTES];  ///< 64 bytes private key
} iota_keypair_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief fill-in random bytes into the given byte buffer.
 *
 * @param[out] buf A buffer holds random bytes
 * @param[in] len The length of byte buffer
 */
void iota_crypto_randombytes(uint8_t *const buf, const size_t len);

/**
 * @brief derives key pair from a given seed(IOTA_SEED_BYTES)
 *
 * @param[in] seed A given seed with length of IOTA_SEED_BYTES
 * @param[out] keypair A keypair derived from the seed
 */
void iota_crypto_keypair(uint8_t const seed[], iota_keypair_t *keypair);

/**
 * @brief signs message by the given private key
 *
 * @param[in] priv_key The private key
 * @param[in] msg A byte buffer holds the message data
 * @param[in] msg_len The length of the message
 * @param[out] signature The output signature
 * @return int 0 on successful
 */
int iota_crypto_sign(uint8_t const priv_key[], uint8_t msg[], size_t msg_len, uint8_t signature[]);

/**
 * @brief HMAC-SHA-256 interface
 *
 * @param[in] secret_key The private/secret key
 * @param[in] msg A buffer holds message data
 * @param[in] msg_len The length of message
 * @param[out] auth The output authentication
 * @return int 0 on successful
 */
int iota_crypto_hmacsha256(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]);

/**
 * @brief HMAC-SHA-512 interface
 *
 * @param[in] secret_key The private/secret key
 * @param[in] msg A buffer holds message data
 * @param[in] msg_len The length of message
 * @param[out] auth The output authentication
 * @return int 0 on successful
 */
int iota_crypto_hmacsha512(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]);

/**
 * @brief Blake2b hash function
 *
 * @param[in] msg The message to hash
 * @param[in] msg_len The length of message
 * @param[out] out An output hash
 * @param[out] out_len  The length of output hash
 * @return int 0 on success
 */
int iota_blake2b_sum(uint8_t const msg[], size_t msg_len, uint8_t out[], size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
