// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CRYPTO_IOTA_H__
#define __CRYPTO_IOTA_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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
/**
 * @brief Ed25519 Keypair
 *
 */
typedef struct {
  uint8_t pub[ED_PUBLIC_KEY_BYTES];    ///< Public key with 32 bytes
  uint8_t priv[ED_PRIVATE_KEY_BYTES];  ///< Private key with 64 bytes
} ed25519_keypair_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fill-in random bytes into the given byte buffer.
 *
 * @param[out] buf A buffer holds random bytes
 * @param[in] len The length of the buffer
 */
void iota_crypto_randombytes(uint8_t *const buf, const size_t len);

/**
 * @brief Derives key pair from a given ed25519 seed
 *
 * @param[in] seed A given seed with length of the ed25519 seed
 * @param[out] keypair A keypair derived from the seed
 */
void iota_crypto_keypair(uint8_t const seed[], ed25519_keypair_t *keypair);

/**
 * @brief Signs message by the given ed25519 private key
 *
 * @param[in] priv_key The ed25519 private key
 * @param[in] msg A byte buffer holds the message data
 * @param[in] msg_len The length of the message
 * @param[out] signature The output signature
 * @return int 0 on successful
 */
int iota_crypto_sign(uint8_t const priv_key[], uint8_t msg[], size_t msg_len, uint8_t signature[]);

/**
 * @brief Verify if the signature is valid with the message and public key
 *
 * @param[in] msg A byte buffer holds the message data
 * @param[in] msg_len The length of the message
 * @param[in] pub_key The ed25519 public key
 * @param[in] signature The ed25519 signature
 * @return int 0 if valid and -1 if invalid
 */
int iota_crypto_sign_open(uint8_t msg[], size_t msg_len, uint8_t const pub_key[], uint8_t signature[]);

/**
 * @brief HMAC-SHA-256 hash computation
 *
 * @param[in] secret_key The private/secret key
 * @param[in] msg A buffer holds message data
 * @param[in] msg_len The length of message
 * @param[out] auth The output authentication
 * @return int 0 on successful
 */
int iota_crypto_hmacsha256(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]);

/**
 * @brief HMAC-SHA-512 hash computation
 *
 * @param[in] secret_key The private/secret key
 * @param[in] msg A buffer holds message data
 * @param[in] msg_len The length of message
 * @param[out] auth The output authentication
 * @return int 0 on successful
 */
int iota_crypto_hmacsha512(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]);

/**
 * @brief Create Blake2b state object which is needed for partially hash calculations
 * @return void* A pointer to the Blake2b state
 */
void *iota_blake2b_new_state();

/**
 * @brief Free Blake2b state object
 *
 * @param[in] state The state of hash function
 */
void iota_blake2b_free_state(void *state);

/**
 * @brief Initialize Blake2b hash function
 *
 * @param[in] state The state of hash function
 * @param[out] out_len  The length of output hash
 * @return int 0 on success
 */
int iota_blake2b_init(void *state, size_t out_len);

/**
 * @brief Provide additional data to hash in Blake2b hash function
 *
 * @param[in] state The state of hash function
 * @param[in] data The data to hash
 * @param[in] data_len The length of data
 * @return int 0 on success
 */
int iota_blake2b_update(void *state, uint8_t const data[], size_t data_len);

/**
 * @brief Finalize Blake2b hash function
 *
 * @param[in] state The state of hash function
 * @param[out] out An output hash
 * @param[out] out_len  The length of output hash
 * @return int 0 on success
 */
int iota_blake2b_final(void *state, uint8_t out[], size_t out_len);

/**
 * @brief Blake2b hash computation
 *
 * @param[in] msg The message to hash
 * @param[in] msg_len The length of message
 * @param[out] out An output hash
 * @param[out] out_len  The length of output hash
 * @return int 0 on success
 */
int iota_blake2b_sum(uint8_t const msg[], size_t msg_len, uint8_t out[], size_t out_len);

/**
 * @brief SHA-256 computation
 *
 * @param[in] msg The message
 * @param[in] msg_len The length of message
 * @param[out] hash The output hash
 * @return int 0 on success
 */
int iota_crypto_sha256(uint8_t const msg[], size_t msg_len, uint8_t hash[]);

/**
 * @brief SHA-512 computation
 *
 * @param[in] msg The message
 * @param[in] msg_len The length of the message
 * @param[out] hash The output hash
 * @return int 0 on success
 */
int iota_crypto_sha512(uint8_t const msg[], size_t msg_len, uint8_t hash[]);

/**
 * @brief PBKDF2 HMAC SHA512 computation
 *
 * Ref: https://datatracker.ietf.org/doc/html/rfc2898#section-5.2
 *
 * @param[in] pwd The password buffer, an octet string
 * @param[in] pwd_len The length of password
 * @param[in] salt The salt buffer, an octet string
 * @param[in] salt_len The length of salt
 * @param[in] iterations The iteration counter, must be bigger than 0
 * @param[out] dk The derived key
 * @param[in] dk_len The length of derived key
 * @return int 0 on success
 */
int iota_crypto_pbkdf2_hmac_sha512(char const pwd[], size_t pwd_len, char const salt[], size_t salt_len,
                                   int32_t iterations, uint8_t dk[], size_t dk_len);

#ifdef __cplusplus
}
#endif

#endif
