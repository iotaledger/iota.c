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

#define CRYPTO_SHA512_KEY_BYTES 32    // crypto_auth_hmacsha512_KEYBYTES
#define CRYPTO_SHA512_HASH_BYTES 64   // crypto_auth_hmacsha512_BYTES
#define CRYPTO_SHA256_KEY_BYTES 32    // crypto_auth_hmacsha256_KEYBYTES
#define CRYPTO_SHA256_HASH_BYTES 32   // crypto_auth_hmacsha256_BYTES
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

/**
 * @brief SHA-256 HASH
 *
 * @param[in] msg message data
 * @param[in] msg_len the length of data
 * @param[out] hash the output hash
 * @return int 0 on success
 */
int iota_crypto_sha256(uint8_t const msg[], size_t msg_len, uint8_t hash[]);

/**
 * @brief SHA-512 HASH
 *
 * @param[in] msg message data
 * @param[in] msg_len the length of data
 * @param[out] hash the output hash
 * @return int 0 on success
 */
int iota_crypto_sha512(uint8_t const msg[], size_t msg_len, uint8_t hash[]);

/**
 * @brief PBKDF2 HMAC SHA512
 *
 * Ref: https://datatracker.ietf.org/doc/html/rfc2898#section-5.2
 *
 * @param[in] pwd password buffer, an octet string
 * @param[in] pwd_len the length of password
 * @param[in] salt salt buffer, an octet string
 * @param[in] salt_len the length of salt
 * @param[in] iterations iteration count, must be bigger than 0
 * @param[out] dk derived key
 * @param[in] dk_len the length of derived key
 * @return int 0 on success
 */
int iota_crypto_pbkdf2_hmac_sha512(char const pwd[], size_t pwd_len, char const salt[], size_t salt_len,
                                   int32_t iterations, uint8_t dk[], size_t dk_len);

/**
 * @brief endianness check
 *
 * There is no standardized way to check endianness with different compilers at compile-time
 * for better compatibility, we check it at runtime.
 *
 * @return true little-endian
 * @return false big-endian
 */
static inline bool is_little_endian() {
  int16_t i = 0xF;
  char *p = (char *)&i;
  return (p[0] == 0xF);
}

#ifdef __cplusplus
}
#endif

#endif
