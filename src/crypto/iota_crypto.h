#ifndef __CRYPTO_IOTA_H__
#define __CRYPTO_IOTA_H__

#include "sodium.h"

#define ED_SEED_BYTES 32         // ed25519 seed bytes
#define ED_PUBLIC_KEY_BYTES 32   // ed2519 public key bytes
#define ED_PRIVATE_KEY_BYTES 64  // ed25519 secret/private key bytes
#define ED_SIGNATURE_BYTES 64    // ed25519 signature bytes

typedef struct {
  uint8_t pub[ED_PUBLIC_KEY_BYTES];
  uint8_t priv[ED_PRIVATE_KEY_BYTES];
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
 * @brief A a simplified interface for message authentication
 *
 * @param[in] secret_key The private/secret key
 * @param[in] msg A buffer holds message data
 * @param[in] msg_len The length of message
 * @param[out] auth The output authentication
 * @return int 0 on successful
 */
int iota_crypto_hmacsha256(uint8_t const secret_key[], uint8_t msg[], size_t msg_len, uint8_t auth[]);

#ifdef __cplusplus
}
#endif

#endif
