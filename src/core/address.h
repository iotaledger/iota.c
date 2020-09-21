#ifndef __CORE_ADDRESS_H__
#define __CORE_ADDRESS_H__

#include <stdbool.h>

#include "core/types.h"
#include "sodium.h"

// the length of an address (digest length = 32 + version byte length = 1).
#define IOTA_ADDRESS_BYTES 33
#define IOTA_ADDRESS_BASE58_LEN 48
#define IOTA_SEED_BYTES crypto_sign_ed25519_SEEDBYTES

#define ED_PUBLIC_KEY_BYTES crypto_sign_ed25519_PUBLICKEYBYTES
#define ED_PRIVATE_KEY_BYTES crypto_sign_ed25519_SECRETKEYBYTES
#define ED_SIGNATURE_BYTES crypto_sign_ed25519_BYTES
#define ED_DIGEST_BYTES 32

// address signature version
typedef enum { ADDRESS_VER_WOTS = 0, ADDRESS_VER_ED25519 = 1 } address_version_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets a random seed.
 *
 * @param[out] seed An output seed
 */
void random_seed(byte_t seed[]);

/**
 * @brief Gets a human readable version of the Seed (base58 encoded).
 *
 * @param[in] seed The seed in bytes
 * @param[out] str_buf The seed string
 * @param[in] buf_len The len of string
 * @return true
 * @return false
 */
bool seed_2_base58(byte_t const seed[], char str_buf[], size_t *buf_len);

/**
 * @brief Gets seed bytes from a human readable seed string.
 *
 * @param[in] str the seed string
 * @param[out] out_seed seed in bytes array
 * @return true
 * @return false
 */
bool seed_from_base58(char const str[], byte_t out_seed[]);

/**
 * @brief Gets the address from corresponding seed and index
 *
 * @param[in] seed The seed for genrate address
 * @param[in] index The index of address
 * @param[in] version The address signature version
 * @param[out] addr_out An address
 */
void get_address(byte_t seed[], uint64_t index, address_version_t version, byte_t addr_out[]);

/**
 * @brief Gets a human readable version of the address (base58 encoded).
 *
 * @param[in] address An address in bytes
 * @param[out] str_buf A buffer holds string address
 * @return true
 * @return false
 */
bool address_2_base58(byte_t const address[], char str_buf[]);

/**
 * @brief Converts base58 into IOTA address raw data.
 *
 * @param[in] base58_str A base58 string
 * @param[out] addr A buffer holds address
 * @return true
 * @return false
 */
bool address_from_base58(char const base58_str[], byte_t addr[]);

/**
 * @brief signs data/message and returns the signature.
 *
 * @param[in] seed The seed
 * @param[in] index The index of address
 * @param[in] data The message or data
 * @param[in] data_len The length of data
 * @param[out] signature The signed signature.
 */
void sign_signature(byte_t const seed[], uint64_t index, byte_t const data[], uint64_t data_len, byte_t signature[]);

/**
 * @brief Validates signature
 *
 * @param[in] seed The seed
 * @param[in] index An address index
 * @param[in] signature The signature
 * @param[in] data The expected data
 * @param[in] data_len The length of data
 * @return true
 * @return false
 */
bool sign_verify_signature(byte_t const seed[], uint64_t index, byte_t signature[], byte_t const data[],
                           size_t data_len);

/**
 * @brief print out hexmal value in a byte array.
 *
 * @param[in] data A byte array.
 * @param[in] len The size of the byte array.
 */
void dump_hex(byte_t const data[], size_t len);

#ifdef __cplusplus
}
#endif

#endif