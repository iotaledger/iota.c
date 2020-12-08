#ifndef __CORE_ADDRESS_H__
#define __CORE_ADDRESS_H__

#include <stdbool.h>

#include "core/seed.h"
#include "core/types.h"
#include "crypto/iota_crypto.h"

// the length of an address
#define IOTA_ADDRESS_BYTES (1 + ED_PUBLIC_KEY_BYTES)  // address version + address data

// the hex address is used in node API, it's a string of 64 characters, the version field is excluded
#define IOTA_ADDRESS_HEX_BYTES (ED_PUBLIC_KEY_BYTES * 2)

// address signature version
typedef enum { ADDRESS_VER_WOTS = 0, ADDRESS_VER_ED25519 = 1 } address_version_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the address from seed
 *
 * @param[in] seed The seed for genrating address
 * @param[in] version The address version(address_version_t)
 * @param[in] index The index of address
 * @param[out] addr_out The output address
 */
void get_address_from_seed(seed_ctx_t const* const seed, address_version_t version, uint64_t index, byte_t addr_out[]);

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