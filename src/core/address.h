// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_ADDRESS_H__
#define __CORE_ADDRESS_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/constants.h"
#include "core/utils/byte_buffer.h"
#include "crypto/iota_crypto.h"

/**
 * @brief Address types that supported by the protocol
 *
 */
typedef enum {
  ADDRESS_TYPE_ED25519 = 0,  ///< Denotes an Ed25519 address
  ADDRESS_TYPE_ALIAS = 8,    ///< Denotes an Alias address
  ADDRESS_TYPE_NFT = 16      ///< Denotes a NFT address
} address_type_t;

/**
 * @brief Address object
 *
 * the address length depends on the type.
 * * ADDRESS_TYPE_ED25519: 32 bytes
 * * ADDRESS_TYPE_ALIAS: 20 bytes
 * * ADDRESS_TYPE_NFT: 20 bytes
 *
 */
typedef struct {
  address_type_t type;                ///< one of address types
  byte_t address[ADDRESS_MAX_BYTES];  ///< address data
} address_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derive ed25519 keypair from slip10 seed and path
 *
 * @param[in] seed The seed for slip10
 * @param[in] seed_len The length of seed
 * @param[in] path The path for slip10
 * @param[out] keypair The derived ed25519 keypair
 * @return int 0 on success
 */
int address_keypair_from_path(byte_t seed[], size_t seed_len, char path[], ed25519_keypair_t *keypair);

/**
 * @brief Derive an ed25519 address from slip10
 *
 * @param[in] seed The seed for slip10
 * @param[in] seed_len The length of seed
 * @param[in] path The path for slip10
 * @param[out] addr An ed25519 address object
 * @return int 0 on success
 */
int ed25519_address_from_path(byte_t seed[], size_t seed_len, char path[], address_t *addr);

/**
 * @brief Derive ed25519 address from ed25519 public key
 *
 * @param[in] pub_key An ed25519 public key
 * @param[out] addr An ed25519 address object
 * @return int 0 on success
 */
int address_from_ed25519_pub(byte_t const pub_key[], address_t *addr);

/**
 * @brief Derive an Alias address from output ID
 *
 * @param[in] output_id A output ID byte array
 * @param[in] output_id_len A length of output ID byte array
 * @param[out] addr An Alias address object
 * @return int 0 on success
 */
int alias_address_from_output(byte_t const output_id[], uint8_t output_id_len, address_t *addr);

/**
 * @brief Derive a NFT address from output ID
 *
 * @param[in] output_id A output ID byte array
 * @param[in] output_id_len A length of output ID byte array
 * @param[out] addr A NFT address object
 * @return int 0 on success
 */
int nft_address_from_output(byte_t const output_id[], uint8_t output_id_len, address_t *addr);

/**
 * @brief Get the length of the given address in bytes.
 *
 * @param[in] addr An address object
 * @return uint8_t
 */
uint8_t address_len(address_t const *const addr);

/**
 * @brief Get the serialized length of the given address
 *
 * @param[in] addr An address object
 * @return uint8_t
 */
uint8_t address_serialized_len(address_t *addr);

/**
 * @brief Serialize the given address to binary from.
 *
 * @param[in] addr An address object
 * @param[out] bytes A buffer hold serialized data
 * @param[in] len The length of the buffer
 * @return size_t The bytes written is returned, 0 on error
 */
size_t address_serialize(address_t *addr, byte_t bytes[], size_t len);

/**
 * @brief Deserialize a binary data to an address object
 *
 * The returned address need to be freed after use.
 *
 * @param[in] bytes A buffer holds binary data
 * @param[in] len the length of the buffer
 * @return address_t* A pointer to the deserialized address, NULL on error
 */
address_t *address_deserialize(byte_t bytes[], size_t len);

/**
 * @brief Create an address object from the given bech32 string
 *
 * @param[in] hrp The HRP of bech32
 * @param[in] bech32 The string of bech32 address
 * @param[out] addr The output address object
 * @return int 0 on success
 */
int address_from_bech32(char const hrp[], char const bech32[], address_t *addr);

/**
 * @brief Get bech32 string from the given address
 *
 * @param[in] addr An address object
 * @param[in] hrp The HRP of bech32
 * @param[out] bech32_buf A buffer hold bech32 string
 * @param[in] buf_len The length of the given buffer
 * @return int 0 on success
 */
int address_to_bech32(address_t *addr, char const hrp[], char bech32_buf[], size_t buf_len);

/**
 * @brief Check if two addresses are equal
 *
 * @param[in] addr1 Address 1
 * @param[in] addr2 Address 2
 * @return true
 * @return false
 */
bool address_equal(address_t *addr1, address_t *addr2);

/**
 * @brief Clone an address object, it should be freed after use.
 *
 * @param addr[in] The address for clone
 * @return address_t* A new address object
 */
address_t *address_clone(address_t const *const addr);

/**
 * @brief Print an address object
 *
 * @param[in] addr An address object
 */
void address_print(address_t const *const addr);

/**
 * @brief Free an address object
 *
 * @param[in] addr An address object
 */
void address_free(address_t *addr);

#ifdef __cplusplus
}
#endif

#endif
