// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_ADDRESS_H__
#define __CORE_ADDRESS_H__

#include <stdbool.h>

#include "core/types.h"

// An Ed25519 address is the Blake2b-256 hash of an Ed25519 public key.
#define ADDRESS_ED25519_BYTES 32
// An Alias address is the Blake2b-160 hash of the OutputID which created it.
#define ADDRESS_ALIAS_BYTES 20
// A NFT address is the Blake2b-160 hash of the OutputID which created it.
#define ADDRESS_NFT_BYTES 20
#define ADDRESS_MAX_BYTES ADDRESS_ED25519_BYTES
#define ADDRESS_MIN_BYTES ADDRESS_ALIAS_BYTES
#define ADDRESS_SERIALIZED_MAX_BYTES (1 + ADDRESS_ED25519_BYTES)
#define ADDRESS_SERIALIZED_MIN_BYTES (1 + ADDRESS_ALIAS_BYTES)

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

// create ed25519 address from from seed and slip10 path

/**
 * @brief Create an ed25519 address from slip10
 *
 * @param[in] seed The seed for slip10
 * @param[in] seed_len The length of seed
 * @param[in] path The path for slip10
 * @param[out] addr An ed25519 address object
 * @return int 0 on success
 */
int ed25519_address_from_path(byte_t seed[], size_t seed_len, char path[], address_t *addr);

/**
 * @brief Create an Alias address from output ID
 *
 * @param[in] output_id A string of output ID
 * @param[out] addr An Alias address object
 * @return int 0 on success
 */
int alias_address_from_output(char const output_id[], address_t *addr);

/**
 * @brief Create a NFT address from output ID
 *
 * @param[in] output_id A string of output ID
 * @param[out] addr A NFT address object
 * @return int 0 on success
 */
int nft_address_from_output(char const output_id[], address_t *addr);

/**
 * @brief Get the byte length of the given address
 *
 * @param[in] addr An address object
 * @return uint8_t
 */
uint8_t address_len(address_t *addr);

/**
 * @brief Get the serialized length of the given address
 *
 * @param[in] addr An address object
 * @return uint8_t
 */
uint8_t address_serialized_len(address_t *addr);

/**
 * @brief Serialized the given address to binary from.
 *
 * @param[in] addr An address object
 * @param[out] bytes A buffer hold serialized data
 * @param[in] len The length of the buffer
 * @return int o on success
 */
int address_serialized(address_t *addr, byte_t bytes[], size_t len);

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
 * @brief Compare two address objects
 *
 * @param[in] addr1 Address 1
 * @param[in] addr2 Address 2
 * @return true
 * @return false
 */
bool address_equal(address_t *addr1, address_t *addr2);

#ifdef __cplusplus
}
#endif

#endif
