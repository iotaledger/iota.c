// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_ADDRESS_H__
#define __CORE_ADDRESS_H__

#include <stdbool.h>

#include "core/seed.h"
#include "core/types.h"
#include "crypto/iota_crypto.h"

// the length of an address
#define IOTA_ADDRESS_BYTES (1 + ED_PUBLIC_KEY_BYTES)  // address version + address data
#define ED25519_ADDRESS_BYTES ED_PUBLIC_KEY_BYTES     // ed25519 address schema
// the hex address is used in node API, it's a string of 64 characters, the version field is excluded
#define IOTA_ADDRESS_HEX_BYTES (ED25519_ADDRESS_BYTES * 2)

// address signature version
typedef enum { ADDRESS_VER_ED25519 = 0, ADDRESS_VER_UNKNOW = 1 } address_version_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get address from ed25519 public key
 *
 * @param[in] pub_key An ed25519 public key
 * @param[out] addr Output address with length of 32 bytes
 * @return int 0 on success
 */
int address_from_ed25519_pub(byte_t const pub_key[], byte_t addr[]);

/**
 * @brief Get Ed25519 keypair from given seed and path
 *
 * @param[in] seed A seed
 * @param[in] path A string of path, ex: "m/0H/1H/2H" or "m/0'/1'/2'"
 * @param[out] keypair The ed25519 keypair
 * @return int 0 on success
 */
int address_keypair_from_path(byte_t seed[], char path[], iota_keypair_t* keypair);

/**
 * @brief Get address from seed and slip10 path
 *
 * @param[in] seed An IOTA seed
 * @param[in] path A string of path, ex: "m/0H/1H/2H" or "m/0'/1'/2'"
 * @param[out] out_addr
 * @return int 0 on success
 */
int address_from_path(byte_t seed[], char path[], byte_t out_addr[]);

/**
 * @brief Get an IOTA address from a given bech32 string
 *
 * The address is 33 bytes which is a version byte + ed25519 address bytes
 *
 * @param[in] hrp The human readable prefix
 * @param[in] bech32_str An address string
 * @param[out] out_addr an ed25519 address with the version byte
 * @return int 0 on success;
 */
int address_from_bech32(char const* hrp, char const* bech32_str, byte_t out_addr[]);

/**
 * @brief Get a bech32 string from a given address
 *
 * @param[in] addr An ed25519 address with the version byte
 * @param[in] hrp The human readable prefix
 * @param[out] bech32_addr An address string
 * @return int 0 on success
 */
int address_2_bech32(byte_t const addr[], char const* hrp, char* bech32_addr);

/**
 * @brief Convert Bech32 address to ed25519 in hex string form
 *
 * @param[in] hrp The HRP prefix
 * @param[in] bech32 A Bech32 address string
 * @param[out] hex A buffer holds output
 * @param[in] hex_len the length of the buffer, should bigger than 65 bytes
 * @return int 0 on success
 */
int address_bech32_to_hex(char const hrp[], char const bech32[], char hex[], size_t hex_len);

#ifdef __cplusplus
}
#endif

#endif
