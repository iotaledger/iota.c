// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_SLIP10_H__
#define __CORE_UTILS_SLIP10_H__

#include <stdint.h>

#include "core/types.h"

#define BIP32_HARDENED (1UL << 31)
#define MAX_PIB32_PATH 32
#define SLIP10_PUBLIC_KEY_BYTES 33
#define SLIP10_PRIVATE_KEY_BYTES 32
#define SLIP10_CHAIN_CODE_BYTES 32

typedef enum { SECP256K1_CURVE, NIST_P256_CURVE, ED25519_CURVE } slip10_curve_t;

typedef struct {
  byte_t key[SLIP10_PRIVATE_KEY_BYTES];
  byte_t chain_code[SLIP10_CHAIN_CODE_BYTES];
} slip10_key_t;

typedef struct {
  uint32_t path[MAX_PIB32_PATH];
  int len;
} bip32_path_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets bip32 path from string
 *
 * @param[in] str A bip32 path string
 * @param[out] path The output path
 * @return int 0 on successful
 */
int slip10_parse_path(char str[], bip32_path_t* path);

/**
 * @brief Derives key from given seed and path
 *
 * @param[in] seed A seed in byte array
 * @param[in] seed_len The length of seed
 * @param[in] path The string of path
 * @param[in] curve The type of curve, only support ed25519
 * @param[out] key The derived key
 * @return int 0 on successful
 */
int slip10_key_from_path(byte_t seed[], size_t seed_len, char path[], slip10_curve_t curve, slip10_key_t* key);

/**
 * @brief Get public key from the derived key
 *
 * @param[in] curve The type of curve, only support ed25519
 * @param[in] key A slip-10 key
 * @param[out] pub_key The public key
 * @return int 0 on successful
 */
int slip10_public_key(slip10_curve_t curve, slip10_key_t* key, byte_t pub_key[]);

#ifdef __cplusplus
}
#endif

#endif
