// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_SEED_H__
#define __CORE_SEED_H__

#include "core/types.h"
#include "crypto/iota_crypto.h"

#define IOTA_SEED_BYTES ED_SEED_BYTES
#define IOTA_SEED_HEX_BYTES (ED_SEED_BYTES * 2)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets a random seed in binary format, 32 bytes.
 *
 * @param[out] seed An output of 32-byte seed
 */
void random_seed(byte_t seed[]);

/**
 * @brief Gets a random seed in hex-encoded format, 64 bytes.
 *
 * @param[out] seed An output of 64-byte seed
 */
void random_seed_hex(byte_t seed[]);

#ifdef __cplusplus
}
#endif

#endif