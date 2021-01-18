// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_SEED_H__
#define __CORE_SEED_H__

#include "core/types.h"
#include "crypto/iota_crypto.h"

#define IOTA_SEED_BYTES ED_SEED_BYTES

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets a random seed.
 *
 * @param[out] seed An output seed
 */
void random_seed(byte_t seed[]);

#ifdef __cplusplus
}
#endif

#endif