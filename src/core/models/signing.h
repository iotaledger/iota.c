// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_SIGNING_H__
#define __CORE_MODELS_SIGNING_H__

#include <inttypes.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/unlock_block.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Sign transaction
 *
 * @param[in] inputs An UTXO input list
 * @param[in] essence_hash An essence hash
 * @param[out] unlock_blocks A list of unlock blocks which will be created
 * @return int 0 on success
 */
int signing_transaction_sign(utxo_inputs_list_t* inputs, byte_t essence_hash[], unlock_list_t** unlock_blocks);

#ifdef __cplusplus
}
#endif

#endif  // __CORE_MODELS_SIGNING_H__
