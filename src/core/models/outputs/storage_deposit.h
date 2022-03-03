// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__
#define __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__

#include <stdint.h>

#include "core/models/outputs/outputs.h"

/**
 * @brief Specifies the current parameters for the byte cost computation
 *
 */
typedef struct {
  uint64_t v_byte_cost;         ///< Defines the rent of a single virtual byte denoted in IOTA tokens
  uint64_t v_byte_factor_data;  ///< Defines the multiplier for data fields
  uint64_t v_byte_factor_key;   ///< Defines the multiplier for fields which can act as keys for lookups
  uint64_t v_byte_offset;  ///< Additional virtual bytes that are caused by additional data that has to be stored in the
                           ///< database but is not part of the output itself
} byte_cost_config_t;

byte_cost_config_t storage_deposit_get_default_config();

uint64_t storage_deposit_calc_min_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                 void *output);

bool storage_deposit_check_sufficient_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                     void *output);

#endif  // __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__
