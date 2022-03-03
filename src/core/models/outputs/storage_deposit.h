// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__
#define __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__

#include "core/models/outputs/byte_cost_config.h"
#include "core/models/outputs/outputs.h"

/**
 * @brief Create and return default byte cost configuration
 *
 * @return *byte_cost_config_t
 */
byte_cost_config_t *storage_deposit_get_default_config();

/**
 * @brief Create new byte cost configuration
 *
 * @param[in] byte_cost Rent of a single virtual byte denoted in IOTA tokens
 * @param[in] byte_factor_data Multiplier for data fields
 * @param[in] byte_factor_key Multiplier for key fields
 * @param[in] byte_offset Additional virtual bytes
 * @return *byte_cost_config_t
 */
byte_cost_config_t *storage_deposit_new_config(uint64_t byte_cost, uint64_t byte_factor_data, uint64_t byte_factor_key,
                                               uint64_t byte_offset);

/**
 * @brief Check if a sufficient storage deposit was made for the given output
 *
 * @param[in] config A byte cost configuration
 * @param[in] output_type UTXO output type
 * @param[in] output Pointer to an output
 * @return true if output has enough storage deposit amount
 */
bool storage_deposit_check_sufficient_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                     void *output);

#endif  // __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__
