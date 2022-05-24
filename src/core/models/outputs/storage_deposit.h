// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__
#define __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__

#include "core/models/outputs/byte_cost_config.h"
#include "core/models/outputs/outputs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Calculate minimum storage deposit for the given output
 *
 * @param[in] config A byte cost configuration
 * @param[in] output_type UTXO output type
 * @param[in] output Pointer to an output
 * @return true if output has enough storage deposit amount
 */
uint64_t calc_minimum_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type, void *output);

/**
 * @brief Check if a sufficient storage deposit was made for the given output
 *
 * @param[in] config A byte cost configuration
 * @param[in] output_type UTXO output type
 * @param[in] output Pointer to an output
 * @return true if output has enough storage deposit amount
 */
bool storage_deposit_check(byte_cost_config_t *config, utxo_output_type_t output_type, void *output);

#ifdef __cplusplus
}
#endif

#endif  // __CORE_MODELS_OUTPUT_STORAGE_DEPOSIT_H__
