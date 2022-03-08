// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_BYTE_COST_CONFIG_H__
#define __CORE_BYTE_COST_CONFIG_H__

#include <stdint.h>

/**
 * @brief Specifies the current parameters for the byte cost computation
 *
 */
typedef struct {
  uint16_t v_byte_cost;        ///< Defines the rent of a single virtual byte denoted in IOTA tokens
  uint8_t v_byte_factor_data;  ///< Defines the multiplier for data fields
  uint8_t v_byte_factor_key;   ///< Defines the multiplier for fields which can act as keys for lookups
  uint16_t v_byte_offset;  ///< Additional virtual bytes that are caused by additional data that has to be stored in the
                           ///< database but is not part of the output itself
} byte_cost_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new byte cost configuration
 *
 * @param[in] byte_cost Rent of a single virtual byte denoted in IOTA tokens
 * @param[in] byte_factor_data Multiplier for data fields
 * @param[in] byte_factor_key Multiplier for key fields
 * @return *byte_cost_config_t
 */
byte_cost_config_t *byte_cost_config_new(uint16_t byte_cost, uint8_t byte_factor_data, uint8_t byte_factor_key);

/**
 * @brief Create new default byte cost configuration
 *
 * @return *byte_cost_config_t
 */
byte_cost_config_t *byte_cost_config_default_new();

/**
 * @brief Free byte cost configuration
 *
 * @param[in] config A byte cost configuration
 */
void byte_cost_config_free(byte_cost_config_t *config);

#ifdef __cplusplus
}
#endif

#endif  // __CORE_BYTE_COST_CONFIG_H__
