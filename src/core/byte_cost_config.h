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

#endif  // __CORE_BYTE_COST_CONFIG_H__
