// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_ALIAS_H__
#define __CORE_MODELS_OUTPUT_ALIAS_H__

#include <stdint.h>

#include "core/models/outputs/native_tokens.h"
#include "core/types.h"

/**
 * @brief An output type which represents an alias account.
 *
 */
typedef struct {
  uint64_t amount;                ///< The amount of IOTA tokens held by the output
  native_tokens_t native_tokens;  ///< The native tokens held by the output
  void* alias_id;                 ///< The identifier of this alias account
  void* st_ctl;                   ///< State Controller, the entity which is allowed to control this alias account state
  void* gov_ctl;                  ///< Governance Controller, the entity which is allowed to govern this alias account
  uint32_t state_index;           ///< The index of the state
  byte_t* state_metadata;         ///< The state of the alias account which can only be mutated by the state controller
  uint32_t foundry_counter;       ///< The counter that denotes the number of foundries created by this alias account
  void* feature_blocks;           ///< The feature blocks which modulate the constraints on the output
} output_alias_t;

#endif
