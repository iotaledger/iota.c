// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_EXTENDED_H__
#define __CORE_MODELS_OUTPUT_EXTENDED_H__

#include <stdint.h>

#include "core/models/outputs/native_tokens.h"

/**
 * @brief An output type which can hold native tokens and feature blocks.
 *
 */
typedef struct {
  void* address;                  ///< The deposit address
  uint64_t amount;                ///< The amount of IOTA tokens
  native_tokens_t native_tokens;  ///< The native tokens
  void* feature_blocks;           ///< The feature blocks which modulate the constrants on the output
} output_extended_t;

#endif
