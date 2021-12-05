// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__
#define __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__

#include <stdint.h>

#include "core/types.h"
#include "uthash.h"

/**
 * @brief Native Tokens is a set of Native Token
 *
 */
typedef struct {
  byte_t token_id[38];  ///< Identifier of the native toke
  void* amount;         ///< uint256, Amount of tokens
  UT_hash_handle hh;
} native_tokens_t;

#endif
