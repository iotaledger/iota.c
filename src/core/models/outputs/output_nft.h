// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NFT_H__
#define __CORE_MODELS_OUTPUT_NFT_H__

#include <stdint.h>

#include "core/models/outputs/native_tokens.h"
#include "core/types.h"

/**
 * @brief An output type used to implement non-fungible tokens.
 *
 */
typedef struct {
  void* address;                  ///< The actual address
  uint64_t amount;                ///< The amount of IOTA tokens held by this output
  native_tokens_t native_tokens;  ///< The native tokens held by the output
  void* nft_id;                   ///< The identifier of this NFT
  byte_t* immutable_metadata;     ///< Arbitrary immutable binary data attached to this NFT
  void* feature_blocks;           ///< The feature blocks which modulate the constraints on the output
} output_nft_t;

#endif
