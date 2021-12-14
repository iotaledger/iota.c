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
  void* address;                   ///< The actual address
  uint64_t amount;                 ///< The amount of IOTA tokens held by this output
  native_tokens_t* native_tokens;  ///< The native tokens held by the output
  void* nft_id;                    ///< The identifier of this NFT
  byte_t* immutable_metadata;      ///< Arbitrary immutable binary data attached to this NFT
  void* feature_blocks;            ///< The feature blocks which modulate the constraints on the output
} output_nft_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new NFT Output object.
 *
 * @param[in] address Deposit address (Ed25519, Alias or NFT address)
 * @param[in] amount The amount of IOTA tokens to held by the output
 * @param[in] tokens Set of native tokens held by the output
 * @param[in] nft_id The identifier of this NFT
 * @param[in] metadata Arbitrary immutable binary data attached to this NFT
 * @param[in] metadata_len Length of metadata byte array
 * @param[in] feature_blocks Set of feature blocks
 *
 * @return output_nft_t* or NULL on failure
 */
output_nft_t* output_nft_new(void* address, uint64_t amount, native_tokens_t** tokens, void* nft_id, byte_t* metadata,
                             uint32_t metadata_len, void* feature_blocks);

/**
 * @brief Free NFT Output object.
 *
 * @param[in] output NFT Output object.
 */
void output_nft_free(output_nft_t* output);

/**
 * @brief Get the length of a serialized NFT Output
 *
 * @param[in] output NFT Output object.
 * @return size_t The number of bytes of serialized data
 */
size_t output_nft_serialize_length(output_nft_t* output);

/**
 * @brief Serialize NFT Output to a buffer
 *
 * @param[in] output NFT Output object.
 * @param[out] buf A buffer holds the serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t output_nft_serialize(output_nft_t* output, byte_t buf[]);

#endif
