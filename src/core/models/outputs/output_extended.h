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
  void* address;                   ///< Deposit address
  uint64_t amount;                 ///< The amount of IOTA tokens to held by the output
  native_tokens_t* native_tokens;  ///< The native tokens held by the output
  void* feature_blocks;            ///< The feature blocks which modulate the constraints on the output
} output_extended_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new Extended Output object.
 *
 * @param[in] address Deposit address (Ed25519, Alias or NFT address)
 * @param[in] amount The amount of IOTA tokens to held by the output
 * @param[in] tokens Set of native tokens held by the output
 * @param[in] feature_blocks Set of feature blocks
 *
 * @return output_extended_t* or NULL on failure
 */
output_extended_t* output_extended_new(void* address, uint64_t amount, native_tokens_t** tokens, void* feature_blocks);

/**
 * @brief Free Extended Output object.
 *
 * @param[in] oe Extended Output object.
 */
void output_extended_free(output_extended_t* oe);

/**
 * @brief Get the length of a serialized Extended Output
 *
 * @param[in] oe Extended Output object.
 * @return size_t The number of bytes of serialized data
 */
size_t output_extended_serialize_length(output_extended_t* oe);

/**
 * @brief Serialize Extended Output to a buffer
 *
 * @param[in] oe Extended Output object.
 * @param[out] buf A buffer holds the serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t output_extended_serialize(output_extended_t* oe, byte_t buf[]);

#ifdef __cplusplus
}
#endif

#endif
