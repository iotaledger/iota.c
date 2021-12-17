// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_EXTENDED_H__
#define __CORE_MODELS_OUTPUT_EXTENDED_H__

#include <stdint.h>

#include "core/address.h"
#include "core/models/outputs/feat_blocks.h"
#include "core/models/outputs/native_tokens.h"

/**
 * @brief An output type which can hold native tokens and feature blocks.
 *
 */
typedef struct {
  address_t* address;              ///< Deposit address
  uint64_t amount;                 ///< The amount of IOTA tokens to held by the output
  native_tokens_t* native_tokens;  ///< The native tokens held by the output
  feat_list_t* feature_blocks;     ///< The feature blocks which modulate the constraints on the output
} output_extended_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new Extended Output object.
 *
 * @param[in] addr Deposit address (Ed25519, Alias or NFT address)
 * @param[in] amount The amount of IOTA tokens to held by the output
 * @param[in] tokens Set of native tokens held by the output
 * @param[in] feat_blocks Set of feature blocks
 *
 * @return output_extended_t* or NULL on failure
 */
output_extended_t* output_extended_new(address_t* addr, uint64_t amount, native_tokens_t* tokens,
                                       feat_list_t* feat_blocks);

/**
 * @brief Free Extended Output object.
 *
 * @param[in] output Extended Output object.
 */
void output_extended_free(output_extended_t* output);

/**
 * @brief Get the length of a serialized Extended Output
 *
 * @param[in] output Extended Output object.
 * @return size_t The number of bytes of serialized data
 */
size_t output_extended_serialize_len(output_extended_t* output);

/**
 * @brief Serialize Extended Output to a binary data
 *
 * @param[in] output Extended Output object.
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return int 0 on success
 */
int output_extended_serialize(output_extended_t* output, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a Extended Output object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return output_extended_t*
 */
output_extended_t* output_extended_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print Extended Output.
 *
 * @param[in] output Extended Output object.
 */
void output_extended_print(output_extended_t* output);

#ifdef __cplusplus
}
#endif

#endif
