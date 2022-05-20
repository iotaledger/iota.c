// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_BASIC_H__
#define __CORE_MODELS_OUTPUT_BASIC_H__

#include <stdint.h>

#include "core/address.h"
#include "core/models/outputs/feat_blocks.h"
#include "core/models/outputs/native_tokens.h"
#include "core/models/outputs/unlock_conditions.h"

/**
 * @brief An output type which can hold native tokens and features
 *
 */
typedef struct {
  uint64_t amount;                      ///< The amount of IOTA tokens to held by the output
  native_tokens_list_t* native_tokens;  ///< The native tokens held by the output
  cond_blk_list_t* unlock_conditions;   ///< Define how the output can be unlocked and spent
  feature_list_t* features;             ///< The features which modulate the constraints on the output
} output_basic_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new Basic Output object
 *
 * @param[in] amount The amount of IOTA tokens to held by the output
 * @param[in] tokens List of native tokens held by the output
 * @param[in] cond_blocks Set of unlock condition blocks
 * @param[in] features List of features
 *
 * @return output_basic_t* or NULL on failure
 */
output_basic_t* output_basic_new(uint64_t amount, native_tokens_list_t* tokens, cond_blk_list_t* cond_blocks,
                                 feature_list_t* features);

/**
 * @brief Free Basic Output object
 *
 * @param[in] output Basic Output object
 */
void output_basic_free(output_basic_t* output);

/**
 * @brief Get the length of a serialized Basic Output
 *
 * @param[in] output Basic Output object
 * @return size_t The number of bytes of serialized data
 */
size_t output_basic_serialize_len(output_basic_t* output);

/**
 * @brief Serialize Basic Output to a binary data
 *
 * @param[in] output Basic Output object
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t output_basic_serialize(output_basic_t* output, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a Basic Output object
 *
 * @param[in] buf The basic output data in binary
 * @param[in] buf_len The length of the data
 * @return output_basic_t* or NULL on failure
 */
output_basic_t* output_basic_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone Basic Output object, it should be freed after use.
 *
 * @param[in] output Basic Output object for clone
 * @return output_basic_t* New Basic Output object
 */
output_basic_t* output_basic_clone(output_basic_t const* const output);

/**
 * @brief Print Basic Output
 *
 * @param[in] output Basic Output object
 * @param[in] indentation Tab indentation when printing Basic Output
 */
void output_basic_print(output_basic_t* output, uint8_t indentation);

/**
 * @brief Basic Output syntactic validation
 *
 * @param[in] output A Basic output
 * @return true Valid
 * @return false Invalid
 */
bool output_basic_syntactic(output_basic_t* output);

#ifdef __cplusplus
}
#endif

#endif
