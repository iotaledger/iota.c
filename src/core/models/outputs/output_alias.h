// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_ALIAS_H__
#define __CORE_MODELS_OUTPUT_ALIAS_H__

#include <stdint.h>

#include "core/address.h"
#include "core/models/outputs/feat_blocks.h"
#include "core/models/outputs/native_tokens.h"
#include "core/types.h"
#include "core/utils/byte_buffer.h"

/**
 * @brief An output type which represents an alias account.
 *
 */
typedef struct {
  uint64_t amount;                       ///< The amount of IOTA tokens held by the output
  native_tokens_t* native_tokens;        ///< The native tokens held by the output
  byte_t alias_id[ADDRESS_ALIAS_BYTES];  ///< The identifier of this alias account
  address_t* st_ctl;           ///< State Controller, the entity which is allowed to control this alias account state
  address_t* gov_ctl;          ///< Governance Controller, the entity which is allowed to govern this alias account
  uint32_t state_index;        ///< The index of the state
  byte_buf_t* state_metadata;  ///< The state of the alias account which can only be mutated by the state controller
  uint32_t foundry_counter;    ///< The counter that denotes the number of foundries created by this alias account
  feat_blk_list_t* feature_blocks;  ///< The feature blocks which modulate the constraints on the output
} output_alias_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new Alias Output object.
 *
 * @param[in] amount The amount of IOTA tokens to held by the output
 * @param[in] tokens Set of native tokens held by the output
 * @param[in] alias_id The identifier of this alias account
 * @param[in] st_ctl State Controller, the entity which is allowed to control this alias account state
 * @param[in] gov_ctl Governance Controller, the entity which is allowed to govern this alias account
 * @param[in] state_index The index of the state
 * @param[in] metadata Arbitrary immutable binary data attached to this alias account
 * @param[in] metadata_len Length of metadata byte array
 * @param[in] foundry_counter The counter that denotes the number of foundries created by this alias account
 * @param[in] feat_blocks Set of feature blocks
 *
 * @return output_alias_t* or NULL on failure
 */
output_alias_t* output_alias_new(uint64_t amount, native_tokens_t* tokens, byte_t alias_id[], address_t* st_ctl,
                                 address_t* gov_ctl, uint32_t state_index, byte_t* metadata, uint32_t metadata_len,
                                 uint32_t foundry_counter, feat_blk_list_t* feat_blocks);

/**
 * @brief Free Alias Output object.
 *
 * @param[in] output Alias Output object.
 */
void output_alias_free(output_alias_t* output);

/**
 * @brief Get the length of a serialized Alias Output
 *
 * @param[in] output Alias Output object.
 * @return size_t The number of bytes of serialized data
 */
size_t output_alias_serialize_len(output_alias_t* output);

/**
 * @brief Serialize Alias Output to a buffer
 *
 * @param[in] output Alias Output object.
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t output_alias_serialize(output_alias_t* output, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a Alias Output object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return output_alias_t* or NULL on failure
 */
output_alias_t* output_alias_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print Alias Output
 *
 * @param[in] output Alias Output object
 */
void output_alias_print(output_alias_t* output);

#endif
