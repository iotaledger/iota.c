// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_ALIAS_H__
#define __CORE_MODELS_OUTPUT_ALIAS_H__

#include <stdint.h>

#include "core/address.h"
#include "core/models/outputs/feat_blocks.h"
#include "core/models/outputs/native_tokens.h"
#include "core/models/outputs/unlock_conditions.h"
#include "core/types.h"
#include "core/utils/byte_buffer.h"

/**
 * @brief The Alias account object
 *
 * Describes an alias account in the ledger that can be controlled by the state and governance controllers
 *
 */
typedef struct {
  uint64_t amount;                      ///< The amount of IOTA tokens held by the output
  native_tokens_list_t* native_tokens;  ///< The native tokens held by the output
  byte_t alias_id[ALIAS_ID_BYTES];      ///< The identifier of this alias account
  uint32_t state_index;        ///< A counter that must increase by 1 every time the alias is state transitioned
  byte_buf_t* state_metadata;  ///< Metadata that can only be changed by the state controller
  uint32_t foundry_counter;    ///< The counter that denotes the number of foundries created by this alias account
  cond_blk_list_t* unlock_conditions;  ///< Define how the output can be unlocked and spent
  feat_blk_list_t* feature_blocks;     ///< Define functionality of this output
  feat_blk_list_t* immutable_blocks;   ///< Immutable blocks are defined upon deployment of the UTXO state machine and
                                       ///< are not allowed to change in any future state transition
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
 * @param[in] state_index The index of the state
 * @param[in] metadata Arbitrary immutable binary data attached to this alias account
 * @param[in] metadata_len Length of metadata byte array
 * @param[in] foundry_counter The counter that denotes the number of foundries created by this alias account
 * @param[in] cond_blocks Set of unlock condition blocks
 * @param[in] feat_blocks Set of feature blocks
 * @param[in] immut_feat_blocks List of immutable feature blocks
 *
 * @return output_alias_t* or NULL on failure
 */
output_alias_t* output_alias_new(uint64_t amount, native_tokens_list_t* tokens, byte_t alias_id[], uint32_t state_index,
                                 byte_t* metadata, uint32_t metadata_len, uint32_t foundry_counter,
                                 cond_blk_list_t* cond_blocks, feat_blk_list_t* feat_blocks,
                                 feat_blk_list_t* immut_feat_blocks);

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
 * @brief Clone Alias Output object, it should be freed after use.
 *
 * @param[in] output Alias Output object for clone
 * @return output_alias_t* New Alias Output object
 */
output_alias_t* output_alias_clone(output_alias_t const* const output);

/**
 * @brief Print Alias Output
 *
 * @param[in] output Alias Output object
 * @param[in] indentation Tab indentation when printing Alias Output
 */
void output_alias_print(output_alias_t* output, uint8_t indentation);

/**
 * @brief Alias Output syntactic validation
 *
 * @param[in] output An Alias output object
 * @return true Valid
 * @return false Invalid
 */
bool output_alias_syntactic(output_alias_t* output);

#endif
