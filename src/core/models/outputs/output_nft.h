// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NFT_H__
#define __CORE_MODELS_OUTPUT_NFT_H__

#include <stdint.h>

#include "core/address.h"
#include "core/models/outputs/feat_blocks.h"
#include "core/models/outputs/native_tokens.h"
#include "core/models/outputs/unlock_conditions.h"
#include "core/types.h"
#include "core/utils/byte_buffer.h"

/**
 * @brief An output type used to implement non-fungible tokens.
 *
 */
typedef struct {
  uint64_t amount;                     ///< The amount of IOTA tokens held by this output
  native_tokens_list_t* native_tokens;      ///< The native tokens held by the output
  byte_t nft_id[NFT_ID_BYTES];         ///< The identifier of this NFT
  cond_blk_list_t* unlock_conditions;  ///< Define how the output can be unlocked and spent
  feat_blk_list_t* feature_blocks;     ///< The feature blocks which modulate the constraints on the output
  feat_blk_list_t* immutable_blocks;   ///< Immutable blocks are defined upon deployment of the UTXO state machine and
                                       ///< are not allowed to change in any future state transition
} output_nft_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new NFT Output object.
 *
 * @param[in] amount The amount of IOTA tokens to held by the output
 * @param[in] tokens Set of native tokens held by the output
 * @param[in] nft_id The identifier of this NFT
 * @param[in] cond_blocks Set of unlock condition blocks
 * @param[in] feat_blocks List of feature blocks
 * @param[in] immut_feat_blocks List of immutable feature blocks
 *
 * @return output_nft_t* or NULL on failure
 */
output_nft_t* output_nft_new(uint64_t amount, native_tokens_list_t* tokens, byte_t nft_id[],
                             cond_blk_list_t* cond_blocks, feat_blk_list_t* feat_blocks,
                             feat_blk_list_t* immut_feat_blocks);

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
size_t output_nft_serialize_len(output_nft_t* output);

/**
 * @brief Serialize NFT Output to a buffer
 *
 * @param[in] output NFT Output object.
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t output_nft_serialize(output_nft_t* output, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a NFT Output object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return output_nft_t* or NULL on failure
 */
output_nft_t* output_nft_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone NFT Output object, it should be freed after use.
 *
 * @param[in] output NFT Output object for clone
 * @return output_nft_t* New NFT Output object
 */
output_nft_t* output_nft_clone(output_nft_t const* const output);

/**
 * @brief Print NFT Output
 *
 * @param[in] output NFT Output object
 * @param[in] indentation Tab indentation when printing NFT Output
 */
void output_nft_print(output_nft_t* output, uint8_t indentation);

/**
 * @brief NFT Output syntactic validation
 *
 * @param[in] output A NFT Output object
 * @return true Valid
 * @return false Invalid
 */
bool output_nft_syntactic(output_nft_t* output);

#endif
