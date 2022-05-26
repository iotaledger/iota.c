// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NFT_H__
#define __CORE_MODELS_OUTPUT_NFT_H__

#include <stdint.h>

#include "core/constants.h"
#include "core/models/outputs/features.h"
#include "core/models/outputs/native_tokens.h"
#include "core/models/outputs/unlock_conditions.h"
#include "core/utils/byte_buffer.h"

/**
 * @brief An output type used to implement non-fungible tokens.
 *
 */
typedef struct {
  uint64_t amount;                        ///< The amount of IOTA tokens held by this output
  native_tokens_list_t* native_tokens;    ///< The native tokens held by the output
  byte_t nft_id[NFT_ID_BYTES];            ///< The identifier of this NFT
  unlock_cond_list_t* unlock_conditions;  ///< Define how the output can be unlocked and spent
  feature_list_t* features;               ///< The features which modulate the constraints on the output
  feature_list_t* immutable_features;  ///< Immutable features are defined upon deployment of the UTXO state machine and
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
 * @param[in] cond_list Set of unlock conditions
 * @param[in] features List of features
 * @param[in] immut_features List of immutable features
 *
 * @return output_nft_t* or NULL on failure
 */
output_nft_t* output_nft_new(uint64_t amount, native_tokens_list_t* tokens, byte_t nft_id[],
                             unlock_cond_list_t* cond_list, feature_list_t* features, feature_list_t* immut_features);

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
 * @param[in] buf The NFT data in binary
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

#ifdef __cplusplus
}
#endif

#endif
