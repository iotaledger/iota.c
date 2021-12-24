// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_FOUNDRY_H__
#define __CORE_MODELS_OUTPUT_FOUNDRY_H__

#include <stdint.h>

#include "core/models/outputs/feat_blocks.h"
#include "core/models/outputs/native_tokens.h"
#include "core/utils/uint256.h"

// Token tag length in bytes
#define TOKEN_TAG_BYTES_LEN 12

/**
 * @brief Token schemes
 *
 */
typedef enum {
  SIMPLE_TOKEN_SCHEME = 0  // For now, only token scheme 0 is supported.
} token_scheme_e;

/**
 * @brief An output type which controls the supply of user defined native tokens.
 *
 */
typedef struct {
  address_t* address;                     ///< The alias controlling this foundry
  uint64_t amount;                        ///< The amount of IOTA tokens held by this output
  native_tokens_t* native_tokens;         ///< The native tokens held by this output
  uint32_t serial;                        ///< The serial number of the foundry
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];  ///< The tag which is always the last 12 bytes of the tokens generated by this
                                          ///< foundry
  uint256_t circ_supply;                  ///< The circulating supply of tokens controlled by this foundry
  uint256_t max_supply;                   ///< The maximum supply of tokens controlled by this foundry
  token_scheme_e token_scheme;            ///< The token scheme used by this foundry
  feat_blk_list_t* feature_blocks;        ///< The feature blocks which modulate the constrants on this output
} output_foundry_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new Foundry Output object.
 *
 * @param[in] addr The alias controlling the foundry
 * @param[in] amount The amount of IOTA tokens held by the output
 * @param[in] tokens The list of native tokens held by the output
 * @param[in] serial The serial number of the foundry
 * @param[in] token_tag The last 12 bytes of ID of the tokens
 * @param[in] circ_supply The circulating supply of tokens controlled by the foundry
 * @param[in] max_supply The maximum supply of tokens controlled by the foundry
 * @param[in] token_scheme The token scheme of the foundry
 * @param[in] feat_blocks Set of feature blocks
 *
 * @return output_foundry_t* or NULL on failure
 */
output_foundry_t* output_foundry_new(address_t* addr, uint64_t amount, native_tokens_t* tokens, uint32_t serial_num,
                                     byte_t token_tag[], uint256_t circ_supply, uint256_t max_supply,
                                     token_scheme_e token_scheme, feat_blk_list_t* feat_blocks);

/**
 * @brief Free Foundry Output object.
 *
 * @param[in] output Foundry Output object.
 */
void output_foundry_free(output_foundry_t* output);

/**
 * @brief Get the length of a serialized Foundry Output
 *
 * @param[in] output Foundry Output object.
 * @return size_t The number of bytes of serialized data
 */
size_t output_foundry_serialize_len(output_foundry_t* output);

/**
 * @brief Serialize Foundry Output to binary data
 *
 * @param[in] output Foundry Output object
 * @param[out] buf A buffer that holds the serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t The number of bytes written or 0 on errors
 */
size_t output_foundry_serialize(output_foundry_t* output, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a Foundry Output object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return output_foundry_t* or NULL on failure
 */
output_foundry_t* output_foundry_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print Foundry Output
 *
 * @param[in] output Foundry Output object
 */
void output_foundry_print(output_foundry_t* output);

#ifdef __cplusplus
}
#endif

#endif
