// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_FOUNDRY_H__
#define __CORE_MODELS_OUTPUT_FOUNDRY_H__

#include <stdint.h>

#include "core/models/outputs/features.h"
#include "core/models/outputs/native_tokens.h"
#include "core/models/outputs/unlock_conditions.h"
#include "core/utils/uint256.h"

/**
 * @brief Token scheme types
 *
 */
typedef enum {
  SIMPLE_TOKEN_SCHEME = 0  // For now, only token scheme 0 is supported.
} token_scheme_e;

/**
 * @brief Simple token scheme
 *
 */
typedef struct {
  uint256_t minted_tokens;  ///< The amount of tokens minted by this foundry.
  uint256_t melted_tokens;  ///< The amount of tokens melted by this foundry.
  uint256_t max_supply;     ///< The maximum supply of tokens controlled by this foundry.
} token_scheme_simple_t;

/**
 * @brief A token scheme
 *
 */
typedef struct {
  token_scheme_e type;  ///< For now, only simple token scheme is supported.
  void* token_scheme;   ///< Pointer to a token scheme
} token_scheme_t;

/**
 * @brief An output type which controls the supply of user defined native tokens.
 *
 */
typedef struct {
  uint64_t amount;                        ///< The amount of IOTA tokens held by this output
  native_tokens_list_t* native_tokens;    ///< The native tokens held by this output
  uint32_t serial;                        ///< The serial number of the foundry
  token_scheme_t* token_scheme;           ///< The token scheme used by this foundry
  unlock_cond_list_t* unlock_conditions;  ///< Define how the output can be unlocked and spent
  feature_list_t* features;               ///< The features which modulate the constraints on this output
  feature_list_t* immutable_features;  ///< Immutable Features are defined upon deployment of the UTXO state machine and
                                       ///< are not allowed to change in any future state transition
} output_foundry_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief New a simple token scheme
 *
 * @param[in] minted_tokens The amount of minted tokens
 * @param[in] melted_tokens The amount of melted tokens
 * @param[in] max_supply The maximum supply of tokens
 * @return token_scheme_t*
 */
token_scheme_t* token_scheme_simple_new(uint256_t* minted_tokens, uint256_t* melted_tokens, uint256_t* max_supply);

/**
 * @brief ake copy of a token scheme
 *
 * @param[in] scheme A token scheme
 * @return token_scheme_t*
 */
token_scheme_t* token_scheme_clone(token_scheme_t* scheme);

/**
 * @brief Get the serialize bytes of a token scheme
 *
 * @param[in] scheme A token scheme
 * @return size_t
 */
size_t token_scheme_serialize_len(token_scheme_t* scheme);

/**
 * @brief Serialize a token scheme
 *
 * @param[in] scheme A token scheme object
 * @param[in] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t token_scheme_serialize(token_scheme_t* scheme, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a token scheme serialized data
 *
 * @param[in] buf A buffer holding serialized token scheme
 * @param[in] buf_len The length of the buffer
 * @return token_scheme_t*
 */
token_scheme_t* token_scheme_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Token scheme syntactic validation
 *
 * @param[in] output A token scheme object
 * @return true Valid
 * @return false Invalid
 */
bool token_scheme_syntactic(token_scheme_t* token_scheme);

/**
 * @brief Print token scheme
 *
 * @param[in] scheme A token scheme object
 * @param[in] indentation Tab indentation when printing Foundry Output
 */
void token_scheme_print(token_scheme_t* scheme, uint8_t indentation);

/**
 * @brief Free a token scheme object
 *
 * @param[in] scheme A token scheme object
 */
void token_scheme_free(token_scheme_t* scheme);

/**
 * @brief Create a Foundry Output object
 *
 * @param[in] alias An alias address controlling this foundry
 * @param[in] amount The amount of IOTA tokens held by this output
 * @param[in] tokens The list of native toktens held by this output
 * @param[in] serial_num The serial number
 * @param[in] token_scheme The token scheme
 * @param[in] meta The metadata
 * @param[in] meta_len The length of metadata
 * @param[in] immut_meta The immutable metadata
 * @param[in] immut_meta_len The length of immutable metadata
 * @return output_foundry_t*
 */
output_foundry_t* output_foundry_new(address_t* alias, uint64_t amount, native_tokens_list_t* tokens,
                                     uint32_t serial_num, token_scheme_t* token_scheme, byte_t meta[], size_t meta_len,
                                     byte_t immut_meta[], size_t immut_meta_len);

/**
 * @brief Free Foundry Output object.
 *
 * @param[in] output Foundry Output object.
 */
void output_foundry_free(output_foundry_t* output);

/**
 * @brief Calculate and return Foundry Output ID
 *
 * @param[in] output Foundry Output object
 * @param[in] addr An alias address
 * @param[out] id Calculated Foundry Output ID
 * @param[in] id_len Length of Foundry Output ID array
 * @return int 0 on success
 */
int output_foundry_calculate_id(output_foundry_t* output, address_t* addr, byte_t id[], uint8_t id_len);

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
 * @param[in] buf The foundry data in binary
 * @param[in] buf_len The length of the data
 * @return output_foundry_t* or NULL on failure
 */
output_foundry_t* output_foundry_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone Foundry Output object, it should be freed after use.
 *
 * @param[in] output Foundry Output object for clone
 * @return output_foundry_t* New Foundry Output object
 */
output_foundry_t* output_foundry_clone(output_foundry_t const* const output);

/**
 * @brief Print Foundry Output
 *
 * @param[in] output Foundry Output object
 * @param[in] indentation Tab indentation when printing Foundry Output
 */
void output_foundry_print(output_foundry_t* output, uint8_t indentation);

/**
 * @brief Foundry Output syntactic validation
 *
 * @param[in] output A Foundry Outout object
 * @return true Valid
 * @return false Invalid
 */
bool output_foundry_syntactic(output_foundry_t* output);

#ifdef __cplusplus
}
#endif

#endif
