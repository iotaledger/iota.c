// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__
#define __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/types.h"
#include "core/utils/uint256.h"
#include "utlist.h"

// Native Token ID length in bytes
#define NATIVE_TOKEN_ID_BYTES 38
// Serialized bytes = token ID(38 bytes) + amount(uint256_t)
#define NATIVE_TOKENS_SERIALIZED_BYTES (NATIVE_TOKEN_ID_BYTES + 32)

/**
 * @brief Native Token structure
 *
 */
typedef struct {
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];  ///< Identifier of the Native Token
  uint256_t amount;                        ///< Amount of the Native Token
} native_token_t;

/**
 * @brief A list of Native Tokens
 *
 */
typedef struct native_tokens_list {
  native_token_t *token;            //< Points to a current Native Token
  struct native_tokens_list *next;  //< Points to a next Native Token
} native_tokens_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize Native Tokens list.
 *
 * @return native_tokens_list_t* a NULL pointer
 */
native_tokens_list_t *native_tokens_new();

/**
 * @brief Find Native Token by a given token ID.
 *
 * @param[in] nt Native Tokens list
 * @param[in] id Native Token ID to be searched
 * @return native_token_t*
 */
native_token_t *native_tokens_find_by_id(native_tokens_list_t *nt, byte_t id[]);

/**
 * @brief Get a number of Native Tokens in a list.
 *
 * @param[in] nt Native Tokens list
 * @return uint16_t
 */
uint8_t native_tokens_count(native_tokens_list_t *nt);

/**
 * @brief Free Native Tokens list.
 *
 * @param[in] nt Native Tokens list
 */
void native_tokens_free(native_tokens_list_t *nt);

/**
 * @brief Add Native Token to a Native Tokens list.
 *
 * @param[in] nt Native Tokens list
 * @param[in] token_id Identifier of Native Token
 * @param[in] amount A pointer to uint256 object
 * @return int 0 on success
 */
int native_tokens_add(native_tokens_list_t **nt, byte_t token_id[], uint256_t const *amount);

/**
 * @brief Compare two Native Tokens if they have the same ID.
 *
 * @param[in] token1 Pointer to Native Token
 * @param[in] token2 Pointer to Native Token
 * @return bool
 */
bool native_tokens_equal(native_token_t *token1, native_token_t *token2);

/**
 * @brief Get the length of Native Tokens serialized data
 *
 * @param[in] nt Native Tokens list
 * @return size_t The number of bytes of serialized data
 */
size_t native_tokens_serialize_len(native_tokens_list_t *nt);

/**
 * @brief Serialize Native Tokens to a buffer
 *
 * @param[in] nt Native Tokens list
 * @param[out] buf A buffer for serialization
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t native_tokens_serialize(native_tokens_list_t **nt, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a Native Token object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return native_tokens_list_t*
 */
native_tokens_list_t *native_tokens_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone Native Token list object, it should be freed after use.
 *
 * @param[in] nt Native Token list object for clone
 * @return native_tokens_list_t* New Native Token list object
 */
native_tokens_list_t *native_tokens_clone(native_tokens_list_t *const nt);

/**
 * @brief Print Native Tokens list.
 *
 * @param[in] nt Native Tokens list
 * @param[in] indentation Tab indentation when printing Native Tokens list
 */
void native_tokens_print(native_tokens_list_t *nt, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
