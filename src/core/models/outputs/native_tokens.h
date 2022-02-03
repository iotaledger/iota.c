// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__
#define __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/types.h"
#include "core/utils/uint256.h"
#include "uthash.h"

// Native Token ID length in bytes
#define NATIVE_TOKEN_ID_BYTES 38

// Serialized bytes = token ID(38 bytes) + amount(uint256_t)
#define NATIVE_TOKENS_SERIALIZED_BYTES (NATIVE_TOKEN_ID_BYTES + 32)

/**
 * @brief Native Tokens is a set of Native Token
 *
 */
typedef struct {
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];  ///< Identifier of the Native Token
  uint256_t *amount;                       ///< Amount of Tokens. Pointer to uint256_t object
  UT_hash_handle hh;
} native_tokens_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize Native Tokens set.
 *
 * @return native_tokens_t* a NULL pointer
 */
static native_tokens_t *native_tokens_new() { return NULL; }

/**
 * @brief Find Native Token by a given token ID.
 *
 * @param[in] nt Native Tokens set
 * @param[in] id Native Token ID to be searched
 * @return native_tokens_t*
 */
static native_tokens_t *native_tokens_find_by_id(native_tokens_t **nt, byte_t id[]) {
  native_tokens_t *elm = NULL;
  HASH_FIND(hh, *nt, id, NATIVE_TOKEN_ID_BYTES, elm);
  return elm;
}

/**
 * @brief Get a number of Native Tokens in a set.
 *
 * @param[in] nt Native Tokens set
 * @return uint16_t
 */
static uint8_t native_tokens_count(native_tokens_t **nt) { return (uint8_t)HASH_COUNT(*nt); }

/**
 * @brief Free Native Tokens set.
 *
 * @param[in] nt Native Tokens set
 */
static void native_tokens_free(native_tokens_t **nt) {
  native_tokens_t *curr_elm, *tmp;
  HASH_ITER(hh, *nt, curr_elm, tmp) {
    HASH_DEL(*nt, curr_elm);
    if (curr_elm->amount) {
      free(curr_elm->amount);
    }
    free(curr_elm);
  }
}

/**
 * @brief Add Native Token to a Native Tokens set.
 *
 * @param[in] nt Native Tokens set
 * @param[in] token_id Identifier of Native Token
 * @param[in] amount A pointer to uint256 object
 * @return int 0 on success
 */
int native_tokens_add(native_tokens_t **nt, byte_t token_id[], uint256_t const *amount);

/**
 * @brief Compare two Native Tokens if they have the same ID.
 *
 * @param[in] token1 Pointer to Native Token
 * @param[in] token2 Pointer to Native Token
 * @return bool
 */
bool native_tokens_equal(native_tokens_t *token1, native_tokens_t *token2);

/**
 * @brief Get the length of Native Tokens serialized data
 *
 * @param[in] nt Native Tokens set
 * @return size_t The number of bytes of serialized data
 */
size_t native_tokens_serialize_len(native_tokens_t **nt);

/**
 * @brief Serialize Native Tokens to a buffer
 *
 * @param[in] nt Native Tokens set
 * @param[out] buf A buffer for serialization
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t native_tokens_serialize(native_tokens_t **nt, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a Native Token object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return native_tokens_t*
 */
native_tokens_t *native_tokens_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone Native Token set object, it should be freed after use.
 *
 * @param[in] nt Native Token set object for clone
 * @return native_tokens_t* New Native Token set object
 */
native_tokens_t *native_tokens_clone(native_tokens_t const *const nt);

/**
 * @brief Print Native Tokens set.
 *
 * @param[in] nt Native Tokens set
 * @param[in] indentation Tab indentation when printing Native Tokens set
 */
void native_tokens_print(native_tokens_t **nt, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
