// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__
#define __CORE_MODELS_OUTPUT_NATIVE_TOKENS_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/types.h"
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
  void *amount;                            ///< Amount of Tokens. Pointer to uint256_t object
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
static uint16_t native_tokens_count(native_tokens_t **nt) { return (uint16_t)HASH_COUNT(*nt); }

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
 * @param[in] amount Amount of tokens. Pointer to uint256_t object.
 * @return int 0 on success
 */
int native_tokens_add(native_tokens_t **nt, byte_t token_id[], void *amount);

/**
 * @brief Compare two Native Tokens if they have the same ID.
 *
 * @param[in] token1 Native Token
 * @param[in] token2 Native Token
 * @return bool
 */
bool native_tokens_equal(native_tokens_t *token1, native_tokens_t *token2);

/**
 * @brief Serialize Native Tokens to a buffer
 *
 * @param[in] nt Native Tokens set
 * @param[out] buf A buffer for serialization
 * @return size_t number of bytes write to the buffer
 */
size_t native_tokens_serialization(native_tokens_t **nt, byte_t buf[]);

/**
 * @brief Print Native Tokens set.
 *
 * @param[in] nt Native Tokens set
 */
void native_tokens_print(native_tokens_t **nt);

#ifdef __cplusplus
}
#endif

#endif
