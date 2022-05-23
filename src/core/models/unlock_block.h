// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_UNLOCK_BLOCK_H__
#define __CORE_MODELS_UNLOCK_BLOCK_H__

#include <stdint.h>

#include "core/utils/byte_buffer.h"
#include "crypto/iota_crypto.h"

/**
 * @brief Unlock types that are supported by the protocol
 *
 */
typedef enum {
  UNLOCK_SIGNATURE_TYPE = 0,  ///< Denotes a signature unlock
  UNLOCK_REFERENCE_TYPE = 1,  ///< Denotes a reference unlock
  UNLOCK_ALIAS_TYPE = 2,      ///< Denotes a alias unlock
  UNLOCK_NFT_TYPE = 3         ///< Denotes a NFT unlock
} unlock_type_t;

/**
 * @brief An unlock object which points to a consumed output
 *
 */
typedef struct {
  unlock_type_t type;  ///< The type of the unlock object
  void* obj;           ///< A pointer to an unlock object
} unlock_t;

/**
 * @brief A list of unlocks
 *
 */
typedef struct unlock_list {
  unlock_t current;          ///< Represents a current unlock
  struct unlock_list* next;  ///< Points to next unlock
} unlock_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize an unlock list object
 *
 * @return A NULL pointer
 */
unlock_list_t* unlock_list_new();

/**
 * @brief Add an unlock to the list
 *
 * @param[in] list The head of the unlock list
 * @param[in] block An unlock to be added to the list
 * @return int 0 on success
 */
int unlock_list_add(unlock_list_t** list, unlock_t* unlock);

/**
 * @brief Add an ed25519 signature unlock
 *
 * @param[in] list The head of list
 * @param[in] sig An ed25519 signature unlock
 * @param[in] sig_len The length of signature unlock
 * @return int 0 on success
 */
int unlock_list_add_signature(unlock_list_t** list, byte_t* sig, size_t sig_len);

/**
 * @brief Add a reference unlock
 *
 * @param[in] list The head of list
 * @param[in] index The index of reference unlock
 * @return int 0 on success.
 */
int unlock_list_add_reference(unlock_list_t** list, uint16_t index);

/**
 * @brief Add an alias unlock
 *
 * @param[in] list The head of list
 * @param[in] index The index of alias unlock
 * @return int 0 on success.
 */
int unlock_list_add_alias(unlock_list_t** list, uint16_t index);

/**
 * @brief Add a NFT unlock
 *
 * @param[in] list The head of list
 * @param[in] index The index of NFT unlock
 * @return int 0 on success.
 */
int unlock_list_add_nft(unlock_list_t** list, uint16_t index);

/**
 * @brief Get the length of unlock list
 *
 * @param[in] list The head of list
 * @return uint16_t
 */
uint16_t unlock_list_count(unlock_list_t* list);

/**
 * @brief Get the pointer of an unlock in the list
 *
 * @param[in] list An unlock list
 * @param[in] index The index of the unlock object
 * @return unlock_t* A pointer to an unlock
 */
unlock_t* unlock_list_get(unlock_list_t* list, uint16_t index);

/**
 * @brief Get the unlock index of a given public key
 *
 * @param[in] list The head of list
 * @param[in] pub_key A ed25519 public key
 * @return int32_t if not found return -1 else return the index
 */
int32_t unlock_list_find_pub(unlock_list_t* list, byte_t const* const pub_key);

/**
 * @brief Get the serialized length of an unlock list
 *
 * @param[in] list The head of list
 * @return size_t 0 on failed
 */
size_t unlock_list_serialize_length(unlock_list_t* list);

/**
 * @brief Serialize an unlock list
 *
 * @param[in] list The head of list
 * @param[out] buf A buffer holds serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t unlock_list_serialize(unlock_list_t* list, byte_t buf[]);

/**
 * @brief Deserialize a binary data to an unlock list object
 *
 * @param[in] buf The unlock list data in binary
 * @param[in] buf_len The length of the data
 * @return unlock_list_t* or NULL on failure
 */
unlock_list_t* unlock_list_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Free an unlock list
 *
 * @param[in] list An unlock list object
 */
void unlock_list_free(unlock_list_t* list);

/**
 * @brief Print out an unlock list list
 *
 * @param[in] list An unlock list
 * @param[in] indentation Tab indentation when printing unlock list
 */
void unlock_list_print(unlock_list_t* list, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
