// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_UNLOCK_BLOCK_H__
#define __CORE_MODELS_UNLOCK_BLOCK_H__

#include <stdint.h>
#include "core/types.h"
#include "crypto/iota_crypto.h"

// ed25519 signature block  = signature type + public key + signature
#define ED25519_SIGNATURE_BLOCK_BYTES (1 + ED_PUBLIC_KEY_BYTES + ED_SIGNATURE_BYTES)  // 97 bytes
// unlock_block_t + reference = 1 + 2
#define UNLOCK_REFERENCE_SERIALIZE_BYTES (1 + sizeof(uint16_t))
//  unlock_block_t + signature type + pub_key + signature
#define UNLOCK_SIGNATURE_SERIALIZE_BYTES (1 + ED25519_SIGNATURE_BLOCK_BYTES)

/**
 * @brief An unlock block list object
 *
 */
typedef struct unlock_blocks {
  unlock_block_t type;         ///< 0 denotes a Signature Unlock Block, 1 denotes a Reference Unlock Block.
  uint16_t reference;          ///< Represents the index of a pervious unlock block
  byte_t* sig_block;           ///< signature type + public key + signature
  struct unlock_blocks* next;  ///< point to next block
} unlock_blocks_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize a unlock block list object
 *
 * @return unlock_blocks_t* a NULL pointer
 */
unlock_blocks_t* unlock_blocks_new();

/**
 * @brief Add an ed25519 signature block
 *
 * @param[in] blocks The head of list
 * @param[in] sig An ed25519 signature block
 * @param[in] sig_len The length of signature block
 * @return int 0 on success
 */
int unlock_blocks_add_signature(unlock_blocks_t** blocks, byte_t* sig, size_t sig_len);

/**
 * @brief Add a reference block
 *
 * @param[in] blocks The head of list
 * @param[in] ref The index of reference
 * @return int 0 on success.
 */
int unlock_blocks_add_reference(unlock_blocks_t** blocks, uint16_t ref);

/**
 * @brief Get the length of unlock blocks
 *
 * @param[in] blocks The head of list
 * @return uint16_t
 */
uint16_t unlock_blocks_count(unlock_blocks_t* blocks);

/**
 * @brief Get the block index of a given public key
 *
 * @param[in] blocks The head of list
 * @param[in] pub_key A ed25519 public key
 * @return int32_t if not found return -1 else retrun the index
 */
int32_t unlock_blocks_find_pub(unlock_blocks_t* blocks, byte_t const* const pub_key);

/**
 * @brief Get the serialized length of unlocked blocks
 *
 * @param[in] blocks The head of list
 * @return size_t 0 on failed
 */
size_t unlock_blocks_serialize_length(unlock_blocks_t* blocks);

/**
 * @brief Serialize unlock blocks
 *
 * @param[in] blocks The head of list
 * @param[out] buf A buffer holds serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t unlock_blocks_serialize(unlock_blocks_t* blocks, byte_t buf[]);

/**
 * @brief Free an unlock block list
 *
 * @param[in] blocks An unlock block object
 */
void unlock_blocks_free(unlock_blocks_t* blocks);

/**
 * @brief Print out unlocked blocks object
 *
 * @param[in] blocks An unlock block object
 */
void unlock_blocks_print(unlock_blocks_t* blocks);

#ifdef __cplusplus
}
#endif

#endif