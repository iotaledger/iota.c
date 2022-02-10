// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_UNLOCK_BLOCK_H__
#define __CORE_MODELS_UNLOCK_BLOCK_H__

#include <stdint.h>
#include "core/types.h"
#include "crypto/iota_crypto.h"

// ed25519 signature block  = signature type + public key + signature
#define ED25519_SIGNATURE_BLOCK_BYTES (1 + ED_PUBLIC_KEY_BYTES + ED_SIGNATURE_BYTES)  // 97 bytes
// unlock_type_t + reference = 1 + 2
#define UNLOCK_REFERENCE_SERIALIZE_BYTES (1 + sizeof(uint16_t))
//  unlock_type_t + signature type + pub_key + signature
#define UNLOCK_SIGNATURE_SERIALIZE_BYTES (1 + ED25519_SIGNATURE_BLOCK_BYTES)
// unlock_type_t + alias index = 1 + 2
#define UNLOCK_ALIAS_SERIALIZE_BYTES (1 + sizeof(uint16_t))
// unlock_type_t + NFT index = 1 + 2
#define UNLOCK_NFT_SERIALIZE_BYTES (1 + sizeof(uint16_t))

/**
 * @brief Unlock block types that are supported by the protocol
 *
 */
typedef enum {
  UNLOCK_BLOCK_TYPE_SIGNATURE = 0,  ///< Denotes a signature unlock block
  UNLOCK_BLOCK_TYPE_REFERENCE = 1,  ///< Denotes a reference unlock block
  UNLOCK_BLOCK_TYPE_ALIAS = 2,      ///< Denotes a alias unlock block
  UNLOCK_BLOCK_TYPE_NFT = 3         ///< Denotes a NFT unlock block
} unlock_type_t;

/**
 * @brief An unlock block object which points to a consumed output
 *
 */
typedef struct {
  unlock_type_t type;  ///< 0 denotes a Signature Unlock Block, 1 denotes a Reference Unlock Block, 2 denotes an Alias
                       ///< Unlock Block, 3 denotes a NFT Unlock Block.
  void* block_data;    ///< A pointer to index or signature data
} unlock_block_t;

/**
 * @brief A list of unlock blocks
 *
 */
typedef struct unlock_list {
  unlock_block_t block;      ///< Represents an unlock block
  struct unlock_list* next;  ///< Points to next unlock block
} unlock_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize a unlock block list object
 *
 * @return unlock_list_t* a NULL pointer
 */
unlock_list_t* unlock_blocks_new();

/**
 * @brief Add unlock block to the list
 *
 * @param[in] blocks The head of list
 * @param[in] block An unlock block to be added to the list
 * @return int 0 on success
 */
int unlock_blocks_add(unlock_list_t** blocks, unlock_block_t* block);

/**
 * @brief Add an ed25519 signature unlock block
 *
 * @param[in] blocks The head of list
 * @param[in] sig An ed25519 signature unlock block
 * @param[in] sig_len The length of signature unlock block
 * @return int 0 on success
 */
int unlock_blocks_add_signature(unlock_list_t** blocks, byte_t* sig, size_t sig_len);

/**
 * @brief Add a reference unlock block
 *
 * @param[in] blocks The head of list
 * @param[in] index The index of reference unlock block
 * @return int 0 on success.
 */
int unlock_blocks_add_reference(unlock_list_t** blocks, uint16_t index);

/**
 * @brief Add an alias unlock block
 *
 * @param[in] blocks The head of list
 * @param[in] index The index of alias unlock block
 * @return int 0 on success.
 */
int unlock_blocks_add_alias(unlock_list_t** blocks, uint16_t index);

/**
 * @brief Add a NFT unlock block
 *
 * @param[in] blocks The head of list
 * @param[in] index The index of NFT unlock block
 * @return int 0 on success.
 */
int unlock_blocks_add_nft(unlock_list_t** blocks, uint16_t index);

/**
 * @brief Get the length of unlock blocks
 *
 * @param[in] blocks The head of list
 * @return uint16_t
 */
uint16_t unlock_blocks_count(unlock_list_t* blocks);

/**
 * @brief Get the pointer of block in the list
 *
 * @param[in] blocks A unlock block list
 * @param[in] index The index of block
 * @return unlock_block_t* A pointer to a block
 */
unlock_block_t* unlock_blocks_get(unlock_list_t* blocks, uint16_t index);

/**
 * @brief Get the unlock block index of a given public key
 *
 * @param[in] blocks The head of list
 * @param[in] pub_key A ed25519 public key
 * @return int32_t if not found return -1 else return the index
 */
int32_t unlock_blocks_find_pub(unlock_list_t* blocks, byte_t const* const pub_key);

/**
 * @brief Get the serialized length of unlocked blocks
 *
 * @param[in] blocks The head of list
 * @return size_t 0 on failed
 */
size_t unlock_blocks_serialize_length(unlock_list_t* blocks);

/**
 * @brief Serialize unlock blocks
 *
 * @param[in] blocks The head of list
 * @param[out] buf A buffer holds serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t unlock_blocks_serialize(unlock_list_t* blocks, byte_t buf[]);

/**
 * @brief Free an unlock block list
 *
 * @param[in] blocks An unlock block object
 */
void unlock_blocks_free(unlock_list_t* blocks);

/**
 * @brief Print out unlocked blocks object
 *
 * @param[in] blocks An unlock block object
 */
void unlock_blocks_print(unlock_list_t* blocks);

#ifdef __cplusplus
}
#endif

#endif
