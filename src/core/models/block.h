// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_BLOCK_H__
#define __CORE_MODELS_BLOCK_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/models/payloads/milestone.h"

typedef enum {
  CORE_BLOCK_PAYLOAD_DEPRECATED_0 = 0,
  CORE_BLOCK_PAYLOAD_DEPRECATED_1,
  CORE_BLOCK_PAYLOAD_INDEXATION,
  CORE_BLOCK_PAYLOAD_RECEIPT,
  CORE_BLOCK_PAYLOAD_TREASURY,
  CORE_BLOCK_PAYLOAD_TAGGED,
  CORE_BLOCK_PAYLOAD_TRANSACTION,
  CORE_BLOCK_PAYLOAD_MILESTONE,
  CORE_BLOCK_PAYLOAD_UNKNOWN = UINT32_MAX - 1,
} core_block_payload_type_t;

/**
 * @brief A block object
 *
 */
typedef struct {
  uint8_t protocol_version;  ///< Protocol version number of block.
  UT_array* parents;         ///< Parents of this block.
  uint32_t payload_type;     ///< Payload type, one of core_block_payload_type_t
  void* payload;             ///< Payload object, NULL is no payload.
  uint64_t nonce;            ///< The nonce which lets this block fulfill the Proof-of-Work requirement.
} core_block_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a core block object
 *
 * @param[in] ver A protocol version
 * @return core_block_t*
 */
core_block_t* core_block_new(uint8_t ver);

/**
 * @brief Calculate a transaction essence hash
 *
 * @param[in] blk A block with transaction payload
 * @param[out] essence_hash Calculated essence hash
 * @param[in] essence_hash_len Length of an essence hash array
 * @return int 0 on success
 */
int core_block_essence_hash_calc(core_block_t* blk, byte_t essence_hash[], uint8_t essence_hash_len);

/**
 * @brief Free a core block object
 *
 * @param[in] blk block object
 */
void core_block_free(core_block_t* blk);

/**
 * @brief Add a parent to the block
 *
 * @param[in] blk A block object
 * @param[in] blk_id A block ID
 */
void core_block_add_parent(core_block_t* blk, byte_t const blk_id[]);

/**
 * @brief Get the number of parent
 *
 * @param[in] blk A block object
 * @return size_t
 */
size_t core_block_parent_len(core_block_t* blk);

/**
 * @brief Gets a parent ID by a given index
 *
 * @param[in] blk A block object
 * @param[in] index A index of a block ID
 * @return byte_t* a pointer to the binary ID
 */
byte_t* core_block_get_parent_id(core_block_t* blk, size_t index);

/**
 * @brief Get the block payload type
 *
 * @param[in] blk The block object
 * @return core_block_payload_type_t
 */
core_block_payload_type_t core_block_get_payload_type(core_block_t* blk);

/**
 * @brief Get the length of a serialized core block
 *
 * @param[in] blk The block object
 * @return size_t The number of bytes of serialized data
 */
size_t core_block_serialize_len(core_block_t* blk);

/**
 * @brief Serialize core block to a buffer
 *
 * @param[in] blk The block object
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t core_block_serialize(core_block_t* blk, byte_t buf[], size_t buf_len);

/**
 * @brief Print out a core block
 *
 * @param[in] blk The block object
 * @param[in] indentation Tab indentation when printing core block
 */
void core_block_print(core_block_t* blk, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
