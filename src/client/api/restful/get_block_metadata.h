// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_BLOCK_META_H__
#define __CLIENT_API_RESTFUL_BLOCK_META_H__

#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "client/constants.h"
#include "core/utils/macros.h"
#include "utarray.h"

/**
 * @brief Stores the block metadata object
 *
 */
typedef struct {
  char blk_id[BIN_TO_HEX_STR_BYTES(IOTA_BLOCK_ID_BYTES)];  ///< the hex encoded block ID string
  UT_array *parents;                                       ///< the parent block IDs
  char inclusion_state[32];       ///< the ledger inclusion state of the transaction payload, one of `noTransaction`,
                                  ///< `conflicting`, `included`
  bool is_solid;                  ///< whether the block is solid
  int8_t should_promote;          ///< whether the block should be promoted, optional
  int8_t should_reattach;         ///< whether the block should be reattached, optional
  uint32_t referenced_milestone;  ///< The milestone index that references this block, optional
  uint32_t milestone_idx;         ///< If this block represents a milestone this is the milestone index, optional
  uint8_t conflict_reason;        ///< a reason why the block has conflict, optional
} block_meta_t;

/**
 * @brief The response of get block metadata API call
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;    ///< Error message if is_error is True
    block_meta_t *meta;  ///< a response object if is_error is False
  } u;
} res_block_meta_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates block metadata object
 * @return block_meta_t*
 */
block_meta_t *metadata_new();

/**
 * @brief Frees a block metadata object
 * @param[in] meta A block_meta_t* object
 */
void metadata_free(block_meta_t *meta);

/**
 * @brief Allocates block metadata response
 * @return res_block_meta_t*
 */
res_block_meta_t *block_meta_new();

/**
 * @brief Frees a block metadata response object
 * @param[in] res A response object
 */
void block_meta_free(res_block_meta_t *res);

/**
 * @brief Parse a block metadata response
 * @param[in] data The response data to be parsed
 * @param[out] res The block metadata object
 * @return int 0 If success
 */
int parse_blocks_metadata(char const *const j_str, block_meta_t *res);

/**
 * @brief Message metadata JSON deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res A response object of block metadata
 * @return int 0 on success
 */
int block_meta_deserialize(char const *const j_str, res_block_meta_t *res);

/**
 * @brief Gets the number of parent blocks
 *
 * @param[in] res A metadata response
 * @return size_t A number of parent
 */
size_t block_meta_parents_count(block_meta_t *msg);

/**
 * @brief Gets the parent block ID by a given index
 *
 * @param[in] res A metadata response
 * @param[in] index An index
 * @return char* The string of parent block ID
 */
char *block_meta_parent_get(block_meta_t *msg, size_t index);

/**
 * @brief Gets block metadata from a given block ID
 *
 * @param[in] ctx The client configuration
 * @param[in] blk_id A block ID string for query
 * @param[out] res A block metadata response
 * @return int 0 on success
 */
int get_block_metadata(iota_client_conf_t const *ctx, char const blk_id[], res_block_meta_t *res);

/**
 * @brief Print a block metadata object
 *
 * @param[in] res res_block_meta_t*
 * @param[in] indentation Tab indentation when printing block children
 */
void print_block_metadata(res_block_meta_t *res, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_RESTFUL_BLOCK_META_H__
