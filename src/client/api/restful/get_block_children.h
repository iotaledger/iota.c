// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_BLOCK_CHILDREN_H__
#define __CLIENT_API_RESTFUL_BLOCK_CHILDREN_H__

#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "client/constants.h"
#include "core/utils/macros.h"
#include "utarray.h"

/**
 * @brief The block children object.
 *
 */
typedef struct {
  uint32_t max_results;  ///< The maximum count of results that are returned by the node.
  uint32_t count;        ///< The actual count of results that are returned.
  char blk_id[BIN_TO_HEX_STR_BYTES(IOTA_BLOCK_ID_BYTES)];  ///< the hex encoded block ID string
  UT_array *children;                                      ///< the hex encoded block IDs of the children of this block.
} block_children_t;

/**
 * @brief The response of get block children API call
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;        ///< Error message if is_error is True
    block_children_t *data;  ///< a response object if is_error is False
  } u;
} res_block_children_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Allocates block children response
 * @return res_block_children_t*
 */
res_block_children_t *res_block_children_new();

/**
 * @brief Frees a block children response object
 * @param[in] res A response object
 */
void res_block_children_free(res_block_children_t *res);

/**
 * @brief block children JSON deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res A response object of block children
 * @return int 0 on success
 */
int deser_block_children(char const *const j_str, res_block_children_t *res);

/**
 * @brief Gets the number of children IDs
 *
 * @param res The block children response
 * @return size_t The number of children IDs
 */
size_t res_block_children_len(res_block_children_t *res);

/**
 * @brief Gets the children block ID by a given index
 *
 * @param res The children response
 * @param index A index
 * @return char* The hex string of children block ID
 */
char *res_block_children_get(res_block_children_t *res, size_t index);

/**
 * @brief Gets block children from a given block ID
 *
 * @param[in] ctx The client configuration
 * @param[in] blk_id A block ID string for query
 * @param[out] res A block children response
 * @return int 0 on success
 */
int get_block_children(iota_client_conf_t const *ctx, char const blk_id[], res_block_children_t *res);

/**
 * @brief Print Message Children
 *
 * @param[in] res res_block_children_t*
 * @param[in] indentation Tab indentation when printing block children
 */
void print_block_children(res_block_children_t *res, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_RESTFUL_BLOCK_CHILDREN_H__
