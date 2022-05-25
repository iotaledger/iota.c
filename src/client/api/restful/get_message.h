// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_GET_MSG_H__
#define __CLIENT_API_RESTFUL_GET_MSG_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/models/message.h"

/**
 * @brief The response of get block
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;   ///< Error message if is_error is True
    core_block_t *blk;  ///< a block object if is_error is False
  } u;
} res_block_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a block for API response
 *
 * @return res_block_t*
 */
res_block_t *res_block_new();

/**
 * @brief Free a block object
 *
 * @param[in] blk A block object
 */
void res_block_free(res_block_t *blk);

/**
 * @brief The block response deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res the block object
 * @return int 0 on success
 */
int deser_get_block(char const *const j_str, res_block_t *res);

/**
 * @brief Get the block data from a given block ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] blk_id A block ID to query
 * @param[out] res The block body of the given ID
 * @return int 0 on success
 */
int get_block_by_id(iota_client_conf_t const *conf, char const blk_id[], res_block_t *res);

#ifdef __cplusplus
}
#endif

#endif
