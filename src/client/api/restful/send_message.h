// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_SEND_MSG_H__
#define __CLIENT_API_RESTFUL_SEND_MSG_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "client/constants.h"
#include "core/models/message.h"
#include "core/utils/macros.h"

/**
 * @brief The response of send block
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t* error;                                        ///< Error message if is_error is True
    char blk_id[BIN_TO_HEX_STR_BYTES(IOTA_BLOCK_ID_BYTES)];  ///< a block IDs string if is_error is False
  } u;
} res_send_block_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize the response of send_block
 *
 * @param[in] json_str The response string
 * @param[out] res The response object
 * @return int 0 on success
 */
int deser_send_block_response(char const* json_str, res_send_block_t* res);

/**
 * @brief Send block thought core block object
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] blk A Block object
 * @param[out] res An error or block ID
 * @return int 0 on success
 */
int send_core_block(iota_client_conf_t const* const conf, core_block_t* blk, res_send_block_t* res);

#ifdef __cplusplus
}
#endif

#endif
