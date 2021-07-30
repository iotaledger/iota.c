// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_FIND_MSG_H__
#define __CLIENT_API_V1_FIND_MSG_H__

#include <stdbool.h>
#include <stdint.h>
#include "utarray.h"

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/types.h"

/**
 * @brief Stores message IDs from the response object
 *
 */
typedef struct {
  uint32_t max_results;  ///< The MAX results
  uint32_t count;        ///< The number of message IDs in this response
  UT_array *msg_ids;     ///< message IDs
} find_msg_t;

/**
 * @brief API response of find message
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;     ///< Error message if is_error is True
    find_msg_t *msg_ids;  ///< Message IDs if is_error is False
  } u;
} res_find_msg_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a response object of the find message API
 *
 * @return res_find_msg_t*
 */
res_find_msg_t *res_find_msg_new();

/**
 * @brief Free a find message response object
 *
 * @param[in] res The response object
 */
void res_find_msg_free(res_find_msg_t *res);

/**
 * @brief Get the number of message IDs from the response
 *
 * @param[in] res The response object
 * @return size_t
 */
size_t res_find_msg_get_id_len(res_find_msg_t *res);

/**
 * @brief Get the message ID from a given index
 *
 * @param[in] res The response object
 * @param[in] index A number of index
 * @return char* NULL if out of range
 */
char *res_find_msg_get_id(res_find_msg_t *res, size_t index);

/**
 * @brief Deserialize JSON response
 *
 * @param[in] j_str A JSON string
 * @param[in] res The response object
 * @return int 0 on success
 */
int deser_find_message(char const *const j_str, res_find_msg_t *res);

/**
 * @brief Find message IDs from a given indexation
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] index An indexation string
 * @param[out] res The response object
 * @return int 0 on success
 */
int find_message_by_index(iota_client_conf_t const *conf, char const index[], res_find_msg_t *res);

#ifdef __cplusplus
}
#endif

#endif
