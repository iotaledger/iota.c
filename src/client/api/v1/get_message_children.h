
// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_MSG_CHILDREN_H__
#define __CLIENT_API_V1_MSG_CHILDREN_H__

#include <stdint.h>

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/models/message.h"
#include "core/types.h"

/**
 * @brief The message children object.
 *
 */
typedef struct {
  uint32_t max_results;                        ///< The maximum count of results that are returned by the node.
  uint32_t count;                              ///< The actual count of results that are returned.
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1];  ///< the hex encoded message ID string
  UT_array *children;                          ///< the hex encoded message IDs of the children of this message.
} msg_children_t;

/**
 * @brief The response of get message children API call
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;      ///< Error message if is_error is True
    msg_children_t *data;  ///< a response object if is_error is False
  } u;
} res_msg_children_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Allocates message children response
 * @return res_msg_children_t*
 */
res_msg_children_t *res_msg_children_new();

/**
 * @brief Frees a message children reponse object
 * @param[in] res A response object
 */
void res_msg_children_free(res_msg_children_t *res);

/**
 * @brief message children JSON deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object of message children
 * @return int 0 on success
 */
int deser_msg_children(char const *const j_str, res_msg_children_t *res);

/**
 * @brief Gets the number of children IDs
 *
 * @param res The message children response
 * @return size_t The number of children IDs
 */
size_t res_msg_children_len(res_msg_children_t *res);

/**
 * @brief Gets the children message ID by a given index
 *
 * @param res The children respose
 * @param index A index
 * @return char* The hex string of children message ID
 */
char *res_msg_children_get(res_msg_children_t *res, size_t index);

/**
 * @brief Gets message children from a given message ID
 *
 * @param[in] ctx IOTA Client conf
 * @param[in] msg_id A message ID string for query
 * @param[out] res A message children response
 * @return int 0 on success
 */
int get_message_children(iota_client_conf_t const *ctx, char const msg_id[], res_msg_children_t *res);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_V1_MSG_CHILDREN_H__
