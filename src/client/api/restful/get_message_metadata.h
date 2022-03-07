// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_MSG_META_H__
#define __CLIENT_API_RESTFUL_MSG_META_H__

#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/models/message.h"
#include "core/types.h"
#include "core/utils/macros.h"

/**
 * @brief Stores the message metadata object
 *
 */
typedef struct {
  char msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];  ///< the hex encoded message ID string
  UT_array *parents;                                         ///< the parent message IDs
  char inclusion_state[32];       ///< the ledger inclusion state of the transaction payload, one of `noTransaction`,
                                  ///< `conflicting`, `included`
  bool is_solid;                  ///< whether the message is solid
  int8_t should_promote;          ///< whether the message should be promoted, optional
  int8_t should_reattach;         ///< whether the message should be reattached, optional
  uint64_t referenced_milestone;  ///< The milestone index that references this message, optional
  uint64_t milestone_idx;         ///< If this message represents a milestone this is the milestone index, optional
} msg_meta_t;

/**
 * @brief The response of get message metadata API call
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;  ///< Error message if is_error is True
    msg_meta_t *meta;  ///< a response object if is_error is False
  } u;
} res_msg_meta_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Allocates message metadata response
 * @return res_msg_meta_t*
 */
res_msg_meta_t *msg_meta_new();

/**
 * @brief Frees a message metadata response object
 * @param[in] res A response object
 */
void msg_meta_free(res_msg_meta_t *res);

/**
 * @brief Message metadata JSON deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object of message metadata
 * @return int 0 on success
 */
int msg_meta_deserialize(char const *const j_str, res_msg_meta_t *res);

/**
 * @brief Gets the number of parent messages
 *
 * @param[in] res A metadata response
 * @return size_t A number of parent
 */
size_t msg_meta_parents_len(res_msg_meta_t *res);

/**
 * @brief Gets the parent message ID by a given index
 *
 * @param[in] res A metadata response
 * @param[in] index An index
 * @return char* The string of parent message ID
 */
char *msg_meta_parent_get(res_msg_meta_t *res, size_t index);

/**
 * @brief Gets message metadata from a given message ID
 *
 * @param[in] ctx IOTA Client conf
 * @param[in] msg_id A message ID string for query
 * @param[out] res A message metadata response
 * @return int 0 on success
 */
int get_message_metadata(iota_client_conf_t const *ctx, char const msg_id[], res_msg_meta_t *res);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_RESTFUL_MSG_META_H__
