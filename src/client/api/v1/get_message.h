// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_GET_MSG_H__
#define __CLIENT_API_V1_GET_MSG_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/message.h"
#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/models/message.h"

/**
 * @brief The response of get message
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;  ///< Error message if is_error is True
    message_t *msg;    ///< a message object if is_error is False
  } u;
} res_message_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a message for API response
 *
 * @return res_message_t*
 */
res_message_t *res_message_new();

/**
 * @brief Free a message object
 *
 * @param[in] msg A message object
 */
void res_message_free(res_message_t *msg);

/**
 * @brief Get the message data from a given message ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] msg_id A message ID to query
 * @param[out] res The message body of the given ID
 * @return int 0 on success
 */
int get_message_by_id(iota_client_conf_t const *conf, char const msg_id[], res_message_t *res);

/**
 * @brief The message response deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res the message object
 * @return int 0 on success
 */
int deser_get_message(char const *const j_str, res_message_t *res);

/**
 * @brief Get the signature count in message
 *
 * @param[in] res The message object
 * @return size_t
 */
size_t get_message_milestone_signature_count(res_message_t const *const res);

/**
 * @brief Extra a signature string from message
 *
 * @param[in] res The message object
 * @param[in] index The index of signature
 * @return char* NULL on failed.
 */
char *get_message_milestone_signature(res_message_t const *const res, size_t index);

/**
 * @brief Get the message payload type
 *
 * @param[in] res The message object
 * @return msg_payload_type_t
 */
msg_payload_type_t get_message_payload_type(res_message_t const *const res);

#ifdef __cplusplus
}
#endif

#endif
