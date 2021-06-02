// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_SEND_MSG_H__
#define __CLIENT_API_V1_SEND_MSG_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/message.h"
#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/models/message.h"
#include "core/types.h"

/**
 * @brief The response of send message
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t* error;                            ///< Error message if is_error is True
    char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1];  ///< a message IDs string if is_error is False
  } u;
} res_send_message_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize the response of send_message
 *
 * @param[in] json_str The response string
 * @param[out] res The response object
 * @return int 0 on success
 */
int deser_send_message_response(char const* json_str, res_send_message_t* res);

/**
 * @brief Serialize a indexation message
 *
 * @param[in] msg A message object
 * @param[out] buf A JSON string of the message object
 * @return int 0 on success
 */
int serialize_indexation(message_t* msg, byte_buf_t* buf);

/**
 * @brief Send out an indexation message
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] index The string of index
 * @param[in] data The string of data
 * @param[out] res The response object
 * @return int 0 on success
 */
int send_indexation_msg(iota_client_conf_t const* const conf, char const index[], char const data[],
                        res_send_message_t* res);

/**
 * @brief Send out a message object
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] msg A message object
 * @param[out] res The response object
 * @return int 0 on success
 */
int send_message(iota_client_conf_t const* const conf, message_t* msg, res_send_message_t* res);

/**
 * @brief Send message thought core message object
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] msg A core message
 * @param[out] res An error or message ID
 * @return int 0 on success
 */
int send_core_message(iota_client_conf_t const* const conf, core_message_t* msg, res_send_message_t* res);

#ifdef __cplusplus
}
#endif

#endif
