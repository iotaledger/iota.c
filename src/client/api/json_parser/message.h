// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_MESSAGE_H__
#define __CLIENT_API_JSON_PARSER_MESSAGE_H__

#include "cJSON.h"
#include "core/models/message.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize a JSON object to message
 *
 * @param[in] json_obj A JSON object
 * @param[out] msg The output message object
 * @return int 0 on success
 */
int json_message_deserialize(cJSON* json_obj, core_message_t* msg);

/**
 * @brief Serialize a message to JSON object
 *
 * @param[in] msg A message object
 * @return cJSON* NULL on errors
 */
cJSON* json_message_serialize(core_message_t* msg);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_MESSAGE_H__
