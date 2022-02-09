// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_MESSAGE_H__
#define __CLIENT_API_JSON_PARSER_MESSAGE_H__

#include "cJSON.h"
#include "core/models/message.h"

#ifdef __cplusplus
extern "C" {
#endif

int json_message_deserialize(cJSON* json_obj, core_message_t* msg);

cJSON* json_message_serialize(core_message_t* msg);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_MESSAGE_H__
