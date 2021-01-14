// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_MESSAGE_BUILDER_H__
#define __CLIENT_API_MESSAGE_BUILDER_H__

#include "core/models/message.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Serialize message object to a JSON string
 *
 * @param[in] msg A message object
 * @return char*
 */
char* message_to_json(core_message_t* msg);

#ifdef __cplusplus
}
#endif

#endif