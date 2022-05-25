// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_BLOCKS_METADATA_H__
#define __SUB_BLOCKS_METADATA_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/events/node_event.h"
#include "core/models/message.h"
#include "core/utils/macros.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Subscribes message-metadata/{messageid} event
 *
 * @param[in] client The event client instance
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] msg_id A messsage id for the event
 * @param[in] qos A QoS level for the topic
 * @return int 0 If Success
 */
int event_subscribe_msg_metadata(event_client_handle_t client, int *mid, char const msg_id[], int qos);

#ifdef __cplusplus
}
#endif

#endif
