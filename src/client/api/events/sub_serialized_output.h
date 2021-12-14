// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_SERIALIZED_OUTPUT_H__
#define __SUB_SERIALIZED_OUTPUT_H__

#include "client/api/events/node_event.h"

#define EVENT_MS_INDEX_MAX_LEN 64
#define EVENT_MS_INDEX_MIN_LEN 1
#define EVENT_TXN_ID_LEN 64

/**
 * @brief Subscribes transactions/{transactionId}/included_message topic
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] transaction_id A transacton id
 * @param[in] qos The QoS level for the topic
 * @return int 0 If success
 */
int event_sub_txn_included_msg(event_client_handle_t client, int *mid, char const transaction_id[], int qos);

/**
 * @brief Subscribes messages/indexation/{index} topic for receiving messages with indexation payloads
 *
 * @param[in] client The event client object
 * @param[in] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] index An index to get messages
 * @param[in] qos The QoS level for the topic
 * @return int 0 If success
 */
int event_sub_msg_indexation(event_client_handle_t client, int *mid, char const index[], int qos);

#endif
