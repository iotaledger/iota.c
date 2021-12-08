// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_SERIALIZED_OUTPUT_H__
#define __SUB_SERIALIZED_OUTPUT_H__

#include "client/api/events/node_event.h"

/**
 * @brief Subscribe to the topic transactions/{transactionId}/included_message
 *
 * @param[in] client The event client object
 * @param[in] mid if not NULL, mid will be set as the message id for the topic
 * @param[in] transaction_id A transacton id
 * @param[in] qos QoS level to be used with the topic
 * @return int return 0 if success
 */
int event_sub_txn_included_msg(event_client_handle_t client, int *mid, char const transaction_id[], int qos);

/**
 * @brief Subscribe to the topic messages/indexation/[index] for receiving messages with indexation payloads
 *
 * @param[in] client The event client object
 * @param[in] mid if not NULL, mid will be set as the message id for the topic
 * @param[in] index An index to listen for messages
 * @param[in] qos QoS level to be used with the topic
 * @return int return 0 if success
 */
int event_sub_msg_indexation(event_client_handle_t client, int *mid, char const index[], int qos);

#endif
