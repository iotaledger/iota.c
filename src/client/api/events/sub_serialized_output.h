// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_SERIALIZED_OUTPUT_H__
#define __SUB_SERIALIZED_OUTPUT_H__

#include "client/api/events/node_event.h"
#include "core/utils/byte_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Subscribes transactions/{transactionId}/included_block topic
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] transaction_id A transacton id
 * @param[in] qos The QoS level for the topic
 * @return int 0 If success
 */
int event_sub_txn_included_blk(event_client_handle_t client, int *mid, char const transaction_id[], int qos);

/**
 * @brief Subscribes blocks/transaction/tagged-data/{tag} topic for receiving transaction blocks with {tag}
 *
 * @param[in] client The event client object
 * @param[in] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] tag A tag to get transaction blocks
 * @param[in] tag_len The length of the tag in bytes
 * @param[in] qos The QoS level for the topic
 * @return int 0 If success
 */
int event_sub_tx_blk_tagged_data(event_client_handle_t client, int *mid, byte_t tag[], uint8_t tag_len, int qos);

/**
 * @brief Subscribes blocks/tagged-data/{tag} topic for receiving blocks with {tag}
 *
 * @param[in] client The event client object
 * @param[in] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] tag A tag to get blocks
 * @param[in] tag_len The length of the tag in bytes
 * @param[in] qos The QoS level for the topic
 * @return int 0 If success
 */
int event_sub_blk_tagged_data(event_client_handle_t client, int *mid, byte_t tag[], uint8_t tag_len, int qos);

#ifdef __cplusplus
}
#endif

#endif
