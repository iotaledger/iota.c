// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MESSAGES_METADATA_H__
#define __SUB_MESSAGES_METADATA_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/events/node_event.h"
#include "core/models/message.h"

#define MSG_ID_LEN 64

/**
 * @brief Stores the message metadata response object
 *
 */
typedef struct {
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1];  ///< The hex encoded message ID string
  UT_array *parents;                           ///< The parent message IDs
  char inclusion_state[32];       ///< The ledger inclusion state of the transaction payload, one of `noTransaction`,
                                  ///< `conflicting` or `included`
  bool is_solid;                  ///< Whether the message is solid
  bool should_promote;            ///< Whether the message should be promoted, optional
  bool should_reattach;           ///< Whether the message should be reattached, optional
  uint64_t referenced_milestone;  ///< The milestone index that references the message, optional
} msg_metadata_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Subscribes messages/{messageid}/metadata event
 *
 * @param[in] client The event client instance
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] msg_id A messsage id for the event
 * @param[in] qos A QoS level for the topic
 * @return int 0 If Success
 */
int event_subscribe_msg_metadata(event_client_handle_t client, int *mid, char const msg_id[], int qos);

/**
 * @brief Allocates a message metadata onject
 * @return msg_metadata_t*
 */
msg_metadata_t *res_msg_metadata_new(void);

/**
 * @brief Free a message metadata object
 * @param[in] res A message metadata object
 */
void res_msg_metadata_free(msg_metadata_t *res);

/**
 * @brief Parse a message metadata response
 * @param[in] data The response data to be parsed
 * @param[out] res The message metadata object
 * @return int 0 If success
 */
int parse_messages_metadata(char *data, msg_metadata_t *res);

/**
 * @brief Gets the count of parent message ids
 *
 * @param[in] res The message metadata object
 * @return size_t The count of parent message ids
 */
size_t res_msg_metadata_parents_count(msg_metadata_t *res);

/**
 * @brief Gets the parent message ID by a given index
 *
 * @param[in] res The message metadata object
 * @param[in] index An index
 * @return char* The parent message ID string
 */
char *res_msg_metadata_parent_get(msg_metadata_t *res, size_t index);

#ifdef __cplusplus
}
#endif

#endif
