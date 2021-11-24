// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MESSAGES_METADATA_H__
#define __SUB_MESSAGES_METADATA_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/models/message.h"

/**
 * @brief Stores the message metadata response object
 *
 */
typedef struct {
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1];  ///< the hex encoded message ID string
  UT_array *parents;                           ///< the parent message IDs
  char inclusion_state[32];       ///< the ledger inclusion state of the transaction payload, one of `noTransaction`,
                                  ///< `conflicting`, `included`
  bool is_solid;                  ///< whether the message is solid
  bool should_promote;            ///< whether the message should be promoted, optional
  bool should_reattach;           ///< whether the message should be reattached, optional
  uint64_t referenced_milestone;  ///< The milestone index that references this message, optional
} msg_metadata_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates message metadata response
 * @return msg_metadata_t*
 */
msg_metadata_t *res_msg_metadata_new(void);

/**
 * @brief Frees a message metadata reponse object
 * @param[in] res A response object
 */
void res_msg_metadata_free(msg_metadata_t *res);

/**
 * @brief Gets the number of parent messages
 *
 * @param[in] res The message metadata response
 * @return size_t The number of parent message ids
 */
size_t res_msg_metadata_parents_len(msg_metadata_t *res);

/**
 * @brief Gets the parent message ID by a given index
 *
 * @param[in] res The message metadata respose
 * @param[in] index A index
 * @return char* The string of parent message ID
 */
char *res_msg_metadata_parent_get(msg_metadata_t *res, size_t index);

/**
 * @brief Parses message metadata response object
 * @param[in] data Data to parse
 * @param[out] res Parsed response object
 * @return 0 if success
 */
int parse_messages_metadata(char *data, msg_metadata_t *res);

#ifdef __cplusplus
}
#endif

#endif

