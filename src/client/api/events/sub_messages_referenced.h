// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MESSAGES_REFERENCED_H__
#define __SUB_MESSAGES_REFERENCED_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/models/message.h"

/**
 * @brief Stores the message referenced response object
 *
 */
typedef struct {
  char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1];  ///< the hex encoded message ID string
  UT_array *parents;                           ///< the parent message IDs
  char inclusion_state[32];       ///< the ledger inclusion state of the transaction payload, one of `noTransaction`,
                                  ///< `conflicting`, `included`
  bool is_solid;                  ///< whether the message is solid
  bool should_promote;            ///< whether the message should be promoted
  bool should_reattach;           ///< whether the message should be reattached
  uint64_t referenced_milestone;  ///< The milestone index that references this message
} msg_referenced_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Parses messages referenced response object
 * @param[in] data Data to parse
 * @param[out] res Parsed response object
 * @return 0 if success
 */
int parse_messages_referenced(char *data, msg_referenced_t *res);

#ifdef __cplusplus
}
#endif

#endif