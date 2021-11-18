// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MESSAGES_REFERENCED_H__
#define __SUB_MESSAGES_REFERENCED_H__

#include <stdbool.h>
#include <stdint.h>

// Message ID in binary form
#define IOTA_MESSAGE_ID_BYTES 32
// Message ID in hex string form
#define IOTA_MESSAGE_ID_HEX_BYTES (IOTA_MESSAGE_ID_BYTES * 2)

// {
//   "messageId": "cf5f77d62285b9ed8d617729e9232ae346a328c1897f0939837198e93ec13e85",
//   "parentMessageIds": [
//     "d026f8b1c856d4e844cc734bbe095429fb880ec4d93f3ccffe3b292a7de17be7",
//     "cf5f77d62285b9ed8d617729e9232ae346a328c1897f0939837198e93ec13e85"
//   ],
//   "isSolid": true,
//   "referencedByMilestoneIndex": 242544,
//   "ledgerInclusionState": "noTransaction",
//   "shouldPromote": true,
//   "shouldReattach": false
// }

/**
 * @brief Stores timestamp and index
 *
 */
typedef struct {
  char timestamp;
  uint32_t index;
} messages_referenced_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates messages referenced response object
 * @return res_balance_t*
 */
messages_referenced_t *res_messages_referenced_new(void);

/**
 * @brief Frees a milestone latest object
 * @param[in] res A response object
 */
void res_messages_referenced_free(messages_referenced_t *res);

/**
 * @brief Allocates balance response object
 * @param[in] data Data to parse
 * @param[out] res Parsed response object
 * @return 0 if success
 */
int parse_messages_referenced(char *data, messages_referenced_t *res);

#ifdef __cplusplus
}
#endif

#endif