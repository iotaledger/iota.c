// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_MESSAGE_H__
#define __CORE_MODELS_MESSAGE_H__

#include <stdint.h>
#include <stdlib.h>

#include "utarray.h"

#include "core/models/payloads/indexation.h"
#include "core/models/payloads/milestone.h"
#include "core/models/payloads/transaction.h"
#include "core/types.h"

// Message ID in binary form
#define IOTA_MESSAGE_ID_BYTES 32
// Message ID in hex string form
#define IOTA_MESSAGE_ID_HEX_BYTES (IOTA_MESSAGE_ID_BYTES * 2)

/**
 * @brief A message object
 *
 */
typedef struct {
  uint64_t network_id;  ///< Network identifier. It is first 8 bytes of the `BLAKE2b-256` hash of the concatenation of
                        ///< the network type and the protocol version string.
  UT_array* parents;    ///< parents of this message
  payload_t payload_type;  ///< payload type
  void* payload;           ///< payload object, NULL is no payload
  uint64_t nonce;          ///< The nonce which lets this message fulfill the Proof-of-Work requirement.
} core_message_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a core message object
 *
 * @return core_message_t*
 */
core_message_t* core_message_new();

/**
 * @brief Sign a transaction message
 *
 * @param[in] msg A message with transaction payload
 * @return int 0 on success
 */
int core_message_sign_transaction(core_message_t* msg);

/**
 * @brief Free a core message object
 *
 * @param[in] msg message object
 */
void core_message_free(core_message_t* msg);

/**
 * @brief Add a parent to the message
 *
 * @param[in] msg A message object
 * @param[in] msg_id A message ID
 */
void core_message_add_parent(core_message_t* msg, byte_t const msg_id[]);

/**
 * @brief Get the number of parent
 *
 * @param[in] msg A message object
 * @return size_t
 */
size_t core_message_parent_len(core_message_t* msg);

#ifdef __cplusplus
}
#endif

#endif
