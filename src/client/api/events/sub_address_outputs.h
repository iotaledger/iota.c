// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_ADDRESS_OUTPUTS_H__
#define __SUB_ADDRESS_OUTPUTS_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/events/node_event.h"

/**
 * @brief The output object in event
 *
 */
typedef struct {
  uint32_t output_type;  ///< the output type
  uint64_t amount;       ///< the amount of this output
  char addr[65];         ///< A hex string of the ed25519 address
} event_output_t;

/**
 * @brief The response of the event address outputs
 *
 */
typedef struct {
  char msg_id[API_MSG_ID_HEX_STR_LEN];  ///< The hex encoded message ID of the message.
  char tx_id[API_TX_ID_HEX_STR_LEN];    ///< The hex encoded transaction id from which this output originated.
  uint16_t output_index;                ///< The index of the output.
  bool is_spent;                        ///< Whether this output is spent.
  uint64_t ledger_index;                ///< The ledger(milestone) index at which this output was available at.
  event_output_t output;                ///< The output in its serialized form.
} event_addr_outputs_t;

/**
 * @brief Parse the response of address outputs
 *
 * @param[in] data The string data of the response
 * @param[out] res The address output object
 * @return int return 0 if success
 */
int event_parse_address_outputs(char const data[], event_addr_outputs_t *res);

/**
 * @brief Subscribe to the address outputs event
 *
 * @param[in] client The event client object
 * @param[in] mid if not NULL, mid will be set as the message id for the topic
 * @param[in] addr An address string
 * @param[in] is_bech32 the address type, true: Bech32 address, false: ed25519 address
 * @param[in] qos QoS level to be used with the topic
 * @return int return 0 if success
 */
int event_sub_address_outputs(event_client_handle_t client, int *mid, char const addr[], bool is_bech32, int qos);

#endif
