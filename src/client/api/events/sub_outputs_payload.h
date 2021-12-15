// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_ADDRESS_OUTPUTS_H__
#define __SUB_ADDRESS_OUTPUTS_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/events/node_event.h"
#include "client/api/message.h"

// output id = transaction id(64) + output index(4)
#define OUTPUT_ID_LEN 68

/**
 * @brief The output object of the response
 *
 */
typedef struct {
  uint32_t output_type;  ///< The output type
  uint64_t amount;       ///< The amount of the output
  char addr[65];         ///< A hex string of the ed25519 address
} event_output_t;

/**
 * @brief The structure for outputs payload response
 *
 */
typedef struct {
  char msg_id[API_MSG_ID_HEX_STR_LEN];  ///< The hex encoded message ID of the message.
  char tx_id[API_TX_ID_HEX_STR_LEN];    ///< The hex encoded transaction id from which this output originated.
  uint16_t output_index;                ///< The index of the output.
  bool is_spent;                        ///< Whether this output is spent.
  uint64_t ledger_index;                ///< The ledger(milestone) index at which this output was available at.
  event_output_t output;                ///< The output object with output type, amount and address.
} event_outputs_payload_t;

/**
 * @brief Subscribes addresses/{address}/outputs event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] addr An address string
 * @param[in] is_bech32 The address type, true: Bech32 address, false: ed25519 address
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_address_outputs(event_client_handle_t client, int *mid, char const addr[], bool is_bech32, int qos);

/**
 * @brief Subscribes outputs/{outputId} event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] output_id An output Id
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_outputs_id(event_client_handle_t client, int *mid, char const output_id[], int qos);

/**
 * @brief Parse the outputs payload
 *
 * @param[in] data The string data of the response
 * @param[out] res The output payload object
 * @return int 0 If success
 */
int event_parse_outputs_payload(char const data[], event_outputs_payload_t *res);

#endif
