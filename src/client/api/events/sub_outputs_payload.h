// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_ADDRESS_OUTPUTS_H__
#define __SUB_ADDRESS_OUTPUTS_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/events/node_event.h"
#include "client/api/json_parser/block.h"
#include "core/address.h"
#include "core/models/block.h"
#include "core/utils/macros.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Subscribes outputs/unlock/{condition}/{address} event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] unlock_condition Type of unlock condition of the output to look for. Allowed values:
 * "address", "storage-return", "expiration", "state-controller", "governor", "immutable-alias", "+"
 * @param[in] bech32_addr Bech32 encoded address
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_outputs_unlock_address(event_client_handle_t client, int *mid, char const *const unlock_condition,
                                     char const *const addr_bech32, int qos);

/**
 * @brief Subscribes outputs/unlock/{condition}/{address}/spent event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] unlock_condition Type of unlock condition of the output to look for. Allowed values:
 * "address", "storage-return", "expiration", "state-controller", "governor", "immutable-alias", "+"
 * @param[in] bech32_addr Bech32 encoded address
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_outputs_unlock_address_spent(event_client_handle_t client, int *mid, char const *const unlock_condition,
                                           char const *const addr_bech32, int qos);

/**
 * @brief Subscribes  outputs/aliases/{aliasId} event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] alias_id An alias id
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_outputs_alias_id(event_client_handle_t client, int *mid, char const alias_id[], int qos);

/**
 * @brief Subscribes  outputs/nfts/{nftId} event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] nft_id A nft id
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_outputs_nft_id(event_client_handle_t client, int *mid, char const nft_id[], int qos);

/**
 * @brief Subscribes  outputs/foundries/{foundryId} event
 *
 * @param[in] client The event client object
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] foundry_id A foundry id
 * @param[in] qos The QoS level to be used with the topic
 * @return int 0 If success
 */
int event_sub_outputs_foundry_id(event_client_handle_t client, int *mid, char const foundry_id[], int qos);

#ifdef __cplusplus
}
#endif

#endif
