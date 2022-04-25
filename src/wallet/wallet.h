// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_WALLET_H__
#define __WALLET_WALLET_H__

/**
 * @brief Simple wallet APIs
 *
 * A reference wallet implementation for users to create there own wallet.
 * This wallet implementation will not contain any storage mechanism which storage could vary on deferent devices.
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "client/api/restful/send_message.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/models/message.h"
#include "core/models/outputs/byte_cost_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODE_DEFAULT_HRP "iota"
#define NODE_DEFAULT_HOST "chrysalis-nodes.iota.org"
#define NODE_DEFAULT_PORT 443

/**
 * @brief IOTA wallet setting
 *
 */
typedef struct {
  byte_t seed[64];               ///< the mnemonic seed of this wallet
  char bech32HRP[8];             ///< The Bech32 HRP of the network. `iota` for mainnet, `atoi` for testnet.
  uint32_t account_index;        ///< wallet account index
  iota_client_conf_t endpoint;   ///< IOTA node endpoint
  uint8_t protocol_version;      ///< Network protocol version of the connected node
  uint64_t network_id;           ///< Network ID of the connected node
  byte_cost_config_t byte_cost;  ///< The byte cost configuration of the network
} iota_wallet_t;

/**
 * @brief Create a wallet instance from the given mnemonic, password, and account index
 *
 * @param[in] ms A string of mnemonic, NULL for genrating a random mnemonic
 * @param[in] pwd A passphase for seed deivation
 * @param[in] account_index The account index
 * @return iota_wallet_t*
 */
iota_wallet_t* wallet_create(char const ms[], char const pwd[], uint32_t account_index);

/**
 * @brief Set a node endpoint, if not calling this method default is "http://localhost:14265/"
 *
 * @param[in] w A wallet instance
 * @param[in] host The hostname of the node
 * @param[in] port The port number of the node
 * @param[in] use_tls if use TLS or not
 * @return int 0 on success
 */
int wallet_set_endpoint(iota_wallet_t* w, char const host[], uint16_t port, bool use_tls);

/**
 * @brief Get an ed25519 address from the given account, change, and index
 *
 * https://chrysalis.docs.iota.org/guides/dev_guide/#addresskey-space
 *
 * @param[in] w A wallet instance
 * @param[in] change The change index which is {0, 1}, also known as wallet chain.
 * @param[in] index Address index
 * @param[out] addr A buffer holds ed25519 address
 * @return int 0 on success
 */
int wallet_ed25519_address_from_index(iota_wallet_t* w, bool change, uint32_t index, address_t* out);

/**
 * @brief Get balance by a given address
 *
 * @param[in] w A wallet instance
 * @param[in] addr An address for query
 * @param[out] balance The balance of the address
 * @return int 0 on success
 */
int wallet_balance_by_address(iota_wallet_t* w, address_t* addr, uint64_t* balance);

/**
 * @brief Get balance by a given bech32 address
 *
 * @param[in] w A wallet instance
 * @param[in] bech32 A string of bech32 address
 * @param[in] balance The balance of the address
 * @return int 0 on success
 */
int wallet_balance_by_bech32(iota_wallet_t* w, char const bech32[], uint64_t* balance);

/**
 * @brief Unlock outputs of the given address index
 *
 * it unlocks expired Timelock and Expiration outputs
 *
 * @param[in w A wallet instance
 * @param[in] change The change index which is {0, 1}, also known as wallet chain.
 * @param[in] index Address index
 * @return int 0 on seccess
 */
int wallet_unlock_outputs(iota_wallet_t* w, bool change, uint32_t index);

/**
 * @brief Transfer IOTA token to an address
 *
 * @param[in] w A wallet instance
 * @param[in] change The change index which is {0, 1}, also known as wallet chain.
 * @param[in] index The index of the sender address
 * @param[in] recv_addr The receiver address
 * @param[in] amount The amount to transfer
 * @param[out] msg_res The response of the transfer
 *
 * @return int 0 on seccess
 */
int wallet_send_basic_outputs(iota_wallet_t* w, bool change, uint32_t index, address_t* recv_addr,
                              uint64_t const amount, res_send_message_t* msg_res);

// TODO, need to be defined
int wallet_create_native_token(iota_wallet_t* w, bool change, uint32_t index, byte_t token_id[], uint64_t amount);

// TODO, need to be defined
int wallet_send_native_token(iota_wallet_t* w, bool change, uint32_t index, char recv_bech32[], uint64_t amount);

/**
 * @brief Destory the wallet account
 *
 * @param[in] w A wallet instance
 */
void wallet_destroy(iota_wallet_t* w);

/**
 * @brief Update configurations of connected node
 *
 * @param[in] w A wallet instance
 * @return int 0 on success
 */
int wallet_update_node_config(iota_wallet_t* w);

#ifdef __cplusplus
}
#endif

#endif
