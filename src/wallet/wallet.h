// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_WALLET_H__
#define __WALLET_WALLET_H__

/**
 * @brief A reference wallet application
 *
 * A reference wallet application for users to create there own wallet on demand.
 * This wallet implementation will not contain any storage mechanism which storage method could vary on devices.
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "client/client_service.h"
#include "core/address.h"
#include "core/models/message.h"
#include "core/seed.h"
#include "core/types.h"

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
  byte_t seed[64];              ///< the mnemonic seed of this wallet
  char bech32HRP[8];            ///< The Bech32 HRP of the network. `iota` for mainnet, `atoi` for testnet.
  iota_client_conf_t endpoint;  ///< IOTA node endpoint
} iota_wallet_t;

/**
 * @brief Create a wallet instance from the given mnemonic and password
 *
 * @param[in] ms A string of mnemonic, NULL for genrating a random mnemonic
 * @param[in] pwd A passphase for seed deivation
 * @return iota_wallet_t*
 */
iota_wallet_t* wallet_create(char const ms[], char const pwd[]);

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
 * @brief Get an ed25519 address from a given account, change, and index
 *
 * https://chrysalis.docs.iota.org/guides/dev_guide/#addresskey-space
 *
 * @param[in] w A wallet instance
 * @param[in] account The account index
 * @param[in] change The change index which is {0, 1}, also known as wallet chain.
 * @param[in] index Address index
 * @param[out] addr A buffer holds ed25519 address
 * @return int 0 on success
 */
int wallet_address_from_index(iota_wallet_t* w, uint32_t account, bool change, uint32_t index, byte_t addr[]);

int wallet_bech32_from_index(iota_wallet_t* w, uint32_t account, bool change, uint32_t index, char addr[]);

/**
 * @brief Get balance by a given address
 *
 * @param[in] w A wallet instance
 * @param[in] addr An address for query
 * @param[out] balance The balance of the address
 * @return int 0 on success
 */
int wallet_balance_by_address(iota_wallet_t* w, byte_t const addr[], uint64_t* balance);

/**
 * @brief Get address balance by a given index
 *
 * @param[in] w A wallet instance
 * @param[in] index The index of address
 * @param[out] balance The balance of the address
 * @return int 0 on success
 */
int wallet_balance_by_index(iota_wallet_t* w, uint32_t index, uint64_t* balance);

/**
 * @brief Send message to the Tangle
 *
 * @param[in] w A wallet instance
 * @param[in] sender_index The address index of this wallet
 * @param[in] receiver The receiver address in ed25519 format
 * @param[in] balance The balance to send
 * @param[in] index An optional indexation
 * @param[in] data An optional indexation data, it's ignored if the index parameter is NULL
 * @param[out] msg_id A buffer holds the message ID string that returned from the node.
 * @param[in] msg_id_len The length of msg_id buffer.
 * @return int 0 on success
 */
int wallet_send(iota_wallet_t* w, uint32_t sender_index, byte_t receiver[], uint64_t balance, char const index[],
                byte_t data[], size_t data_len, char msg_id[], size_t msg_id_len);

/**
 * @brief Destory the wallet account
 *
 * @param[in] w A wallet instance
 */
void wallet_destroy(iota_wallet_t* w);

/**
 * @brief Update bech32HRP from network
 *
 * @param[in] w A wallet instance
 * @return int 0 on success
 */
int wallet_update_bech32HRP(iota_wallet_t* w);

#ifdef __cplusplus
}
#endif

#endif
