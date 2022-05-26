// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_WALLET_H__
#define __WALLET_WALLET_H__

/**
 * @brief Simple wallet APIs
 *
 * A reference wallet implementation for users to create there own wallet.
 * This wallet implementation will not contain any storage mechanism which storage could vary on different devices.
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "client/api/restful/send_block.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/models/block.h"
#include "core/models/outputs/byte_cost_config.h"
#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"

// max length of m/44'/4218'/Account'/Change' or m/44'/4219'/Account'/Change'
#define IOTA_ACCOUNT_PATH_MAX 128

// Registered coin types: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// default coin type for testnet (all coins)
#define SLIP44_COIN_TYPE_TEST 1
// default coin type for IOTA mainnet
#define SLIP44_COIN_TYPE_IOTA 4218
// default coin type for IOTA shimmer
#define SLIP44_COIN_TYPE_SHIMMER 4219

/**
 * @brief IOTA wallet setting
 *
 */
typedef struct {
  byte_t seed[64];               ///< the mnemonic seed of this wallet
  char bech32HRP[8];             ///< The Bech32 HRP of the network. `iota` for mainnet, `atoi` for testnet.
  uint32_t account_index;        ///< wallet account index
  uint32_t coin_type;            ///< the path component of SLIP44 coin type
  iota_client_conf_t endpoint;   ///< IOTA node endpoint
  uint8_t protocol_version;      ///< Network protocol version of the connected node
  uint64_t network_id;           ///< Network ID of the connected node
  byte_cost_config_t byte_cost;  ///< The byte cost configuration of the network
  char indexer_path[15];         ///< The indexer plugins api path, max len 15
} iota_wallet_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a wallet instance from the given mnemonic, password, and account index
 *
 * @param[in] ms A string of mnemonic, NULL for generating a random mnemonic
 * @param[in] pwd A passphrase for seed derivation
 * @param[in] coin_type The path component of SLIP44 coin type
 * @param[in] account_index The account index
 * @return iota_wallet_t*
 */
iota_wallet_t* wallet_create(char const ms[], char const pwd[], uint32_t coin_type, uint32_t account_index);

/**
 * @brief Destroy the wallet account
 *
 * @param[in] w A wallet instance
 */
void wallet_destroy(iota_wallet_t* w);

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
 * @brief Update configurations of connected node
 *
 * @param[in] w A wallet instance
 * @return int 0 on success
 */
int wallet_update_node_config(iota_wallet_t* w);

/**
 * @brief Get the address path
 *
 * @param[in] w A wallet object
 * @param[in] change change index which is {0, 1}, also known as wallet chain.
 * @param[in] index Address index
 * @param[out] buf The buffer holds BIP44 path
 * @param[in] buf_len the length of the buffer
 */
int wallet_get_address_path(iota_wallet_t* w, bool change, uint32_t index, char* buf, size_t buf_len);

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
int wallet_ed25519_address_from_index(iota_wallet_t* w, bool change, uint32_t index, address_t* addr);

/**
 * @brief Get an ed25519 address and keypair from the given account, change, and index
 *
 * https://chrysalis.docs.iota.org/guides/dev_guide/#addresskey-space
 *
 * @param[in] w A wallet instance
 * @param[in] change The change index which is {0, 1}, also known as wallet chain.
 * @param[in] index Address index
 * @param[out] addr A created ed25519 address
 * @param[out] keypair A created keypair
 * @return int 0 on success
 */
int wallet_get_address_and_keypair_from_index(iota_wallet_t* w, bool change, uint32_t index, address_t* addr,
                                              ed25519_keypair_t* keypair);

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
 * @param[out] balance The balance of the address
 * @return int 0 on success
 */
int wallet_balance_by_bech32(iota_wallet_t* w, char const bech32[], uint64_t* balance);

/**
 * @brief Create and prepare core block
 *
 * @param[in] w A wallet instance
 * @param[in] tx A transaction payload
 * @param[in] unspent_outputs A list of unspent outputs
 * @param[in] sign_data A list of signing data
 * @return core_block_t*
 */
core_block_t* wallet_create_core_block(iota_wallet_t* w, transaction_payload_t* tx,
                                       utxo_outputs_list_t* unspent_outputs, signing_data_list_t* sign_data);

/**
 * @brief Send core block to a network
 *
 * @param[in] w A wallet instance
 * @param[in] core_msg A core block which will be sent
 * @param[out] msg_res A response of the transfer
 * @return int 0 on success
 */
int wallet_send_block(iota_wallet_t* w, core_block_t* core_msg, res_send_block_t* msg_res);

#ifdef __cplusplus
}
#endif

#endif
