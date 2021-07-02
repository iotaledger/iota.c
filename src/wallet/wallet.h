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

// max length of m/44'/4218'/Account'/Change'
#define IOTA_ACCOUNT_PATH_MAX 128
#define NODE_DEFAULT_HOST "localhost"
#define NODE_DEFAULT_PORT 14265
static char const* const iota_bip44_prefix = "m/44'/4218'";

/**
 * @brief IOTA wallet setting
 *
 */
typedef struct {
  byte_t seed[IOTA_SEED_BYTES];         ///< the seed of this wallet
  char account[IOTA_ACCOUNT_PATH_MAX];  ///< store Bip44 Paths: m/44'/4128'/Account'/Change'
  char bech32HRP[8];                    ///< The Bech32 HRP of the network. `iota` for mainnet, `atoi` for testnet.
  iota_client_conf_t endpoint;          ///< IOTA node endpoint
} iota_wallet_t;

/**
 * @brief Create a wallet account based on given seed and PIB44 path
 *
 * The path is an IOTA path of BIP-44 derivation paths, it should start with m/44'/4218'
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 *
 * Since we don't have storage, the start and end index are for wallet to seek multiple outputs and addresses
 * As a reuse-address-wallet, start index could quale to end index.
 *
 * @param[in] seed An IOTA seed
 * @param[in] path A string of BIP44 path
 * @return iota_wallet_t* A pointer to a wallet instance
 */
iota_wallet_t* wallet_create(byte_t const seed[], char const path[]);

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
 * @brief Get an address by a given index
 *
 * @param[in] w A wallet instance
 * @param[in] index The index of the address, the index is limited by slip10 spec, the maximun is 2147483646 (1 << 31U).
 * @param[out] addr A buffer holds ed25519 address
 * @return int 0 on success
 */
int wallet_address_by_index(iota_wallet_t* w, uint32_t index, byte_t addr[]);

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
