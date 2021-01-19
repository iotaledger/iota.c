// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_WALLET_H__
#define __WALLET_WALLET_H__

#include <stdint.h>
#include <stdlib.h>

#include "client/client_service.h"
#include "core/address.h"
#include "core/seed.h"
#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// max length of m/44'/4218'/Account'/Change'
#define IOTA_ACCOUNT_PATH_MAX 128
static char const* const iota_bip44_prefix = "m/44'/4218'";

typedef struct {
  byte_t seed[IOTA_SEED_BYTES];
  char account[IOTA_ACCOUNT_PATH_MAX];  // store Bip44 Paths: m/44'/4128'/Account'/Change'
  iota_client_conf_t endpoint;
} iota_wallet_t;

/**
 * @brief Create a wallet account based on given seed and PIB44 path
 *
 * The path is an IOTA path of BIP-44 derivation paths, it should start with m/44'/4218'
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 *
 * @param[in] seed An IOTA seed
 * @param[in] path A string of BIP44 path
 * @return iota_wallet_t*
 */
iota_wallet_t* wallet_create(byte_t const seed[], char const path[]);

/**
 * @brief Set a node endpoint, if not calling this method default is "http://localhost:14265/"
 *
 * @param w A wallet instance
 * @param[in] url The URL of the node
 * @param[in] port The port number of the node
 * @return int 0 on success
 */
int wallet_set_endpoint(iota_wallet_t* w, char const url[], uint16_t port);

/**
 * @brief Get an address by a given index
 *
 * @param[in] w A wallet instance
 * @param[in] index The index of the address, the index is limited by slip10 spec, the maximun is 2147483646 (1 << 31U).
 * @param[out] addr A buffer holds ed25519 address
 * @return int 0 on success
 */
int wallet_address_by_index(iota_wallet_t* w, uint64_t index, byte_t addr[]);

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
int wallet_balance_by_index(iota_wallet_t* w, uint64_t index, uint64_t* balance);

/**
 * @brief Send message to the Tangle
 *
 * @param[in] w A wallet instance
 * @param[in] addr A receiver address
 * @param[in] balance The balance to send
 * @param[in] index An optional indexation, NULL for a none-data message
 * @param[in] data An optional indexation data, ignore if index is NULL
 * @return int 0 on success
 */
int wallet_send(iota_wallet_t* w, byte_t addr[], uint64_t balance, char const index[], char const data[]);

/**
 * @brief Destory the wallet account
 *
 * @param[in] w A wallet instance
 */
void wallet_destroy(iota_wallet_t* w);

#ifdef __cplusplus
}
#endif

#endif
