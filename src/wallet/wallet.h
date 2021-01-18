// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_WALLET_H__
#define __WALLET_WALLET_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/seed.h"
#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// max length of m/44'/4218'/Account'/Change'
#define IOTA_ACOUNT_PATH_MAX 128
#define IOTA_ENDPOINT_MAX_LEN 256
static char const* const iota_bip44_prefix = "m/44'/4218'";

typedef struct {
  byte_t seed[IOTA_SEED_BYTES];
  char account[IOTA_ACOUNT_PATH_MAX];  // store Bip44 Paths: m/44'/4128'/Account'/Change'
  char endpoint[IOTA_ENDPOINT_MAX_LEN];
  uint32_t port;
} iota_wallet_t;

/**
 * @brief Create a wallet account based on given seed and PIB44 path
 *
 * the path is an IOTA path of BIP-44 derivation paths
 * should be start with m/44'/4218'
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 *
 * @param[in] seed An IOTA seed
 * @param[in] path A string of BIP44 path
 * @return iota_wallet_t*
 */
iota_wallet_t* wallet_create(byte_t const seed[], char const path[]);

/**
 * @brief Set a node endpoint, default will use "http://localhost:14265/"
 *
 * @param[in] url The URL of the node
 * @param[in] port The port number of the node
 * @return int 0 on success
 */
int wallet_set_endpoint(iota_wallet_t* w, char const url[], uint32_t port);

int wallet_get_address(iota_wallet_t* w, uint64_t index, byte_t addr[]);

int wallet_get_balance(iota_wallet_t* w, uint64_t* balance);

int wallet_send(iota_wallet_t* w, uint64_t balance, char const index[], char const data[]);

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
