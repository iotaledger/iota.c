// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_BASIC_H__
#define __WALLET_OUTPUT_BASIC_H__

#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"
#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Transfer IOTA token to an address
 *
 * @param[in] w A wallet instance
 * @param[in] change The change index which is {0, 1}, also known as wallet chain.
 * @param[in] index The index of the sender address
 * @param[in] recv_addr The receiver address
 * @param[in] send_amount The amount to transfer
 * @param[out] msg_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_send_basic_output(iota_wallet_t* w, bool change, uint32_t index, address_t* recv_addr,
                             uint64_t const send_amount, res_send_message_t* msg_res);

/**
 * @brief Get unspent basic outputs from a network and add them into a transaction essence
 *
 * @param[in] w A wallet instance
 * @param[in] send_addr A sender address
 * @param[in] sender_key A sender private key
 * @param[in] send_amount An amount to transfer
 * @param[out] essence Transaction essence to add unspent basic outputs into it.
 * @param[out] sign_data A
 * @param[out] total_output_amount A
 *
 * @return int 0 on success
 */
utxo_outputs_list_t* wallet_get_unspent_basic_outputs(iota_wallet_t* w, address_t* send_addr,
                                                      ed25519_keypair_t* sender_key, uint64_t send_amount,
                                                      transaction_essence_t* essence, signing_data_list_t** sign_data,
                                                      uint64_t* total_output_amount);

/**
 * @brief Create a basic output and add it into a transaction essence
 *
 * @param[in] recv_addr A receiver address
 * @param[in] amount An amount for basic output
 * @param[out] essence Transaction essence to add unspent basic outputs into it.
 *
 * @return int 0 on success
 */
int wallet_output_basic_create(address_t* recv_addr, uint64_t amount, transaction_essence_t* essence);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_BASIC_H__
