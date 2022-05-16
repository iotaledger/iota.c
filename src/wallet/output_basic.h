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

// create basic unspent outputs
utxo_outputs_list_t* wallet_get_unspent_basic_outputs(iota_wallet_t* w, transaction_essence_t* essence,
                                                      ed25519_keypair_t* sender_key, address_t* send_addr,
                                                      uint64_t send_amount, signing_data_list_t** sign_data,
                                                      uint64_t* total_output_amount);

// create a receiver for a basic output
int wallet_output_basic_create(transaction_essence_t* essence, address_t* recv_addr, uint64_t amount);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_BASIC_H__
