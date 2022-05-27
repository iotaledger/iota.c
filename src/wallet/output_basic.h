// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_BASIC_H__
#define __WALLET_OUTPUT_BASIC_H__

#include "core/models/outputs/output_basic.h"
#include "core/models/signing.h"
#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send basic transaction which transfers IOTA tokens to an address
 *
 * @param[in] w A wallet instance
 * @param[in] sender_change The sender change index which is {0, 1}, also known as wallet chain
 * @param[in] sender_index The sender address index
 * @param[in] send_amount The amount to transfer
 * @param[in] send_native_tokens The native tokens to transfer
 * @param[in] recv_addr The receiver address
 * @param[out] blk_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_basic_output_send(iota_wallet_t* w, bool sender_change, uint32_t sender_index, uint64_t send_amount,
                             native_tokens_list_t* send_native_tokens, address_t* recv_addr, res_send_block_t* blk_res);

/**
 * @brief Create and return basic output
 *
 * @param[in] recv_addr A receiver address
 * @param[in] amount An amount for basic output
 * @param[in] native_tokens The native tokens to transfer
 * @param[out] output_basic Newly created basic output
 *
 * @return output_basic_t* or NULL on failure
 */
output_basic_t* wallet_output_basic_create(address_t* recv_addr, uint64_t amount, native_tokens_list_t* native_tokens);

/**
 * @brief Collect inputs and create a remainder output if necessary
 *
 * @param[in] w A wallet instance
 * @param[in] essence A transaction essence to add all collected inputs
 * @param[in] send_addr A sender address
 * @param[in] send_amount An amount to transfer
 * @param[in] send_native_tokens The native tokens to transfer
 * @param[out] balance_sufficient Do collected inputs have enough balance of base tokens and native tokens
 * @param[out] inputs A list of all collected inputs for a transaction
 * @param[out] remainder A remainder basic output for a transaction
 *
 * @return int 0 on success
 */
int wallet_get_inputs_and_create_remainder(iota_wallet_t* w, transaction_essence_t* essence, address_t* send_addr,
                                           uint64_t send_amount, native_tokens_list_t* send_native_tokens,
                                           bool* balance_sufficient, utxo_outputs_list_t** inputs,
                                           output_basic_t** remainder);

/**
 * @brief Create signatures for all collected inputs
 *
 * @param[in] inputs A list of all collected inputs
 * @param[in] sender_key A sender private key
 * @param[out] sign_data A list of signing data
 *
 * @return int 0 on success
 */
int create_signatures_for_inputs(utxo_outputs_list_t* inputs, ed25519_keypair_t* sender_key,
                                 signing_data_list_t** sign_data);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_BASIC_H__
