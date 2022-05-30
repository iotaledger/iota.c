// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_BASIC_H__
#define __WALLET_OUTPUT_BASIC_H__

#include <stdint.h>

#include "client/api/restful/get_outputs_id.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/signing.h"
#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create and return a basic output
 *
 * @param[in] recv_addr A receiver address
 * @param[in] amount An amount to sent
 * @param[in] native_tokens A native tokens to sent
 *
 * @return output_basic_t* or NULL on failure
 */
output_basic_t* wallet_basic_output_create(address_t* recv_addr, uint64_t amount, native_tokens_list_t* native_tokens);

/**
 * @brief Get all senders unspent basic output IDs from a network
 *
 * @param[in] w A wallet instance
 * @param[in] send_addr A sender address
 *
 * @return res_outputs_id_t* or NULL on failure
 */
res_outputs_id_t* wallet_get_unspent_basic_output_ids(iota_wallet_t* w, address_t* send_addr);

/**
 * @brief Send basic transaction which transfers IOTA tokens to an address
 *
 * @param[in] w A wallet instance
 * @param[in] sender_change A sender change index which is {0, 1}, also known as a wallet chain
 * @param[in] sender_index A sender address index
 * @param[in] send_amount An amount to sent
 * @param[in] send_native_tokens A native tokens to sent
 * @param[in] recv_addr A receiver address
 * @param[out] blk_res A response of a block transfer
 *
 * @return int 0 on success
 */
int wallet_basic_output_send(iota_wallet_t* w, bool sender_change, uint32_t sender_index, uint64_t send_amount,
                             native_tokens_list_t* send_native_tokens, address_t* recv_addr, res_send_block_t* blk_res);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_BASIC_H__
