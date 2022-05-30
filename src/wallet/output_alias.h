// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_ALIAS_H__
#define __WALLET_OUTPUT_ALIAS_H__

#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send transaction which creates a new alias output
 *
 * @param[in] w A wallet instance
 * @param[in] sender_change The sender change index which is {0, 1}, also known as wallet chain
 * @param[in] sender_index The sender address index
 * @param[in] send_amount The amount to transfer
 * @param[in] state_ctrl_addr The receiver address
 * @param[in] govern_addr The receiver address
 * @param[in] foundry_counter The foundry counter
 * @param[out] alias_addr The response of the transfer
 * @param[out] blk_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_alias_output_create(iota_wallet_t* w, bool sender_change, uint32_t sender_index, uint64_t const send_amount,
                               address_t* state_ctrl_addr, address_t* govern_addr, uint32_t foundry_counter,
                               address_t* alias_addr, res_send_block_t* blk_res);

/**
 * @brief Send alias state transition transaction
 *
 * @param[in] w A wallet instance
 * @param[in] alias_id The alias identifier
 * @param[in] state_ctrl_change The state controller change index which is {0, 1}, also known as wallet chain
 * @param[in] state_ctrl_index The state controller address index
 * @param[in] govern_addr The governor address
 * @param[in] foundry_counter The foundry counter number
 * @param[in] send_amount The amount to transfer
 * @param[in] outputs The outputs which will be created in a transaction
 * @param[out] blk_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_alias_output_state_transition(iota_wallet_t* w, byte_t alias_id[], bool state_ctrl_change,
                                         uint32_t state_ctrl_index, address_t* govern_addr, uint32_t foundry_counter,
                                         uint64_t send_amount, utxo_outputs_list_t* outputs,
                                         native_tokens_list_t* minted_tokens, res_send_block_t* blk_res);

/**
 * @brief Send transaction which destroys alias output
 *
 * @param[in] w A wallet instance
 * @param[in] alias_id The alias identifier
 * @param[in] govern_change The governor change index which is {0, 1}, also known as wallet chain
 * @param[in] govern_index The governor address index
 * @param[in] recv_addr The receiver address
 * @param[out] blk_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_alias_output_destroy(iota_wallet_t* w, byte_t alias_id[], bool govern_change, uint32_t govern_index,
                                address_t* recv_addr, res_send_block_t* blk_res);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_ALIAS_H__
