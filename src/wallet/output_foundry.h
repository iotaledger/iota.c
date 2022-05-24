// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_FOUNDRY_H__
#define __WALLET_OUTPUT_FOUNDRY_H__

#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send mint native token transaction
 *
 * @param[in] w A wallet instance
 * @param[in] alias_addr The alias address
 * @param[in] state_ctrl_change The state controller change index which is {0, 1}, also known as wallet chain
 * @param[in] state_ctrl_index The state controller address index
 * @param[in] govern_addr The governor address
 * @param[in] max_supply The maximum supply of newly minted native tokens
 * @param[in] minted_tokens The number of newly minted native tokens
 * @param[in] serial_number The serial number of new foundry
 * @param[in] foundry_counter The foundry counter number
 * @param[in] receiver_addr The receiver address to which newly minted native tokens will be transferred
 * @param[out] msg_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_foundry_output_mint_native_tokens(iota_wallet_t* w, address_t* alias_addr, bool state_ctrl_change,
                                             uint32_t state_ctrl_index, address_t* govern_addr, uint256_t* max_supply,
                                             uint256_t* minted_tokens, uint32_t serial_number, uint32_t foundry_counter,
                                             address_t* receiver_addr, res_send_message_t* msg_res);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_FOUNDRY_H__
