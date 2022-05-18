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
 * @param[in] sender_addr The sender address
 * @param[in] sender_keypair The sender private key
 * @param[in] send_amount The amount to transfer
 * @param[in] state_ctrl_addr The receiver address
 * @param[in] govern_addr The receiver address
 * @param[out] alias_addr The response of the transfer
 * @param[out] msg_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_alias_create_send(iota_wallet_t* w, address_t* sender_addr, ed25519_keypair_t* sender_keypair,
                             uint64_t const send_amount, address_t* state_ctrl_addr, address_t* govern_addr,
                             address_t* alias_addr, res_send_message_t* msg_res);

/**
 * @brief Send alias state transition transaction
 *
 * @param[in] w A wallet instance
 * @param[in] alias_id The alias identifier
 * @param[in] state_ctrl_addr The state controller address
 * @param[in] state_ctrl_keypair The state controller private key
 * @param[in] govern_addr The governor address
 * @param[out] msg_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_alias_state_transition_send(iota_wallet_t* w, byte_t alias_id[], address_t* state_ctrl_addr,
                                       ed25519_keypair_t* state_ctrl_keypair, address_t* govern_addr,
                                       res_send_message_t* msg_res);

/**
 * @brief Send transaction which destroys alias output
 *
 * @param[in] w A wallet instance
 * @param[in] alias_id The alias identifier
 * @param[in] govern_keypair The governor private key
 * @param[in] recv_addr The receiver address
 * @param[out] msg_res The response of the transfer
 *
 * @return int 0 on success
 */
int wallet_alias_destroy_send(iota_wallet_t* w, byte_t alias_id[], ed25519_keypair_t* govern_keypair,
                              address_t* recv_addr, res_send_message_t* msg_res);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_ALIAS_H__
