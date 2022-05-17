// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_ALIAS_H__
#define __WALLET_OUTPUT_ALIAS_H__

#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

int wallet_alias_create_transaction(iota_wallet_t* w, address_t* sender_addr, ed25519_keypair_t* sender_keypair,
                                    uint64_t const send_amount, address_t* state_ctrl_addr, address_t* govern_addr,
                                    byte_t output_id[], res_send_message_t* msg_res);

int wallet_alias_state_transition_transaction(iota_wallet_t* w, byte_t alias_id[], byte_t output_id[],
                                              address_t* state_ctrl_addr, ed25519_keypair_t* state_ctrl_keypair,
                                              address_t* govern_addr, res_send_message_t* msg_res);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_ALIAS_H__
