// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLET_OUTPUT_ALIAS_H__
#define __WALLET_OUTPUT_ALIAS_H__

#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

int wallet_create_alias_output(iota_wallet_t* w, bool change, uint32_t index, uint64_t const send_amount,
                               address_t* state_ctrl_addr, address_t* govern_addr, res_send_message_t* msg_res,
                               byte_t alias_id[], byte_t alias_output_id[]);

int wallet_send_alias_output(iota_wallet_t* w, bool change, uint32_t index, uint64_t const send_amount,
                             byte_t alias_id[], address_t* state_ctrl_addr, address_t* govern_addr, byte_t output_id[],
                             res_send_message_t* msg_res);

#ifdef __cplusplus
}
#endif

#endif  // __WALLET_OUTPUT_ALIAS_H__
