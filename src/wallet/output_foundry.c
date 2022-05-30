// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/storage_deposit.h"
#include "wallet/output_alias.h"
#include "wallet/output_foundry.h"

int wallet_foundry_output_mint_native_tokens(iota_wallet_t* w, address_t* alias_addr, bool state_ctrl_change,
                                             uint32_t state_ctrl_index, address_t* govern_addr,
                                             address_t* receiver_addr, uint256_t* max_supply, uint256_t* minted_tokens,
                                             uint32_t serial_number, uint32_t foundry_counter,
                                             res_send_block_t* msg_res) {
  if (w == NULL || alias_addr == NULL || govern_addr == NULL || max_supply == NULL || minted_tokens == NULL ||
      receiver_addr == NULL || msg_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  uint256_t* melted_tokens = NULL;
  token_scheme_t* token_scheme = NULL;
  utxo_outputs_list_t* outputs = NULL;
  output_foundry_t* output_foundry = NULL;
  output_basic_t* output_basic = NULL;
  native_tokens_list_t* native_tokens = NULL;
  unlock_cond_list_t* unlock_conds = NULL;
  unlock_cond_t* unlock_addr = NULL;

  // there is no melted native tokens
  melted_tokens = uint256_from_str("0");
  if (!melted_tokens) {
    printf("[%s:%d] can not create melted tokens object\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create token scheme
  token_scheme = token_scheme_simple_new(minted_tokens, melted_tokens, max_supply);
  if (!token_scheme) {
    printf("[%s:%d] can not create token scheme object\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create Foundry Output
  output_foundry = output_foundry_new(alias_addr, 0, NULL, serial_number, token_scheme, NULL, 0, NULL, 0);
  if (!output_foundry) {
    printf("[%s:%d] can not create foundry output\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // calculate minimum storage deposit for Foundry Output and update output's amount
  uint64_t min_storage_deposit = calc_minimum_output_deposit(&w->byte_cost, OUTPUT_FOUNDRY, output_foundry);
  output_foundry->amount = min_storage_deposit;
  // printf("Storage deposit for foundry output: %" PRIu64 "\n", output_foundry->amount);

  outputs = utxo_outputs_new();
  if ((ret = utxo_outputs_add(&outputs, OUTPUT_FOUNDRY, output_foundry)) != 0) {
    printf("[%s:%d] can not add foundry output to a list\n", __func__, __LINE__);
    goto end;
  }

  // create new native tokens
  byte_t token_id[NATIVE_TOKEN_ID_BYTES] = {0};
  if ((ret = output_foundry_calculate_id(output_foundry, alias_addr, token_id, sizeof(token_id))) != 0) {
    printf("[%s:%d] can not calculate output foundry ID\n", __func__, __LINE__);
    goto end;
  }

  native_tokens = native_tokens_new();
  if ((ret = native_tokens_add(&native_tokens, token_id, minted_tokens)) != 0) {
    printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
    goto end;
  }

  // create Basic Output with address unlock condition
  unlock_conds = condition_list_new();
  unlock_addr = condition_addr_new(receiver_addr);
  if (!unlock_addr) {
    printf("[%s:%d] can not create address unlock condition object\n", __func__, __LINE__);
    goto end;
  }
  if ((ret = condition_list_add(&unlock_conds, unlock_addr)) != 0) {
    printf("[%s:%d] can not add address unlock condition to a list\n", __func__, __LINE__);
    goto end;
  }

  output_basic = output_basic_new(0, native_tokens, unlock_conds, NULL);
  if (!output_basic) {
    printf("[%s:%d] can not create basic output\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // calculate minimum storage deposit for Basic Output and update output's amount
  min_storage_deposit = calc_minimum_output_deposit(&w->byte_cost, OUTPUT_BASIC, output_basic);
  output_basic->amount = min_storage_deposit;
  // printf("Storage deposit for basic output: %" PRIu64 "\n", output_basic->amount);

  if ((ret = utxo_outputs_add(&outputs, OUTPUT_BASIC, output_basic)) != 0) {
    printf("[%s:%d] can not add foundry output to a list\n", __func__, __LINE__);
    goto end;
  }

  // send alias state transition transaction to mint new native tokens
  uint64_t amount = output_foundry->amount + output_basic->amount;
  if ((ret = wallet_alias_output_state_transition(w, alias_addr->address, state_ctrl_change, state_ctrl_index,
                                                  govern_addr, foundry_counter, amount, outputs, msg_res)) != 0) {
    printf("Sending block to the Tangle failed!\n");
    goto end;
  }

end:
  uint256_free(melted_tokens);
  token_scheme_free(token_scheme);
  utxo_outputs_free(outputs);
  output_foundry_free(output_foundry);
  output_basic_free(output_basic);
  native_tokens_free(native_tokens);
  condition_list_free(unlock_conds);
  condition_free(unlock_addr);
  return ret;
}
