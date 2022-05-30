// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/storage_deposit.h"
#include "wallet/output_basic.h"

static res_outputs_id_t* get_unspent_basic_output_ids(iota_wallet_t* w, address_t* send_addr) {
  if (w == NULL || send_addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  char send_addr_bech32[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(send_addr, w->bech32HRP, send_addr_bech32, sizeof(send_addr_bech32)) != 0) {
    printf("[%s:%d] address to bech32 conversion failed\n", __func__, __LINE__);
    return NULL;
  }

  outputs_query_list_t* query_param = outputs_query_list_new();
  if (outputs_query_list_add(&query_param, QUERY_PARAM_ADDRESS, send_addr_bech32) != 0) {
    printf("[%s:%d] add query params failed\n", __func__, __LINE__);
    outputs_query_list_free(query_param);
    return NULL;
  }

  res_outputs_id_t* res_id = res_outputs_new();
  if (res_id == NULL) {
    printf("[%s:%d] allocate outputs response failed\n", __func__, __LINE__);
    outputs_query_list_free(query_param);
    return NULL;
  }

  // query output IDs from indexer by bech32 address
  if (get_basic_outputs(&w->endpoint, INDEXER_API_PATH, query_param, res_id) != 0) {
    printf("[%s:%d] get output ID failed\n", __func__, __LINE__);
    outputs_query_list_free(query_param);
    res_outputs_free(res_id);
    return NULL;
  }

  if (res_id->is_error) {
    printf("[%s:%d] Err: %s\n", __func__, __LINE__, res_id->u.error->msg);
    outputs_query_list_free(query_param);
    res_outputs_free(res_id);
    return NULL;
  }

  outputs_query_list_free(query_param);

  return res_id;
}

static bool is_unspent_basic_output_useful(iota_wallet_t* w, output_basic_t* output, uint64_t send_amount,
                                           uint64_t collected_amount, uint64_t remainder_amount,
                                           native_tokens_list_t* send_native_tokens,
                                           native_tokens_list_t* collected_native_tokens,
                                           native_tokens_list_t* remainder_native_tokens) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // use unspent output if collected amount is lower than amount needed to be sent
  if (collected_amount < send_amount && output->amount > 0) {
    return true;
  }

  // is there any useful native tokens inside unspent output
  native_tokens_list_t* elm;
  LL_FOREACH(output->native_tokens, elm) {
    native_token_t* send_native_token = native_tokens_find_by_id(send_native_tokens, elm->token->token_id);
    native_token_t* collected_native_token = native_tokens_find_by_id(collected_native_tokens, elm->token->token_id);

    if (send_native_token) {
      if (!collected_native_token) {
        return true;
      }
      if (collected_native_token && uint256_equal(&send_native_token->amount, &collected_native_token->amount) > 0) {
        return true;
      }
    }
  }

  // if remainder is needed, check if there is enough base tokens for its minimum storage protection
  if (remainder_amount > 0 || native_tokens_count(remainder_native_tokens) > 0) {
    // create Basic Output with address unlock condition
    address_t remainder_addr = {0};
    output_basic_t* remainder_output =
        wallet_output_basic_create(&remainder_addr, remainder_amount, remainder_native_tokens);
    if (!remainder_output) {
      printf("[%s:%d] can not create a reminder basic output\n", __func__, __LINE__);
      return false;
    }

    // calculate minimum storage deposit for remainder output
    uint64_t min_storage_deposit = calc_minimum_output_deposit(&w->byte_cost, OUTPUT_BASIC, remainder_output);
    if (remainder_amount < min_storage_deposit) {
      output_basic_free(remainder_output);
      return true;
    }
    output_basic_free(remainder_output);
  }

  return false;
}

output_basic_t* wallet_output_basic_create(address_t* recv_addr, uint64_t amount, native_tokens_list_t* native_tokens) {
  if (recv_addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* unlock_cond_addr = condition_addr_new(recv_addr);
  if (!unlock_cond_addr) {
    printf("[%s:%d] unable to create address unlock condition\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_list_t* unlock_cond_blk = condition_list_new();
  if (condition_list_add(&unlock_cond_blk, unlock_cond_addr) != 0) {
    printf("[%s:%d] failed to add address unlock condition\n", __func__, __LINE__);
    condition_free(unlock_cond_addr);
    condition_list_free(unlock_cond_blk);
    return NULL;
  }

  output_basic_t* output_basic = output_basic_new(amount, native_tokens, unlock_cond_blk, NULL);
  if (!output_basic) {
    printf("[%s:%d] failed to create basic output\n", __func__, __LINE__);
    condition_free(unlock_cond_addr);
    condition_list_free(unlock_cond_blk);
    return NULL;
  }

  condition_free(unlock_cond_addr);
  condition_list_free(unlock_cond_blk);

  return output_basic;
}

int wallet_get_inputs_and_create_remainder(iota_wallet_t* w, transaction_essence_t* essence, address_t* send_addr,
                                           uint64_t send_amount, native_tokens_list_t* send_native_tokens,
                                           bool* balance_sufficient, utxo_outputs_list_t** inputs,
                                           output_basic_t** remainder) {
  if (w == NULL || essence == NULL || send_addr == NULL || *inputs != NULL || *remainder != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  res_outputs_id_t* res_ids = get_unspent_basic_output_ids(w, send_addr);
  if (!res_ids) {
    printf("[%s:%d] failed to get unspent basic output IDs\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  uint64_t collected_amount = 0;
  uint64_t remainder_amount = 0;
  native_tokens_list_t* collected_native_tokens = native_tokens_new();
  native_tokens_list_t* remainder_native_tokens = native_tokens_new();
  *inputs = utxo_outputs_new();
  *balance_sufficient = false;

  // fetch output data from output IDs
  for (size_t i = 0; i < res_outputs_output_id_count(res_ids); i++) {
    res_output_t* output_res = get_output_response_new();
    if (!output_res) {
      printf("[%s:%d] failed to create output response object\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }

    if (get_output(&w->endpoint, res_outputs_output_id(res_ids, i), output_res) != 0) {
      printf("[%s:%d] failed to get output from a node\n", __func__, __LINE__);
      get_output_response_free(output_res);
      ret = -1;
      goto end;
    }

    if (output_res->is_error) {
      printf("[%s:%d] %s\n", __func__, __LINE__, output_res->u.error->msg);
      get_output_response_free(output_res);
      ret = -1;
      goto end;
    }

    if (output_res->u.data->output->output_type == OUTPUT_BASIC) {
      output_basic_t* output_basic = output_res->u.data->output->output;

      // check if input has any useful amount of base token or native tokens
      if (!is_unspent_basic_output_useful(w, output_basic, send_amount, collected_amount, remainder_amount,
                                          send_native_tokens, collected_native_tokens, remainder_native_tokens)) {
        get_output_response_free(output_res);
        continue;
      }

      // add input into inputs list
      if ((ret = utxo_outputs_add(inputs, OUTPUT_BASIC, output_basic)) != 0) {
        printf("[%s:%d] can not add input to inputs list\n", __func__, __LINE__);
        get_output_response_free(output_res);
        goto end;
      }

      // add input into a transaction essence
      if ((ret = tx_essence_add_input(essence, 0, output_res->u.data->meta.tx_id,
                                      output_res->u.data->meta.output_index) != 0)) {
        printf("[%s:%d] can not add input to transaction essence\n", __func__, __LINE__);
        get_output_response_free(output_res);
        goto end;
      }

      // update collected amount
      collected_amount += output_basic->amount;

      // update collected native tokens
      native_tokens_list_t* elm;
      LL_FOREACH(output_basic->native_tokens, elm) {
        native_token_t* token = native_tokens_find_by_id(collected_native_tokens, elm->token->token_id);
        if (token) {
          if (uint256_add(&token->amount, &token->amount, &elm->token->amount) != true) {
            printf("[%s:%d] can not add amount of two native tokens\n", __func__, __LINE__);
            get_output_response_free(output_res);
            ret = -1;
            goto end;
          }
        } else {
          if ((ret = native_tokens_add(&collected_native_tokens, elm->token->token_id, &elm->token->amount)) != 0) {
            printf("[%s:%d] can not add native token to a list\n", __func__, __LINE__);
            get_output_response_free(output_res);
            goto end;
          }
        }
      }

      // check if remainder output is needed
      remainder_amount = 0;
      native_tokens_free(remainder_native_tokens);
      remainder_native_tokens = NULL;
      if (wallet_calculate_remainder_amount(send_amount, collected_amount, send_native_tokens, collected_native_tokens,
                                            &remainder_amount, &remainder_native_tokens) != 0) {
        printf("[%s:%d] can not calculate a remainder amount\n", __func__, __LINE__);
        get_output_response_free(output_res);
        ret = -1;
        goto end;
      }

      // check inputs balance (base tokens and native tokens)
      if (wallet_is_collected_balance_sufficient(w, send_amount, collected_amount, remainder_amount, send_native_tokens,
                                                 collected_native_tokens, remainder_native_tokens)) {
        // amount of base tokens and native tokens is sufficient, we can exit collecting more inputs
        get_output_response_free(output_res);
        break;
      }
    }

    get_output_response_free(output_res);
  }

  // check inputs balance (base tokens and native tokens) again because there could be no more available inputs but
  // balance of base tokens and native tokens could still be too little
  if (wallet_is_collected_balance_sufficient(w, send_amount, collected_amount, remainder_amount, send_native_tokens,
                                             collected_native_tokens, remainder_native_tokens)) {
    *balance_sufficient = true;
    // create a remainder output (remainder balance is returned to the sender address) if needed
    if (remainder_amount > 0) {
      *remainder = wallet_output_basic_create(send_addr, remainder_amount, remainder_native_tokens);
      if (!*remainder) {
        printf("[%s:%d] can not create a reminder basic output\n", __func__, __LINE__);
        ret = -1;
        goto end;
      }
    }
  }

end:
  // clean up memory
  res_outputs_free(res_ids);
  if (ret != 0) {
    utxo_outputs_free(*inputs);
  }
  native_tokens_free(collected_native_tokens);
  native_tokens_free(remainder_native_tokens);

  return ret;
}

int create_signatures_for_inputs(utxo_outputs_list_t* inputs, ed25519_keypair_t* sender_key,
                                 signing_data_list_t** sign_data) {
  if (inputs == NULL || sender_key == NULL || *sign_data != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  utxo_outputs_list_t* elm;
  LL_FOREACH(inputs, elm) {
    // add signing data (Basic output must have the address unlock condition)
    // get address unlock condition from the basic output
    unlock_cond_t* unlock_cond =
        condition_list_get_type(((output_basic_t*)elm->output->output)->unlock_conditions, UNLOCK_COND_ADDRESS);
    if (!unlock_cond) {
      return -1;
    }

    // add address unlock condition into the signing data list
    if (signing_data_add(unlock_cond->obj, NULL, 0, sender_key, sign_data) != 0) {
      return -1;
    }
  }

  return 0;
}

int wallet_basic_output_send(iota_wallet_t* w, bool sender_change, uint32_t sender_index, uint64_t send_amount,
                             native_tokens_list_t* send_native_tokens, address_t* recv_addr,
                             res_send_block_t* blk_res) {
  if (w == NULL || recv_addr == NULL || blk_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  address_t sender_addr = {0};
  ed25519_keypair_t sender_keypair = {0};
  if (wallet_get_address_and_keypair_from_index(w, sender_change, sender_index, &sender_addr, &sender_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    return -1;
  }

  int ret = 0;
  signing_data_list_t* sign_data = signing_new();
  utxo_outputs_list_t* inputs = NULL;
  output_basic_t* remainder = NULL;
  transaction_payload_t* tx = NULL;
  core_block_t* block = NULL;

  // create a tx
  tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create the receiver output
  output_basic_t* receiver_output = wallet_output_basic_create(recv_addr, send_amount, send_native_tokens);
  if (!receiver_output) {
    printf("[%s:%d] create a receiver basic output failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }
  if (tx_essence_add_output(tx->essence, OUTPUT_BASIC, receiver_output) != 0) {
    printf("[%s:%d] can not add receiver basic output to transaction essence\n", __func__, __LINE__);
    output_basic_free(receiver_output);
    ret = -1;
    goto end;
  }
  output_basic_free(receiver_output);

  // if no base tokens are sent, send only output minimum storage protection amount
  if (send_amount == 0) {
    send_amount = calc_minimum_output_deposit(&w->byte_cost, OUTPUT_BASIC, tx->essence->outputs->output->output);
    ((output_basic_t*)(tx->essence->outputs->output->output))->amount = send_amount;
  }

  // get inputs from the sender address
  bool balance_sufficient = false;
  if ((ret = wallet_get_inputs_and_create_remainder(w, tx->essence, &sender_addr, send_amount, send_native_tokens,
                                                    &balance_sufficient, &inputs, &remainder)) != 0) {
    printf("[%s:%d] can not collect inputs or create a reminder output\n", __func__, __LINE__);
    goto end;
  }

  // check balance of sender outputs
  if (!balance_sufficient) {
    printf("[%s:%d] insufficient address balance\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // if remainder is needed, create remainder output
  if (remainder) {
    if ((ret = tx_essence_add_output(tx->essence, OUTPUT_BASIC, remainder)) != 0) {
      printf("[%s:%d] can not add remainder output to transaction essence\n", __func__, __LINE__);
      goto end;
    }
  }

  // create signature for all collected inputs
  if ((ret = create_signatures_for_inputs(inputs, &sender_keypair, &sign_data)) != 0) {
    printf("[%s:%d] can not create signatures for inputs\n", __func__, __LINE__);
    goto end;
  }

  // create a core block
  block = wallet_create_core_block(w, tx, inputs, sign_data);
  if (!block) {
    printf("[%s:%d] can not create a core block\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // send a block to a network
  ret = wallet_send_block(w, block, blk_res);

end:
  if (block) {
    core_block_free(block);
  } else {
    tx_payload_free(tx);
  }
  signing_free(sign_data);
  utxo_outputs_free(inputs);
  output_basic_free(remainder);
  return ret;
}
