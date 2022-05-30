// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_output.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/storage_deposit.h"
#include "wallet/output_basic.h"

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

res_outputs_id_t* get_unspent_basic_output_ids(iota_wallet_t* w, address_t* send_addr) {
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
    printf("[%s:%d] failed to generate a sender address and private key from an index\n", __func__, __LINE__);
    return -1;
  }

  // create a receiver output
  output_basic_t* receiver_output = wallet_output_basic_create(recv_addr, send_amount, send_native_tokens);
  if (!receiver_output) {
    printf("[%s:%d] create a receiver basic output failed\n", __func__, __LINE__);
    return -1;
  }

  // add a receiver output to outputs list
  utxo_outputs_list_t* outputs = utxo_outputs_new();
  if (utxo_outputs_add(&outputs, OUTPUT_BASIC, receiver_output) != 0) {
    printf("[%s:%d]: can not add receiver output to a list!\n", __func__, __LINE__);
    output_basic_free(receiver_output);
    utxo_outputs_free(outputs);
    return -1;
  }
  output_basic_free(receiver_output);

  // send a block to a network
  byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
  int result = wallet_send(w, &sender_addr, &sender_keypair, NULL, outputs, NULL, payload_id, blk_res);

  // clean memory
  utxo_outputs_free(outputs);

  return result;
}
