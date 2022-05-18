// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "wallet/output_basic.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"

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
  if (get_basic_outputs(&w->endpoint, "/indexer/v1", query_param, res_id) != 0) {
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

static int add_unspent_basic_outputs_to_essence(transaction_essence_t* essence, get_output_t* output_data_res,
                                                ed25519_keypair_t* sender_key, signing_data_list_t** sign_data,
                                                utxo_outputs_list_t** unspent_outputs, uint64_t* total_output_amount) {
  if (essence == NULL || output_data_res == NULL || sender_key == NULL || total_output_amount == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // create inputs and unlock conditions based on the basic output
  output_basic_t* output = (output_basic_t*)output_data_res->output->output;
  *total_output_amount += output->amount;
  // add the output as a tx input into the tx payload
  if (tx_essence_add_input(essence, 0, output_data_res->meta.tx_id, output_data_res->meta.output_index) != 0) {
    return -1;
  }
  // add the output in unspent outputs list to be able to calculate inputs commitment hash
  if (utxo_outputs_add(unspent_outputs, output_data_res->output->output_type, output) != 0) {
    return -1;
  }

  // add signing data (Basic output must have the address unlock condition)
  // get address unlock condition from the basic output
  unlock_cond_blk_t* unlock_cond = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_ADDRESS);
  if (!unlock_cond) {
    return -1;
  }
  // add address unlock condition into the signing data list
  if (signing_data_add(unlock_cond->block, NULL, 0, sender_key, sign_data) != 0) {
    return -1;
  }

  return 0;
}

utxo_outputs_list_t* wallet_get_unspent_basic_outputs(iota_wallet_t* w, address_t* send_addr,
                                                      ed25519_keypair_t* sender_keypair, uint64_t send_amount,
                                                      transaction_essence_t* essence, signing_data_list_t** sign_data,
                                                      uint64_t* total_output_amount) {
  if (w == NULL || send_addr == NULL || sender_keypair == NULL || essence == NULL || total_output_amount == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  res_outputs_id_t* res_id = get_unspent_basic_output_ids(w, send_addr);
  if (!res_id) {
    printf("[%s:%d] failed to get unspent basic output IDs\n", __func__, __LINE__);
    return NULL;
  }

  // fetch output data from output IDs
  *total_output_amount = 0;
  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();
  for (size_t i = 0; i < res_outputs_output_id_count(res_id); i++) {
    res_output_t* output_res = get_output_response_new();
    if (!output_res) {
      printf("[%s:%d] failed to create output response object\n", __func__, __LINE__);
      utxo_outputs_free(unspent_outputs);
      res_outputs_free(res_id);
      return NULL;
    }

    if (get_output(&w->endpoint, res_outputs_output_id(res_id, i), output_res) != 0) {
      printf("[%s:%d] failed to get output from a node\n", __func__, __LINE__);
      get_output_response_free(output_res);
      utxo_outputs_free(unspent_outputs);
      res_outputs_free(res_id);
      return NULL;
    }

    if (output_res->is_error) {
      printf("[%s:%d] %s\n", __func__, __LINE__, output_res->u.error->msg);
      get_output_response_free(output_res);
      utxo_outputs_free(unspent_outputs);
      res_outputs_free(res_id);
      return NULL;
    }

    if (output_res->u.data->output->output_type == OUTPUT_BASIC) {
      uint64_t output_amount = 0;
      if (add_unspent_basic_outputs_to_essence(essence, output_res->u.data, sender_keypair, sign_data, &unspent_outputs,
                                               &output_amount) != 0) {
        get_output_response_free(output_res);
        break;
      }
      *total_output_amount += output_amount;
      // check balance
      if (*total_output_amount >= send_amount) {
        // have got sufficient amount
        get_output_response_free(output_res);
        break;
      }
    }
  }

  // clean up memory
  res_outputs_free(res_id);

  return unspent_outputs;
}

int wallet_output_basic_create(address_t* recv_addr, uint64_t amount, transaction_essence_t* essence) {
  if (recv_addr == NULL || essence == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  unlock_cond_blk_t* unlock_cond_addr = cond_blk_addr_new(recv_addr);
  if (!unlock_cond_addr) {
    printf("[%s:%d] unable to create address unlock condition\n", __func__, __LINE__);
    return -1;
  }

  cond_blk_list_t* unlock_cond_blk = cond_blk_list_new();
  if (cond_blk_list_add(&unlock_cond_blk, unlock_cond_addr) != 0) {
    cond_blk_free(unlock_cond_addr);
    cond_blk_list_free(unlock_cond_blk);
    printf("[%s:%d] failed to add address unlock condition\n", __func__, __LINE__);
    return -1;
  }

  output_basic_t* output_basic = output_basic_new(amount, NULL, unlock_cond_blk, NULL);
  if (!output_basic) {
    cond_blk_free(unlock_cond_addr);
    cond_blk_list_free(unlock_cond_blk);
    printf("[%s:%d] failed to create basic output\n", __func__, __LINE__);
    return -1;
  }

  if (tx_essence_add_output(essence, OUTPUT_BASIC, output_basic) != 0) {
    cond_blk_free(unlock_cond_addr);
    cond_blk_list_free(unlock_cond_blk);
    output_basic_free(output_basic);
    return -1;
  }

  cond_blk_free(unlock_cond_addr);
  cond_blk_list_free(unlock_cond_blk);
  output_basic_free(output_basic);

  return 0;
}

int wallet_basic_send(iota_wallet_t* w, address_t* sender_addr, ed25519_keypair_t* sender_keypair,
                      uint64_t const send_amount, address_t* recv_addr, res_send_message_t* msg_res) {
  if (w == NULL || sender_addr == NULL || sender_keypair == NULL || recv_addr == NULL || msg_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  signing_data_list_t* sign_data = signing_new();
  utxo_outputs_list_t* unspent_outputs = NULL;

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // get unspent basic outputs from a sender address
  uint64_t total_unspent_amount = 0;
  unspent_outputs = wallet_get_unspent_basic_outputs(w, sender_addr, sender_keypair, send_amount, tx->essence,
                                                     &sign_data, &total_unspent_amount);
  if (!unspent_outputs) {
    printf("[%s:%d] address does not have any unspent basic outputs\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // check balance of sender outputs
  if (total_unspent_amount < send_amount) {
    printf("[%s:%d] insufficient address balance\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create the receiver output
  ret = wallet_output_basic_create(recv_addr, send_amount, tx->essence);
  if (ret != 0) {
    printf("[%s:%d] create a receiver basic output failed\n", __func__, __LINE__);
    goto end;
  }

  // check if reminder is needed
  if (total_unspent_amount > send_amount) {
    ret = wallet_output_basic_create(sender_addr, total_unspent_amount - send_amount, tx->essence);
    if (ret != 0) {
      printf("[%s:%d] create a reminder basic output failed\n", __func__, __LINE__);
      goto end;
    }
  }

  // create a core message
  core_message_t* message = wallet_create_core_message(w, tx, unspent_outputs, sign_data);
  if (!message) {
    printf("[%s:%d] can not create a core message\n", __func__, __LINE__);
    goto end;
  }

  // send a message to a network
  ret = wallet_send_message(w, message, msg_res);

  // clean up memory
  core_message_free(message);

end:
  signing_free(sign_data);
  utxo_outputs_free(unspent_outputs);
  return ret;
}
