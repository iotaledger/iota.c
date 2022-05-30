// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"
#include "wallet/bip39.h"
#include "wallet/output_alias.h"
#include "wallet/output_basic.h"
#include "wallet/wallet.h"

static res_outputs_id_t* get_alias_output_from_alias_id(iota_wallet_t* w, byte_t alias_id[]) {
  if (w == NULL || alias_id == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  res_outputs_id_t* res = res_outputs_new();
  if (!res) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  // covert binary alias id to string alias id
  char alias_id_hex[BIN_TO_HEX_STR_BYTES(ALIAS_ID_BYTES)] = {0};
  if (bin_2_hex(alias_id, ALIAS_ID_BYTES, NULL, alias_id_hex, sizeof(alias_id_hex)) != 0) {
    printf("[%s:%d] can not convert alias id from bin to hex\n", __func__, __LINE__);
    res_outputs_free(res);
    return NULL;
  }

  if (get_outputs_from_alias_id(&w->endpoint, INDEXER_API_PATH, alias_id_hex, res) != 0) {
    printf("[%s:%d] can not get output by output id\n", __func__, __LINE__);
    res_outputs_free(res);
    return NULL;
  }

  if (res->is_error) {
    printf("[%s:%d] %s\n", __func__, __LINE__, res->u.error->msg);
    res_outputs_free(res);
    return NULL;
  }

  return res;
}

static res_output_t* wallet_get_unspent_alias_output(iota_wallet_t* w, byte_t alias_id[]) {
  if (w == NULL || alias_id == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  res_outputs_id_t* res_id = get_alias_output_from_alias_id(w, alias_id);
  if (!res_id) {
    printf("[%s:%d] failed to get unspent alias output IDs\n", __func__, __LINE__);
    return NULL;
  }

  if (res_outputs_output_id_count(res_id) != 1) {
    printf("[%s:%d] alias ID should have only one unspent alias output\n", __func__, __LINE__);
    res_outputs_free(res_id);
    return NULL;
  }

  res_output_t* output_res = get_output_response_new();
  if (!output_res) {
    printf("[%s:%d] failed to create output response object\n", __func__, __LINE__);
    res_outputs_free(res_id);
    return NULL;
  }

  if (get_output(&w->endpoint, res_outputs_output_id(res_id, 0), output_res) != 0) {
    printf("[%s:%d] failed to get output from a node\n", __func__, __LINE__);
    get_output_response_free(output_res);
    res_outputs_free(res_id);
    return NULL;
  }

  if (output_res->is_error) {
    printf("[%s:%d] %s\n", __func__, __LINE__, output_res->u.error->msg);
    get_output_response_free(output_res);
    res_outputs_free(res_id);
    return NULL;
  }

  // clean up memory
  res_outputs_free(res_id);

  return output_res;
}

output_alias_t* wallet_output_alias_create(byte_t alias_id[], uint32_t state_index, address_t* state_ctrl_addr,
                                           address_t* govern_addr, uint32_t foundry_counter, uint64_t amount,
                                           native_tokens_list_t* native_tokens) {
  if (alias_id == NULL || state_ctrl_addr == NULL || govern_addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* state = condition_state_new(state_ctrl_addr);
  if (!state) {
    printf("[%s:%d] unable to create state controller address unlock condition\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* governor = condition_governor_new(govern_addr);
  if (!governor) {
    printf("[%s:%d] unable to create governor address unlock condition\n", __func__, __LINE__);
    condition_free(state);
    return NULL;
  }

  unlock_cond_list_t* conds = condition_list_new();
  if (condition_list_add(&conds, state) != 0) {
    printf("[%s:%d] add unlock condition failed\n", __func__, __LINE__);
    condition_free(state);
    condition_free(governor);
    condition_list_free(conds);
    return NULL;
  }
  if (condition_list_add(&conds, governor) != 0) {
    printf("[%s:%d] add unlock condition failed\n", __func__, __LINE__);
    condition_free(state);
    condition_free(governor);
    condition_list_free(conds);
    return NULL;
  }

  output_alias_t* alias_output =
      output_alias_new(amount, native_tokens, alias_id, state_index, NULL, 0, foundry_counter, conds, NULL, NULL);
  if (!alias_output) {
    printf("[%s:%d] creating alias output failed\n", __func__, __LINE__);
    condition_free(state);
    condition_free(governor);
    condition_list_free(conds);
    return NULL;
  }

  condition_free(state);
  condition_free(governor);
  condition_list_free(conds);

  return alias_output;
}

// TODO: the alias output should be able to set optional features such as Sender/Metadata
int wallet_alias_output_create(iota_wallet_t* w, bool sender_change, uint32_t sender_index, uint64_t const send_amount,
                               address_t* state_ctrl_addr, address_t* govern_addr, uint32_t foundry_counter,
                               address_t* alias_addr, res_send_block_t* blk_res) {
  if (w == NULL || state_ctrl_addr == NULL || govern_addr == NULL || alias_addr == NULL || blk_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  address_t sender_addr = {0};
  ed25519_keypair_t sender_keypair = {0};
  if (wallet_get_address_and_keypair_from_index(w, sender_change, sender_index, &sender_addr, &sender_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    return -1;
  }

  // create an alias output
  byte_t alias_id[ALIAS_ID_BYTES] = {0};
  output_alias_t* alias_output =
      wallet_output_alias_create(alias_id, 0, state_ctrl_addr, govern_addr, foundry_counter, send_amount, NULL);
  if (!alias_output) {
    printf("[%s:%d] create an alias output failed\n", __func__, __LINE__);
    return -1;
  }

  // add an alias output to outputs list
  utxo_outputs_list_t* outputs = utxo_outputs_new();
  if (utxo_outputs_add(&outputs, OUTPUT_ALIAS, alias_output) != 0) {
    printf("[%s:%d]: can not add an alias output to a list!\n", __func__, __LINE__);
    output_alias_free(alias_output);
    utxo_outputs_free(outputs);
    return -1;
  }
  output_alias_free(alias_output);

  // send a block to a network
  byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
  if (wallet_send(w, &sender_addr, &sender_keypair, NULL, outputs, payload_id, blk_res) != 0) {
    printf("[%s:%d] can not send alias output create block\n", __func__, __LINE__);
    utxo_outputs_free(outputs);
    return -1;
  }
  utxo_outputs_free(outputs);

  // create alias output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  memcpy(output_id, payload_id, sizeof(payload_id));
  memset(output_id + sizeof(payload_id), 0,
         sizeof(uint16_t));  // index is always 0 because in this function alias output is added into a transaction
                             // essence before basic output

  // create alias address from alias output ID
  if (alias_address_from_output(output_id, sizeof(output_id), alias_addr) != 0) {
    printf("[%s:%d] can not create alias address from output Id!\n", __func__, __LINE__);
    return -1;
  }

  return 0;

  /*int ret = 0;
  utxo_outputs_list_t* inputs = NULL;
  output_basic_t* remainder = NULL;
  signing_data_list_t* sign_data = signing_new();
  transaction_payload_t* tx = NULL;
  core_block_t* block = NULL;

  // create a tx
  tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create alias output
  byte_t alias_id[ALIAS_ID_BYTES] = {0};
  ret = wallet_output_alias_create(tx->essence, alias_id, 0, state_ctrl_addr, govern_addr, foundry_counter, send_amount,
                                   NULL);
  if (ret != 0) {
    printf("[%s:%d] create alias output failed\n", __func__, __LINE__);
    goto end;
  }

  // get inputs from the sender address
  bool balance_sufficient = false;
  if ((ret = wallet_get_inputs_and_create_remainder(w, tx->essence, &sender_addr, send_amount, NULL,
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
    if (tx_essence_add_output(tx->essence, OUTPUT_BASIC, remainder) != 0) {
      printf("[%s:%d] can not add remainder output to transaction essence\n", __func__, __LINE__);
      ret = -1;
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

  // calculate transaction payload ID
  byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
  if (tx_payload_calculate_id(tx, payload_id, sizeof(payload_id)) != 0) {
    printf("[%s:%d] can not calculate transaction payload ID\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create alias output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  memcpy(output_id, payload_id, sizeof(payload_id));
  memset(output_id + sizeof(payload_id), 0,
         sizeof(uint16_t));  // index is always 0 because in this function alias output is added into a transaction
                             // essence before basic output

  // create alias address from alias output ID
  if (alias_address_from_output(output_id, sizeof(output_id), alias_addr) != 0) {
    printf("[%s:%d] can not create alias address from output Id!\n", __func__, __LINE__);
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
   */
}

// TODO: the alias output should be able to send tokens and set state metadata
// TODO: alias address could have more than one unspent output and they need to be collected to satisfy send_amount
int wallet_alias_output_state_transition(iota_wallet_t* w, byte_t alias_id[], bool state_ctrl_change,
                                         uint32_t state_ctrl_index, address_t* govern_addr, uint32_t foundry_counter,
                                         uint64_t send_amount, utxo_outputs_list_t* outputs,
                                         res_send_block_t* blk_res) {
  if (w == NULL || alias_id == NULL || govern_addr == NULL || blk_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  address_t state_ctrl_addr = {0};
  ed25519_keypair_t state_ctrl_keypair = {0};
  if (wallet_get_address_and_keypair_from_index(w, state_ctrl_change, state_ctrl_index, &state_ctrl_addr,
                                                &state_ctrl_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    return -1;
  }

  // get unspent alias output
  res_output_t* output_res = wallet_get_unspent_alias_output(w, alias_id);
  if (!output_res) {
    printf("[%s:%d] alias address does not have any unspent alias outputs\n", __func__, __LINE__);
    return -1;
  }

  utxo_inputs_list_t* inputs = utxo_inputs_new();
  if (utxo_inputs_add(&inputs, 0, output_res->u.data->meta.tx_id, output_res->u.data->meta.output_index) != 0) {
    printf("[%s:%d] can not add unspent output to inputs list\n", __func__, __LINE__);
    get_output_response_free(output_res);
    utxo_inputs_free(inputs);
    return -1;
  }

  uint64_t output_amount = ((output_alias_t*)output_res->u.data->output->output)->amount;
  native_tokens_list_t* output_native_tokens = ((output_alias_t*)output_res->u.data->output->output)->native_tokens;

  if (output_amount < send_amount) {
    printf("[%s:%d] not enough balance in alias output\n", __func__, __LINE__);
    get_output_response_free(output_res);
    utxo_inputs_free(inputs);
    return -1;
  }
  output_amount -= send_amount;

  // get alias state index and increment it
  uint32_t state_index = ((output_alias_t*)output_res->u.data->output->output)->state_index;
  state_index += 1;

  // create an alias output
  output_alias_t* alias_output = wallet_output_alias_create(alias_id, state_index, &state_ctrl_addr, govern_addr,
                                                            foundry_counter, output_amount, output_native_tokens);
  if (!alias_output) {
    printf("[%s:%d] create an alias output failed\n", __func__, __LINE__);
    utxo_inputs_free(inputs);
    return -1;
  }

  // add an alias output to outputs list
  if (utxo_outputs_add(&outputs, OUTPUT_ALIAS, alias_output) != 0) {
    printf("[%s:%d]: can not add an alias output to a list!\n", __func__, __LINE__);
    output_alias_free(alias_output);
    utxo_outputs_free(outputs);
    utxo_inputs_free(inputs);
    return -1;
  }
  output_alias_free(alias_output);

  // send a block to a network
  byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
  if (wallet_send(w, &state_ctrl_addr, &state_ctrl_keypair, inputs, outputs, payload_id, blk_res) != 0) {
    printf("[%s:%d] can not send alias output create block\n", __func__, __LINE__);
    utxo_outputs_free(outputs);
    utxo_inputs_free(inputs);
    return -1;
  }

  // clean up memory
  utxo_outputs_free(outputs);

  return 0;
}

int wallet_alias_output_destroy(iota_wallet_t* w, byte_t alias_id[], bool govern_change, uint32_t govern_index,
                                address_t* recv_addr, res_send_block_t* blk_res) {
  if (w == NULL || alias_id == NULL || recv_addr == NULL || blk_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  address_t govern_addr = {0};
  ed25519_keypair_t govern_keypair = {0};
  if (wallet_get_address_and_keypair_from_index(w, govern_change, govern_index, &govern_addr, &govern_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    return -1;
  }

  // get unspent alias output
  res_output_t* output_res = wallet_get_unspent_alias_output(w, alias_id);
  if (!output_res) {
    printf("[%s:%d] alias address does not have any unspent alias outputs\n", __func__, __LINE__);
    return -1;
  }

  utxo_inputs_list_t* inputs = utxo_inputs_new();
  if (utxo_inputs_add(&inputs, 0, output_res->u.data->meta.tx_id, output_res->u.data->meta.output_index) != 0) {
    printf("[%s:%d] can not add unspent output to inputs list\n", __func__, __LINE__);
    get_output_response_free(output_res);
    return -1;
  }

  // create a basic output
  uint64_t output_amount = ((output_alias_t*)output_res->u.data->output->output)->amount;
  native_tokens_list_t* output_native_tokens = ((output_alias_t*)output_res->u.data->output->output)->native_tokens;
  output_basic_t* output_basic = wallet_output_basic_create(recv_addr, output_amount, output_native_tokens);
  if (!output_basic) {
    printf("[%s:%d] create basic output failed\n", __func__, __LINE__);
    get_output_response_free(output_res);
    utxo_inputs_free(inputs);
    return -1;
  }

  // add a basic output to outputs list
  utxo_outputs_list_t* outputs = utxo_outputs_new();
  if (utxo_outputs_add(&outputs, OUTPUT_BASIC, output_basic) != 0) {
    printf("[%s:%d]: can not add an alias output to a list!\n", __func__, __LINE__);
    get_output_response_free(output_res);
    output_basic_free(output_basic);
    utxo_inputs_free(inputs);
    return -1;
  }
  output_basic_free(output_basic);

  // send a block to a network
  byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
  if (wallet_send(w, &govern_addr, &govern_keypair, inputs, outputs, payload_id, blk_res) != 0) {
    printf("[%s:%d] can not send alias output create block\n", __func__, __LINE__);
    utxo_outputs_free(outputs);
    utxo_inputs_free(inputs);
    return -1;
  }

  // clean up memory
  utxo_outputs_free(outputs);

  return 0;

  /*int ret = 0;
  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();
  res_output_t* output_res = NULL;
  signing_data_list_t* sign_data = signing_new();
  transaction_payload_t* tx = NULL;
  core_block_t* block = NULL;

  // create a tx
  tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // get unspent alias output
  output_res = wallet_get_unspent_alias_output(w, alias_id);
  if (!output_res) {
    printf("[%s:%d] alias address does not have any unspent alias outputs\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // add unspent alias output to transaction essence
  if (add_unspent_alias_output_to_essence(tx->essence, output_res->u.data, &govern_keypair, &sign_data,
                                          &unspent_outputs) != 0) {
    printf("[%s:%d] failed to add alias output to transaction essence\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create basic output
  uint64_t output_amount = ((output_alias_t*)output_res->u.data->output->output)->amount;
  native_tokens_list_t* output_native_tokens = ((output_alias_t*)output_res->u.data->output->output)->native_tokens;
  output_basic_t* output_basic = wallet_output_basic_create(recv_addr, output_amount, output_native_tokens);
  if (!output_basic) {
    printf("[%s:%d] create basic output failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }
  if (tx_essence_add_output(tx->essence, OUTPUT_BASIC, output_basic) != 0) {
    printf("[%s:%d] can not add basic output to transaction essence\n", __func__, __LINE__);
    output_basic_free(output_basic);
    ret = -1;
    goto end;
  }
  output_basic_free(output_basic);

  // create a core block
  block = wallet_create_core_block(w, tx, unspent_outputs, sign_data);
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
  get_output_response_free(output_res);
  utxo_outputs_free(unspent_outputs);
  return ret;*/
}
