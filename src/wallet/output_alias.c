// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "wallet/output_alias.h"
#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "core/models/message.h"
#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"
#include "wallet/bip39.h"
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

static int add_unspent_alias_output_to_essence(transaction_essence_t* essence, get_output_t* output_data_res,
                                               ed25519_keypair_t* state_controller_key, signing_data_list_t** sign_data,
                                               utxo_outputs_list_t** unspent_outputs, uint64_t* output_amount) {
  if (essence == NULL || output_data_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // create inputs and unlock conditions based on the alias output
  output_alias_t* output = (output_alias_t*)output_data_res->output->output;
  *output_amount = output->amount;

  // add the output as a tx input into the tx payload
  if (tx_essence_add_input(essence, 0, output_data_res->meta.tx_id, output_data_res->meta.output_index) != 0) {
    return -1;
  }

  // add the output in unspent outputs list to be able to calculate inputs commitment hash
  if (utxo_outputs_add(unspent_outputs, output_data_res->output->output_type, output) != 0) {
    return -1;
  }

  // add signing data (Alias output must have the state controller unlock condition)
  // get state controller unlock condition from the alias output
  unlock_cond_blk_t* unlock_cond = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  if (!unlock_cond) {
    return -1;
  }

  // add state controller unlock condition into the signing data list
  if (signing_data_add(unlock_cond->block, NULL, 0, state_controller_key, sign_data) != 0) {
    return -1;
  }

  return 0;
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

static int wallet_output_alias_create(transaction_essence_t* essence, byte_t alias_id[], uint32_t state_index,
                                      address_t* state_ctrl_addr, address_t* govern_addr, uint32_t foundry_counter,
                                      uint64_t amount) {
  if (essence == NULL || alias_id == NULL || state_ctrl_addr == NULL || govern_addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  unlock_cond_blk_t* state = cond_blk_state_new(state_ctrl_addr);
  if (!state) {
    printf("[%s:%d] unable to create state controller address unlock condition\n", __func__, __LINE__);
    return -1;
  }

  unlock_cond_blk_t* governor = cond_blk_governor_new(govern_addr);
  if (!governor) {
    printf("[%s:%d] unable to create governor address unlock condition\n", __func__, __LINE__);
    cond_blk_free(state);
    return -1;
  }

  cond_blk_list_t* cond_blocks = cond_blk_list_new();
  if (cond_blk_list_add(&cond_blocks, state) != 0) {
    printf("[%s:%d] add unlock condition failed\n", __func__, __LINE__);
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    return -1;
  }
  if (cond_blk_list_add(&cond_blocks, governor) != 0) {
    printf("[%s:%d] add unlock condition failed\n", __func__, __LINE__);
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    return -1;
  }

  output_alias_t* alias_output =
      output_alias_new(amount, NULL, alias_id, state_index, NULL, 0, foundry_counter, cond_blocks, NULL, NULL);
  if (!alias_output) {
    printf("[%s:%d] creating alias output failed\n", __func__, __LINE__);
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    return -1;
  }

  if (tx_essence_add_output(essence, OUTPUT_ALIAS, alias_output) != 0) {
    printf("[%s:%d] can not add output to transaction essence\n", __func__, __LINE__);
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    output_alias_free(alias_output);
    return -1;
  }

  cond_blk_free(state);
  cond_blk_free(governor);
  cond_blk_list_free(cond_blocks);
  output_alias_free(alias_output);

  return 0;
}

// TODO: the alias output should be able to set optional feature blocks such as Sender/Metadata
int wallet_alias_output_create(iota_wallet_t* w, bool sender_change, uint32_t sender_index, uint64_t const send_amount,
                               address_t* state_ctrl_addr, address_t* govern_addr, uint32_t foundry_counter,
                               address_t* alias_addr, res_send_message_t* msg_res) {
  if (w == NULL || state_ctrl_addr == NULL || govern_addr == NULL || alias_addr == NULL || msg_res == NULL) {
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
  utxo_outputs_list_t* unspent_outputs = NULL;
  signing_data_list_t* sign_data = signing_new();
  transaction_payload_t* tx = NULL;
  native_tokens_list_t* collected_native_tokens = NULL;
  native_tokens_list_t* reminder_native_tokens = NULL;
  core_message_t* message = NULL;

  // create a tx
  tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create alias output
  byte_t alias_id[ALIAS_ID_BYTES] = {0};
  ret =
      wallet_output_alias_create(tx->essence, alias_id, 0, state_ctrl_addr, govern_addr, foundry_counter, send_amount);
  if (ret != 0) {
    printf("[%s:%d] create alias output failed\n", __func__, __LINE__);
    goto end;
  }

  // get outputs from the sender address
  uint64_t collected_amount = 0;
  collected_native_tokens = native_tokens_new();
  unspent_outputs = wallet_get_unspent_basic_outputs(w, &sender_addr, &sender_keypair, send_amount, NULL, tx->essence,
                                                     &sign_data, &collected_amount, &collected_native_tokens);
  if (!unspent_outputs) {
    printf("[%s:%d] address does not have any unspent basic outputs\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // check balance of sender outputs
  if (!wallet_is_collected_balance_sufficient(send_amount, collected_amount, NULL, NULL)) {
    printf("[%s:%d] insufficient address balance\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // calculate a reminder amount if needed
  uint64_t reminder_amount = 0;
  reminder_native_tokens = native_tokens_new();
  if (wallet_calculate_reminder_amount(send_amount, collected_amount, NULL, collected_native_tokens, &reminder_amount,
                                       &reminder_native_tokens) != 0) {
    printf("[%s:%d] can not calculate a reminder amount\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create a reminder if needed
  if (reminder_amount > 0 || native_tokens_count(reminder_native_tokens) > 0) {
    ret = wallet_output_basic_create(&sender_addr, reminder_amount, reminder_native_tokens, tx->essence);
    if (ret != 0) {
      printf("[%s:%d] create a reminder basic output failed\n", __func__, __LINE__);
      goto end;
    }
  }

  // create a core message
  message = wallet_create_core_message(w, tx, unspent_outputs, sign_data);
  if (!message) {
    printf("[%s:%d] can not create a core message\n", __func__, __LINE__);
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

  // send a message to a network
  ret = wallet_send_message(w, message, msg_res);

end:
  if (message) {
    core_message_free(message);
  } else {
    tx_payload_free(tx);
  }
  signing_free(sign_data);
  utxo_outputs_free(unspent_outputs);
  native_tokens_free(collected_native_tokens);
  native_tokens_free(reminder_native_tokens);
  return ret;
}

// TODO: the alias output should be able to send tokens and set state metadata
// TODO: alias address could have more than one unspent output and they need to be collected to satisfy send_amount
int wallet_alias_output_state_transition(iota_wallet_t* w, byte_t alias_id[], bool state_ctrl_change,
                                         uint32_t state_ctrl_index, address_t* govern_addr, uint32_t foundry_counter,
                                         uint64_t send_amount, utxo_outputs_list_t* outputs,
                                         res_send_message_t* msg_res) {
  if (w == NULL || alias_id == NULL || govern_addr == NULL || msg_res == NULL) {
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

  int ret = 0;
  utxo_outputs_list_t* unspent_outputs = NULL;
  res_output_t* output_res = NULL;
  signing_data_list_t* sign_data = signing_new();
  transaction_payload_t* tx = NULL;
  core_message_t* message = NULL;

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
  uint64_t output_amount = 0;
  if (add_unspent_alias_output_to_essence(tx->essence, output_res->u.data, &state_ctrl_keypair, &sign_data,
                                          &unspent_outputs, &output_amount) != 0) {
    printf("[%s:%d] failed to add alias output to transaction essence\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  if (output_amount < send_amount) {
    printf("[%s:%d] not enough balance in alias output\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }
  output_amount -= send_amount;

  // get alias state index and increment it
  uint32_t state_index = ((output_alias_t*)output_res->u.data->output->output)->state_index;
  state_index += 1;

  // create alias output
  ret = wallet_output_alias_create(tx->essence, alias_id, state_index, &state_ctrl_addr, govern_addr, foundry_counter,
                                   output_amount);
  if (ret != 0) {
    printf("[%s:%d] create alias output failed\n", __func__, __LINE__);
    goto end;
  }

  // add additional outputs to transaction essence
  utxo_outputs_list_t* elm;
  LL_FOREACH(outputs, elm) {
    if (tx_essence_add_output(tx->essence, elm->output->output_type, elm->output->output) != 0) {
      printf("[%s:%d] can not add output to transaction essence\n", __func__, __LINE__);
      goto end;
    }
  }

  // create a core message
  message = wallet_create_core_message(w, tx, unspent_outputs, sign_data);
  if (!message) {
    printf("[%s:%d] can not create a core message\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // send a message to a network
  ret = wallet_send_message(w, message, msg_res);

end:
  if (message) {
    core_message_free(message);
  } else {
    tx_payload_free(tx);
  }
  signing_free(sign_data);
  get_output_response_free(output_res);
  utxo_outputs_free(unspent_outputs);
  return ret;
}

int wallet_alias_output_destroy(iota_wallet_t* w, byte_t alias_id[], bool govern_change, uint32_t govern_index,
                                address_t* recv_addr, res_send_message_t* msg_res) {
  if (w == NULL || alias_id == NULL || recv_addr == NULL || msg_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  address_t govern_addr = {0};
  ed25519_keypair_t govern_keypair = {0};
  if (wallet_get_address_and_keypair_from_index(w, govern_change, govern_index, &govern_addr, &govern_keypair) != 0) {
    printf("Failed to generate a sender address and private key from an index!\n");
    return -1;
  }

  int ret = 0;
  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();
  res_output_t* output_res = NULL;
  signing_data_list_t* sign_data = signing_new();
  transaction_payload_t* tx = NULL;
  core_message_t* message = NULL;

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
  uint64_t output_amount = 0;
  if (add_unspent_alias_output_to_essence(tx->essence, output_res->u.data, &govern_keypair, &sign_data,
                                          &unspent_outputs, &output_amount) != 0) {
    printf("[%s:%d] failed to add alias output to transaction essence\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create basic output
  // TODO unspent outputs may have some native tokens which needs to be returned as reminder
  ret = wallet_output_basic_create(recv_addr, output_amount, NULL, tx->essence);
  if (ret != 0) {
    printf("[%s:%d] create basic output failed\n", __func__, __LINE__);
    goto end;
  }

  // create a core message
  message = wallet_create_core_message(w, tx, unspent_outputs, sign_data);
  if (!message) {
    printf("[%s:%d] can not create a core message\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // send a message to a network
  ret = wallet_send_message(w, message, msg_res);

end:
  if (message) {
    core_message_free(message);
  } else {
    tx_payload_free(tx);
  }
  signing_free(sign_data);
  get_output_response_free(output_res);
  utxo_outputs_free(unspent_outputs);
  return ret;
}
