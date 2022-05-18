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

  // add signing data (Alias output must have the state unlock condition)
  // get state unlock condition from the alias output
  unlock_cond_blk_t* unlock_cond = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  if (!unlock_cond) {
    return -1;
  }

  // add state unlock unlock condition into the signing data list
  if (signing_data_add(unlock_cond->block, NULL, 0, state_controller_key, sign_data) != 0) {
    return -1;
  }

  return 0;
}

static utxo_outputs_list_t* wallet_get_unspent_alias_output(iota_wallet_t* w, transaction_essence_t* essence,
                                                            ed25519_keypair_t* keypair, byte_t alias_id[],
                                                            signing_data_list_t** sign_data, uint64_t* output_amount) {
  if (w == NULL || essence == NULL || keypair == NULL || alias_id == NULL || output_amount == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  res_outputs_id_t* res_id = get_alias_output_from_alias_id(w, alias_id);
  if (!res_id) {
    printf("[%s:%d] failed to get unspent alias output IDs\n", __func__, __LINE__);
    return NULL;
  }

  // fetch output data from alias IDs
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

    if (output_res->u.data->output->output_type == OUTPUT_ALIAS) {
      if (add_unspent_alias_output_to_essence(essence, output_res->u.data, keypair, sign_data, &unspent_outputs,
                                              output_amount) != 0) {
        printf("[%s:%d] failed to add alias output to transaction essence\n", __func__, __LINE__);
        get_output_response_free(output_res);
        utxo_outputs_free(unspent_outputs);
        res_outputs_free(res_id);
        return NULL;
      }
    }

    get_output_response_free(output_res);
  }

  // clean up memory
  res_outputs_free(res_id);

  return unspent_outputs;
}

static int wallet_output_alias_create(transaction_essence_t* essence, byte_t alias_id[], uint32_t state_index,
                                      address_t* state_ctrl_addr, address_t* govern_addr, uint64_t amount) {
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
    cond_blk_free(state);
    printf("[%s:%d] unable to create governor address unlock condition\n", __func__, __LINE__);
    return -1;
  }

  cond_blk_list_t* cond_blocks = cond_blk_list_new();
  if (cond_blk_list_add(&cond_blocks, state) != 0) {
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    printf("[%s:%d] add unlock condition failed\n", __func__, __LINE__);
    return -1;
  }
  if (cond_blk_list_add(&cond_blocks, governor) != 0) {
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    printf("[%s:%d] add unlock condition failed\n", __func__, __LINE__);
    return -1;
  }

  output_alias_t* alias_output =
      output_alias_new(amount, NULL, alias_id, state_index, NULL, 0, 0, cond_blocks, NULL, NULL);
  if (!alias_output) {
    cond_blk_free(state);
    cond_blk_free(governor);
    cond_blk_list_free(cond_blocks);
    printf("[%s:%d] creating alias output failed\n", __func__, __LINE__);
    return -1;
  }

  if (tx_essence_add_output(essence, OUTPUT_ALIAS, alias_output) != 0) {
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

int wallet_alias_create_transaction(iota_wallet_t* w, address_t* sender_addr, ed25519_keypair_t* sender_keypair,
                                    uint64_t const send_amount, address_t* state_ctrl_addr, address_t* govern_addr,
                                    address_t* alias_addr, res_send_message_t* msg_res) {
  if (w == NULL || sender_addr == NULL || sender_keypair == NULL || state_ctrl_addr == NULL || govern_addr == NULL ||
      alias_addr == NULL || msg_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  utxo_outputs_list_t* unspent_outputs = NULL;
  signing_data_list_t* sign_data = signing_new();

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // get outputs from the sender address
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

  // create alias output
  byte_t alias_id[ALIAS_ID_BYTES] = {0};
  ret = wallet_output_alias_create(tx->essence, alias_id, 0, state_ctrl_addr, govern_addr, send_amount);
  if (ret != 0) {
    printf("[%s:%d] create alias output failed\n", __func__, __LINE__);
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

  // calculate transaction payload ID
  byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
  if (tx_payload_calculate_id(tx, payload_id, sizeof(payload_id)) != 0) {
    ret = -1;
    printf("[%s:%d] can not calculate transaction payload ID\n", __func__, __LINE__);
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
    ret = -1;
    printf("[%s:%d] can not create alias address from output Id!\n", __func__, __LINE__);
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

int wallet_alias_state_transition_transaction(iota_wallet_t* w, byte_t alias_id[], address_t* state_ctrl_addr,
                                              ed25519_keypair_t* state_ctrl_keypair, address_t* govern_addr,
                                              res_send_message_t* msg_res) {
  if (w == NULL || alias_id == NULL || state_ctrl_addr == NULL || state_ctrl_keypair == NULL || govern_addr == NULL ||
      msg_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  utxo_outputs_list_t* unspent_outputs = NULL;
  signing_data_list_t* sign_data = signing_new();

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // get outputs from the sender address
  uint64_t alias_output_amount = 0;
  unspent_outputs =
      wallet_get_unspent_alias_output(w, tx->essence, state_ctrl_keypair, alias_id, &sign_data, &alias_output_amount);
  if (!unspent_outputs) {
    printf("[%s:%d] address does not have any unspent alias outputs\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create alias output
  ret = wallet_output_alias_create(tx->essence, alias_id, 1, state_ctrl_addr, govern_addr, alias_output_amount);
  if (ret != 0) {
    printf("[%s:%d] create alias output failed\n", __func__, __LINE__);
    goto end;
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

int wallet_alias_destroy_transaction(iota_wallet_t* w, byte_t alias_id[], ed25519_keypair_t* govern_keypair,
                                     address_t* recv_addr, res_send_message_t* msg_res) {
  if (w == NULL || alias_id == NULL || govern_keypair == NULL || recv_addr == NULL || msg_res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;
  utxo_outputs_list_t* unspent_outputs = NULL;
  signing_data_list_t* sign_data = signing_new();

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (!tx) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // get outputs from the sender address
  uint64_t alias_output_amount = 0;
  unspent_outputs =
      wallet_get_unspent_alias_output(w, tx->essence, govern_keypair, alias_id, &sign_data, &alias_output_amount);
  if (!unspent_outputs) {
    printf("[%s:%d] address does not have any unspent alias outputs\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create basic output
  ret = wallet_output_basic_create(recv_addr, alias_output_amount, tx->essence);
  if (ret != 0) {
    printf("[%s:%d] create basic output failed\n", __func__, __LINE__);
    goto end;
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
