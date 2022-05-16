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

// create basic unspent outputs
static utxo_outputs_list_t* alias_outputs_from_output_id(iota_wallet_t* w, transaction_essence_t* essence,
                                                         ed25519_keypair_t* sender_key, byte_t output_id[],
                                                         signing_data_list_t** sign_data) {
  int ret = 0;

  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();

  res_output_t* output_res = get_output_response_new();
  if (output_res) {
    char output_id_str[BIN_TO_HEX_STR_BYTES(IOTA_OUTPUT_ID_BYTES)] = {0};
    bin_2_hex(output_id, IOTA_OUTPUT_ID_BYTES, NULL, output_id_str, sizeof(output_id_str));

    char output_str[BIN_TO_HEX_STR_BYTES(IOTA_OUTPUT_ID_BYTES)] = {0};

    sprintf(output_str, "%s", output_id_str);

    ret = get_output(&w->endpoint, output_str, output_res);
    if (ret == 0) {
      if (!output_res->is_error) {
        // create inputs and unlock conditions based on the basic output
        if (output_res->u.data->output->output_type == OUTPUT_BASIC) {
          output_basic_t* o = (output_basic_t*)output_res->u.data->output->output;
          // add the output as a tx input into the tx payload
          ret = tx_essence_add_input(essence, 0, output_res->u.data->meta.tx_id, output_res->u.data->meta.output_index);
          if (ret != 0) {
            get_output_response_free(output_res);
            return NULL;
          }
          // add the output in unspent outputs list to be able to calculate inputs commitment hash
          ret = utxo_outputs_add(&unspent_outputs, output_res->u.data->output->output_type, o);
          if (ret != 0) {
            get_output_response_free(output_res);
            return NULL;
          }

          // add signing data (Basic output must have the address unlock condition)
          // get address unlock condition from the basic output
          unlock_cond_blk_t* unlock_cond = cond_blk_list_get_type(o->unlock_conditions, UNLOCK_COND_ADDRESS);
          if (!unlock_cond) {
            get_output_response_free(output_res);
            return NULL;
          }
          // add address unlock condition into the signing data list
          ret = signing_data_add(unlock_cond->block, NULL, 0, sender_key, sign_data);
          if (ret != 0) {
            get_output_response_free(output_res);
            return NULL;
          }
        }
      } else {
        printf("[%s:%d] %s\n", __func__, __LINE__, output_res->u.error->msg);
      }
    }
    get_output_response_free(output_res);
  }

  return unspent_outputs;
}

// create a receiver for an alias output
static int alias_receiver_output(transaction_essence_t* essence, byte_t alias_id[], uint32_t state_index,
                                 address_t* state_ctrl_addr, address_t* govern_addr, uint64_t const amount,
                                 address_t* sender) {
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

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_sender(&feat_blocks, sender);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  feat_blk_list_add_issuer(&immut_feat_blocks, sender);

  output_alias_t* alias_output =
      output_alias_new(amount, NULL, alias_id, state_index, NULL, 0, 0, cond_blocks, NULL, NULL);
  if (!alias_output) {
    cond_blk_free(state);
    cond_blk_list_free(cond_blocks);
    printf("[%s:%d] creating alias output failed\n", __func__, __LINE__);
    return -1;
  }

  int ret = 0;

  // add receiver output to tx payload
  if (tx_essence_add_output(essence, OUTPUT_ALIAS, alias_output) != 0) {
    ret = -1;
  }

  cond_blk_free(state);
  cond_blk_list_free(cond_blocks);
  output_alias_free(alias_output);

  return ret;
}

int wallet_create_alias_output(iota_wallet_t* w, bool change, uint32_t index, uint64_t const send_amount,
                               address_t* state_ctrl_addr, address_t* govern_addr, res_send_message_t* msg_res,
                               byte_t alias_id[], byte_t alias_output_id[]) {
  if (!w || !state_ctrl_addr || !govern_addr || !alias_id) {
    printf("[%s:%d] access NULL pointer\n", __func__, __LINE__);
    return -1;
  }

  // create message
  core_message_t* basic_msg = core_message_new(w->protocol_version);
  if (!basic_msg) {
    printf("[%s:%d] create message object failed\n", __func__, __LINE__);
    return -1;
  }

  utxo_outputs_list_t* outputs = NULL;
  signing_data_list_t* sign_data = signing_new();

  address_t sender_addr;
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};
  ed25519_keypair_t sender_key = {};
  int ret = 0;

  ret = wallet_ed25519_address_from_index(w, change, index, &sender_addr);
  if (ret != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    goto end;
  }

  ret = get_address_path(w, change, index, addr_path, sizeof(addr_path));
  if (ret != 0) {
    printf("[%s:%d] Can not derive ed25519 address from seed and path\n", __func__, __LINE__);
    goto end;
  }

  ret = address_keypair_from_path(w->seed, sizeof(w->seed), addr_path, &sender_key);
  if (ret != 0) {
    printf("[%s:%d] get address keypair failed\n", __func__, __LINE__);
    goto end;
  }

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (tx == NULL) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    goto end;
  } else {
    basic_msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;
    basic_msg->payload = tx;
  }

  // get outputs from the sender address
  uint64_t output_amount = 0;
  outputs = wallet_get_unspent_basic_outputs(w, tx->essence, &sender_key, &sender_addr, send_amount, &sign_data,
                                             &output_amount);
  if (!outputs) {
    printf("[%s:%d] get empty outputs from the address\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // check balance of sender outputs
  if (output_amount < send_amount) {
    printf("[%s:%d] insufficient balance\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create the receiver output
  byte_t alias_id_zero[ALIAS_ID_BYTES] = {0};
  ret = alias_receiver_output(tx->essence, alias_id_zero, 0, state_ctrl_addr, govern_addr, send_amount, &sender_addr);
  if (ret != 0) {
    printf("[%s:%d] create the receiver output failed\n", __func__, __LINE__);
    goto end;
  }

  // check if reminder is needed
  if (output_amount > send_amount) {
    ret = wallet_output_basic_create(tx->essence, &sender_addr, output_amount - send_amount);
    if (ret != 0) {
      printf("[%s:%d] create the reminder output failed\n", __func__, __LINE__);
      goto end;
    }
  }

  // calculate inputs commitment
  ret = tx_essence_inputs_commitment_calculate(tx->essence, outputs);
  if (ret != 0) {
    printf("[%s:%d] calculate inputs commitment error\n", __func__, __LINE__);
    goto end;
  }

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  ret = core_message_essence_hash_calc(basic_msg, essence_hash, sizeof(essence_hash));
  if (ret != 0) {
    printf("[%s:%d] calculate essence hash error\n", __func__, __LINE__);
    goto end;
  }

  // sign transaction
  ret =
      signing_transaction_sign(essence_hash, sizeof(essence_hash), tx->essence->inputs, sign_data, &tx->unlock_blocks);
  if (ret != 0) {
    printf("[%s:%d] sign transaction error\n", __func__, __LINE__);
    goto end;
  }

  // syntactic validation
  if (tx_payload_syntactic(tx, &w->byte_cost)) {
    // send out message
    ret = send_core_message(&w->endpoint, basic_msg, msg_res);
  } else {
    ret = -1;
    printf("[%s:%d] invalid transaction payload\n", __func__, __LINE__);
  }

  // calculate alias ID
  if (ret == 0) {
    // calculate transaction payload ID
    byte_t payload_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {0};
    if (tx_payload_calculate_id(tx, payload_id, sizeof(payload_id)) != 0) {
      ret = -1;
      printf("[%s:%d] can not calculate transaction payload ID\n", __func__, __LINE__);
      goto end;
    }

    memcpy(alias_output_id, payload_id, sizeof(payload_id));
    memset(alias_output_id + sizeof(payload_id), 0, sizeof(uint16_t));

    // calculate alias ID
    if (iota_blake2b_sum(alias_output_id, IOTA_OUTPUT_ID_BYTES, alias_id, ALIAS_ID_BYTES) != 0) {
      ret = -1;
      printf("[%s:%d] calculating alias ID failed\n", __func__, __LINE__);
      goto end;
    }
  }

end:
  signing_free(sign_data);
  core_message_free(basic_msg);
  utxo_outputs_free(outputs);
  return ret;
}

int wallet_send_alias_output(iota_wallet_t* w, bool change, uint32_t index, uint64_t const send_amount,
                             byte_t alias_id[], address_t* state_ctrl_addr, address_t* govern_addr, byte_t output_id[],
                             res_send_message_t* msg_res) {
  if (!w || !alias_id || !state_ctrl_addr || !govern_addr) {
    printf("[%s:%d] access NULL pointer\n", __func__, __LINE__);
    return -1;
  }

  // create message
  core_message_t* basic_msg = core_message_new(w->protocol_version);
  if (!basic_msg) {
    printf("[%s:%d] create message object failed\n", __func__, __LINE__);
    return -1;
  }

  utxo_outputs_list_t* outputs = NULL;
  signing_data_list_t* sign_data = signing_new();

  address_t sender_addr;
  char addr_path[IOTA_ACCOUNT_PATH_MAX] = {};
  ed25519_keypair_t sender_key = {};
  int ret = 0;

  ret = wallet_ed25519_address_from_index(w, change, index, &sender_addr);
  if (ret != 0) {
    printf("[%s:%d] get sender address failed\n", __func__, __LINE__);
    goto end;
  }

  ret = get_address_path(w, change, index, addr_path, sizeof(addr_path));
  if (ret != 0) {
    printf("[%s:%d] Can not derive ed25519 address from seed and path\n", __func__, __LINE__);
    goto end;
  }

  ret = address_keypair_from_path(w->seed, sizeof(w->seed), addr_path, &sender_key);
  if (ret != 0) {
    printf("[%s:%d] get address keypair failed\n", __func__, __LINE__);
    goto end;
  }

  // create a tx
  transaction_payload_t* tx = tx_payload_new(w->network_id);
  if (tx == NULL) {
    printf("[%s:%d] create tx payload failed\n", __func__, __LINE__);
    goto end;
  } else {
    basic_msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;
    basic_msg->payload = tx;
  }

  // get outputs from the sender address
  outputs = alias_outputs_from_output_id(w, tx->essence, &sender_key, output_id, &sign_data);
  if (!outputs) {
    printf("[%s:%d] get empty outputs from the address\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // create the receiver output
  ret = alias_receiver_output(tx->essence, alias_id, 1, state_ctrl_addr, govern_addr, send_amount, &sender_addr);
  if (ret != 0) {
    printf("[%s:%d] create the receiver output failed\n", __func__, __LINE__);
    goto end;
  }

  // calculate inputs commitment
  ret = tx_essence_inputs_commitment_calculate(tx->essence, outputs);
  if (ret != 0) {
    printf("[%s:%d] calculate inputs commitment error\n", __func__, __LINE__);
    goto end;
  }

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  ret = core_message_essence_hash_calc(basic_msg, essence_hash, sizeof(essence_hash));
  if (ret != 0) {
    printf("[%s:%d] calculate essence hash error\n", __func__, __LINE__);
    goto end;
  }

  // sign transaction
  ret =
      signing_transaction_sign(essence_hash, sizeof(essence_hash), tx->essence->inputs, sign_data, &tx->unlock_blocks);
  if (ret != 0) {
    printf("[%s:%d] sign transaction error\n", __func__, __LINE__);
    goto end;
  }

  // syntactic validation
  if (tx_payload_syntactic(tx, &w->byte_cost)) {
    // send out message
    ret = send_core_message(&w->endpoint, basic_msg, msg_res);
  } else {
    ret = -1;
    printf("[%s:%d] invalid transaction payload\n", __func__, __LINE__);
  }

end:
  signing_free(sign_data);
  core_message_free(basic_msg);
  utxo_outputs_free(outputs);
  return ret;
}
