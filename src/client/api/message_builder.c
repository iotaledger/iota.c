// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "utlist.h"

#include "client/api/json_utils.h"
#include "client/api/message_builder.h"

// serialize indexation payload to a JSON object
static cJSON* indexation_to_json(indexation_t* index) {
  /*
  An indexation payload structure
  "payload": {
      "type": 2,
      "index": "Foo",
      "data": "426172"
  }
  */
  cJSON* payload_obj = NULL;

  if (!index) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if ((payload_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating payload object failed\n", __func__, __LINE__);
    return NULL;
  }

  // type 2 denote as an indexation payload
  if (!cJSON_AddNumberToObject(payload_obj, "type", 2)) {
    printf("[%s:%d] add payload type failed\n", __func__, __LINE__);
    cJSON_Delete(payload_obj);
    return NULL;
  }

  // make sure index is a string
  byte_buf2str(index->index);
  if (!cJSON_AddStringToObject(payload_obj, "index", (char const*)index->index->data)) {
    printf("[%s:%d] add index failed\n", __func__, __LINE__);
    cJSON_Delete(payload_obj);
    return NULL;
  }

  size_t data_str_len = index->data->len * 2 + 1;
  char* data_str = malloc(data_str_len);
  if (!data_str) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    cJSON_Delete(payload_obj);
    return NULL;
  }

  if (bin2hex(index->data->data, index->data->len, data_str, data_str_len) == 0) {
    // add data object
    if (!cJSON_AddStringToObject(payload_obj, "data", data_str)) {
      printf("[%s:%d] creating data failed\n", __func__, __LINE__);
      cJSON_Delete(payload_obj);
      payload_obj = NULL;
    }
  } else {
    printf("[%s:%d] convert bin to hex string failed\n", __func__, __LINE__);
    free(data_str);
    cJSON_Delete(payload_obj);
    return NULL;
  }

  free(data_str);
  return payload_obj;
}

// serialize utxo input array to a JSON object
static cJSON* tx_inputs_to_json(transaction_essence_t* es) {
  /*
  [
    {
      "type": 0,
      "transactionId": "2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03",
      "transactionOutputIndex": 0
    }
  ]
  */
  char tx_id_str[TRANSACTION_ID_BYTES * 2 + 1] = {};
  cJSON* input_arr = NULL;

  if (!es->inputs) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if ((input_arr = cJSON_CreateArray()) == NULL) {
    printf("[%s:%d] creating input array failed\n", __func__, __LINE__);
    return NULL;
  }

  utxo_input_ht *elm, *tmp;
  HASH_ITER(hh, es->inputs, elm, tmp) {
    cJSON* item = cJSON_CreateObject();
    if (!item) {
      printf("[%s:%d] creating input item object failed\n", __func__, __LINE__);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add type
    if (!cJSON_AddNumberToObject(item, "type", 0)) {
      printf("[%s:%d] add input type failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add tx id
    if (bin2hex(elm->tx_id, TRANSACTION_ID_BYTES, tx_id_str, sizeof(tx_id_str)) != 0) {
      printf("[%s:%d] tx id convertion failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    if (!cJSON_AddStringToObject(item, "transactionId", tx_id_str)) {
      printf("[%s:%d] add tx id to item failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add index
    if (!cJSON_AddNumberToObject(item, "transactionOutputIndex", elm->output_index)) {
      printf("[%s:%d] add input type failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add item to array
    cJSON_AddItemToArray(input_arr, item);
  }

  return input_arr;
}

// serialize utxo output array to a JSON object
static cJSON* tx_outputs_to_json(transaction_essence_t* es) {
  /*
  [
    {
      "type": 0,
      "address": {
        "type": 1,
        "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
      },
      "amount": 1000
    }
  ]
  */
  char addr_str[ED25519_ADDRESS_BYTES * 2 + 1] = {};
  cJSON* output_arr = NULL;

  if (!es->outputs) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if ((output_arr = cJSON_CreateArray()) == NULL) {
    printf("[%s:%d] creating output array failed\n", __func__, __LINE__);
    return NULL;
  }

  sig_unlocked_outputs_ht *elm, *tmp;
  HASH_ITER(hh, es->outputs, elm, tmp) {
    cJSON* item = cJSON_CreateObject();
    if (!item) {
      printf("[%s:%d] creating output item object failed\n", __func__, __LINE__);
      cJSON_Delete(output_arr);
      return NULL;
    }

    // add type
    if (!cJSON_AddNumberToObject(item, "type", 0)) {
      printf("[%s:%d] add output type failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(output_arr);
      return NULL;
    }

    // new address object
    cJSON* addr_obj = cJSON_CreateObject();
    if (!addr_obj) {
      printf("[%s:%d] creating output address object failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(output_arr);
      return NULL;
    }

    // add address type, using ed25519 address schema
    if (!cJSON_AddNumberToObject(addr_obj, "type", 1)) {
      printf("[%s:%d] creating output address object failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(output_arr);
      cJSON_Delete(addr_obj);
      return NULL;
    }

    // add address hash
    if (bin2hex(elm->address, ED25519_ADDRESS_BYTES, addr_str, sizeof(addr_str)) != 0) {
      printf("[%s:%d] address convertion failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(output_arr);
      cJSON_Delete(addr_obj);
      return NULL;
    }

    if (!cJSON_AddStringToObject(addr_obj, "address", addr_str)) {
      printf("[%s:%d] add address hash failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(output_arr);
      cJSON_Delete(addr_obj);
      return NULL;
    }
    // add address object to item
    cJSON_AddItemToObject(item, "address", addr_obj);

    // add amount
    if (!cJSON_AddNumberToObject(item, "amount", elm->amount)) {
      printf("[%s:%d] add amount failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(output_arr);
      return NULL;
    }

    // add item to array
    cJSON_AddItemToArray(output_arr, item);
  }

  return output_arr;
}

// serialize transaction essence to a JSON object
static cJSON* tx_essence_to_json(transaction_essence_t* es) {
  /*
  {
    "type": 0,
    "inputs": input_array
    "outputs": output_array
    "payload": null
  }
  */

  cJSON* es_obj = NULL;
  cJSON* input_arr = NULL;
  cJSON* output_arr = NULL;

  if (!es) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create essence object
  if ((es_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tx essence object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 0,
  if (!cJSON_AddNumberToObject(es_obj, "type", 0)) {
    printf("[%s:%d] add tx type failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }

  // input array
  if ((input_arr = tx_inputs_to_json(es)) == NULL) {
    printf("[%s:%d] add inputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, "inputs", input_arr);

  // output array
  if ((output_arr = tx_outputs_to_json(es)) == NULL) {
    printf("[%s:%d] add outputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, "outputs", output_arr);

  // optional payload
  if (es->payload) {
    // TODO support different payload type
    cJSON* idx_payload = indexation_to_json((indexation_t*)es->payload);
    if (idx_payload) {
      // add a indexation payload to essence
      cJSON_AddItemToObject(es_obj, "payload", idx_payload);
    } else {
      printf("[%s:%d] add indexation payload failed\n", __func__, __LINE__);
      cJSON_Delete(es_obj);
      return NULL;
    }
  } else {
    // add a null payload to essence
    if (!cJSON_AddNullToObject(es_obj, "payload")) {
      printf("[%s:%d] add null payload failed\n", __func__, __LINE__);
      cJSON_Delete(es_obj);
      return NULL;
    }
  }

  return es_obj;
}

// serialize unlocked block array to a JSON object
static cJSON* tx_blocks_to_json(tx_unlock_blocks_t* blocks) {
  /*
  [
    {
      "type": 0,
      "signature": {
        "type": 1,
        "publicKey": "dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a",
        "signature": "e625a71351bbccf87c14932be47c43......493c14932be47c432be47c439a1a8ad242606"
      }
    },
    {
      "type": 1,
      "reference": 0
    }
  ]
  */
  char pub_str[ED_PUBLIC_KEY_BYTES * 2 + 1] = {};
  char sig_str[ED_PRIVATE_KEY_BYTES * 2 + 1] = {};
  cJSON* block_arr = NULL;

  if (!blocks) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // new unlocked block array
  if ((block_arr = cJSON_CreateArray()) == NULL) {
    printf("[%s:%d] creating unlocked block array failed\n", __func__, __LINE__);
    return NULL;
  }

  tx_unlock_blocks_t* elm;
  DL_FOREACH(blocks, elm) {
    if (elm->type == 0) {  // signature block
      cJSON* sig_block = cJSON_CreateObject();
      if (!sig_block) {
        printf("[%s:%d] new signature item failed\n", __func__, __LINE__);
        cJSON_Delete(block_arr);
        return NULL;
      }

      // add type to item, 0 denote as a signature block
      if (!cJSON_AddNumberToObject(sig_block, "type", 0)) {
        printf("[%s:%d] add reference type failed\n", __func__, __LINE__);
        cJSON_Delete(sig_block);
        cJSON_Delete(block_arr);
        return NULL;
      }

      cJSON* sig_obj = cJSON_CreateObject();
      if (!sig_obj) {
        printf("[%s:%d] new signature obj failed\n", __func__, __LINE__);
        cJSON_Delete(block_arr);
        return NULL;
      }

      // add signature type to item, 1 denote as an ed25519 signature
      if (!cJSON_AddNumberToObject(sig_obj, "type", 1)) {
        printf("[%s:%d] add reference type failed\n", __func__, __LINE__);
        cJSON_Delete(sig_obj);
        cJSON_Delete(block_arr);
        return NULL;
      }

      // convert signature to string
      bin2hex(elm->signature.pub_key, ED_PUBLIC_KEY_BYTES, pub_str, sizeof(pub_str));
      if (!cJSON_AddStringToObject(sig_obj, "publicKey", pub_str)) {
        printf("[%s:%d] add public key failed\n", __func__, __LINE__);
        cJSON_Delete(sig_obj);
        cJSON_Delete(block_arr);
        return NULL;
      }

      bin2hex(elm->signature.signature, ED_PRIVATE_KEY_BYTES, sig_str, sizeof(sig_str));
      if (!cJSON_AddStringToObject(sig_obj, "signature", sig_str)) {
        printf("[%s:%d] add signature failed\n", __func__, __LINE__);
        cJSON_Delete(sig_obj);
        cJSON_Delete(block_arr);
        return NULL;
      }

      // add signature to array
      cJSON_AddItemToObject(sig_block, "signature", sig_obj);
      cJSON_AddItemToArray(block_arr, sig_block);

    } else if (elm->type == 1) {  // reference block
      // new ref obj and add to array
      cJSON* ref = cJSON_CreateObject();
      if (!ref) {
        printf("[%s:%d] new reference item failed\n", __func__, __LINE__);
        cJSON_Delete(block_arr);
        return NULL;
      }

      // add type to item, 1 denote as a reference block
      if (!cJSON_AddNumberToObject(ref, "type", 1)) {
        printf("[%s:%d] add reference type failed\n", __func__, __LINE__);
        cJSON_Delete(ref);
        cJSON_Delete(block_arr);
        return NULL;
      }

      // add reference to array
      if (!cJSON_AddNumberToObject(ref, "reference", elm->reference)) {
        printf("[%s:%d] add reference failed\n", __func__, __LINE__);
        cJSON_Delete(ref);
        cJSON_Delete(block_arr);
        return NULL;
      }
      cJSON_AddItemToArray(block_arr, ref);

    } else {
      printf("[%s:%d] Unkown unlocked block type\n", __func__, __LINE__);
    }
  }

  return block_arr;
}

// serialize a transaction payload to a JSON object
static cJSON* tx_payload_to_json(transaction_payload_t* tx) {
  /*
  {
    "type": 0,
    "essence": essence object
    "unlockBlocks": unlock blocks object
  }
  */
  cJSON* tx_payload = NULL;
  cJSON* essence = NULL;
  cJSON* blocks = NULL;

  if (!tx) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create payload object
  if ((tx_payload = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tx payload object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 0,
  if (!cJSON_AddNumberToObject(tx_payload, "type", 0)) {
    printf("[%s:%d] add payload type failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }

  // essence
  if ((essence = tx_essence_to_json(tx->essence)) == NULL) {
    printf("[%s:%d] create essence object failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }
  cJSON_AddItemToObject(tx_payload, "essence", essence);

  // unlocked blocks
  if ((blocks = tx_blocks_to_json(tx->unlock_blocks)) == NULL) {
    printf("[%s:%d] create unlocked blocks object failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }
  cJSON_AddItemToObject(tx_payload, "unlockBlocks", blocks);

  return tx_payload;
}

// serialize a message to a string for sending to a node
char* message_to_json(core_message_t* msg) {
  /*
  {
  "networkId": "6530425480034647824",
  "parent1MessageId": "0b80adc0ca06b21842ac50d32e8132cf369d5e6a556e8454fdc846fd821d0fa2",
  "parent2MessageId": "32105f6889424d264774ce7d086ffd3629719b909f64737708c6a9e719389072",
  "payload": payload object
  "nonce": "2695978"
  }
  */
  char* json_str = NULL;
  cJSON* msg_obj = NULL;
  cJSON* payload = NULL;
  char tmp_str[IOTA_MESSAGE_ID_BYTES * 2 + 1] = {};

  if (!msg) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create message object
  if ((msg_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    return NULL;
  }

  // add network ID
  if (msg->network_id > 0) {
    if (!cJSON_AddNumberToObject(msg_obj, "networkId", msg->network_id)) {
      printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if (!cJSON_AddNullToObject(msg_obj, "networkId")) {
      printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  }

  // add parent1
  bin2hex(msg->parent1, IOTA_MESSAGE_ID_BYTES, tmp_str, sizeof(tmp_str));
  if (!cJSON_AddStringToObject(msg_obj, "parent1MessageId", tmp_str)) {
    printf("[%s:%d] creating parent1 failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }

  // add parent1
  bin2hex(msg->parent2, IOTA_MESSAGE_ID_BYTES, tmp_str, sizeof(tmp_str));
  if (!cJSON_AddStringToObject(msg_obj, "parent2MessageId", tmp_str)) {
    printf("[%s:%d] creating parent2 failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }

  // add payload
  switch (msg->payload_type) {
    case 0:
      payload = tx_payload_to_json((transaction_payload_t*)msg->payload);
      break;
    case 1:
      printf("[%s:%d] TODO\n", __func__, __LINE__);
      break;
    case 2:
      payload = indexation_to_json((indexation_t*)msg->payload);
      break;
    default:
      printf("[%s:%d] Unknow payload type\n", __func__, __LINE__);
      break;
  }

  if (payload == NULL) {
    printf("[%s:%d] creating payload failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }
  cJSON_AddItemToObject(msg_obj, "payload", payload);

  // add nonce
  if (msg->nonce > 0) {
    if (!cJSON_AddNumberToObject(msg_obj, "nonce", msg->nonce)) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if (!cJSON_AddNullToObject(msg_obj, "nonce")) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  }

  // json object to json string
  if ((json_str = cJSON_PrintUnformatted(msg_obj)) == NULL) {
    printf("[%s:%d] convert to string failed\n", __func__, __LINE__);
  }
  cJSON_Delete(msg_obj);

  return json_str;
}
