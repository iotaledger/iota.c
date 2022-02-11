// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/payloads.h"
#include "client/api/json_parser/inputs.h"
#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/outputs.h"
#include "client/api/json_parser/unlock_blocks.h"

static cJSON* json_tx_essence_serialize(transaction_essence_t* es) {
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

  if (es->tx_type != 0) {
    printf("[%s:%d] invalid transaction essence\n", __func__, __LINE__);
    return NULL;
  }

  // create essence object
  if ((es_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tx essence object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 0 to denote a Transaction Essence.
  if (!cJSON_AddNumberToObject(es_obj, JSON_KEY_TYPE, 0)) {
    printf("[%s:%d] add tx type failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }

  // input array
  if ((input_arr = json_inputs_serialize(es->inputs)) == NULL) {
    printf("[%s:%d] add inputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, JSON_KEY_INPUTS, input_arr);

  // output array
  if ((output_arr = json_outputs_serialize(es->outputs)) == NULL) {
    printf("[%s:%d] add outputs failed\n", __func__, __LINE__);
    cJSON_Delete(es_obj);
    return NULL;
  }
  cJSON_AddItemToObject(es_obj, JSON_KEY_OUTPUTS, output_arr);

  // optional payload
  if (es->payload) {
    // TODO support payload in a tx essence
    printf("[%s:%d] TODO: support payload in tx essence\n", __func__, __LINE__);
  } else {
    // add a null payload to essence
    if (!cJSON_AddNullToObject(es_obj, JSON_KEY_PAYLOAD)) {
      printf("[%s:%d] add null payload failed\n", __func__, __LINE__);
      cJSON_Delete(es_obj);
      return NULL;
    }
  }

  return es_obj;
}

int json_transaction_deserialize(cJSON* payload, transaction_payload_t* tx) {
  if (!payload || !tx) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // parsing essence
  cJSON* essence_obj = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_ESSENCE);
  if (essence_obj) {
    // inputs array
    cJSON* inputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
    if (cJSON_IsArray(inputs_obj)) {
      if (json_inputs_deserialize(inputs_obj, &tx->essence->inputs)) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
      return -1;
    }

    // outputs array
    cJSON* outputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_OUTPUTS);
    if (cJSON_IsArray(outputs_obj)) {
      if (json_outputs_deserialize(outputs_obj, &tx->essence->outputs)) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
      return -1;
    }

    // payload in an essence
    cJSON* payload_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_PAYLOAD);
    if (!cJSON_IsNull(payload_obj)) {
      // TODO
      printf("[%s:%d]: TODO, support payload in an essence\n", __func__, __LINE__);
    }

  } else {
    printf("[%s:%d]: %s not found in the message\n", __func__, __LINE__, JSON_KEY_ESSENCE);
    return -1;
  }

  // unlock blocks
  cJSON* blocks_obj = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_UNLOCK_BLOCKS);
  if (cJSON_IsArray(blocks_obj)) {
    if (json_unlock_blocks_deserialize(blocks_obj, &tx->unlock_blocks)) {
      return -1;
    }
  } else {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_BLOCKS);
    return -1;
  }

  return 0;
}

cJSON* json_transaction_serialize(transaction_payload_t* tx) {
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
  if (!cJSON_AddNumberToObject(tx_payload, JSON_KEY_TYPE, 0)) {
    printf("[%s:%d] add payload type failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }

  // essence
  if ((essence = json_tx_essence_serialize(tx->essence)) == NULL) {
    printf("[%s:%d] create essence object failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }
  cJSON_AddItemToObject(tx_payload, JSON_KEY_ESSENCE, essence);

  // unlocked blocks
  if ((blocks = json_unlock_blocks_serialize(tx->unlock_blocks)) == NULL) {
    printf("[%s:%d] create unlocked blocks object failed\n", __func__, __LINE__);
    cJSON_Delete(tx_payload);
    return NULL;
  }
  cJSON_AddItemToObject(tx_payload, JSON_KEY_UNLOCK_BLOCKS, blocks);

  return tx_payload;
}

// TODO
cJSON* json_tagged_serialize(void* tx) { return NULL; }
