// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_utils.h"
#include "client/api/message_builder.h"

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
  cJSON* p_type = NULL;
  cJSON* p_index = NULL;
  cJSON* p_data = NULL;

  if (!index) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if ((payload_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating payload object failed\n", __func__, __LINE__);
    return NULL;
  }

  // type 2 denote as an indexation payload
  if ((p_type = cJSON_CreateNumber(2)) == NULL) {
    printf("[%s:%d] creating payload type failed\n", __func__, __LINE__);
    cJSON_Delete(payload_obj);
    return NULL;
  }
  cJSON_AddItemToObject(payload_obj, "type", p_type);

  // make sure index is a string
  byte_buf2str(index->index);
  if ((p_index = cJSON_CreateString((char const*)index->index->data)) == NULL) {
    printf("[%s:%d] creating index failed\n", __func__, __LINE__);
    cJSON_Delete(payload_obj);
    return NULL;
  }
  cJSON_AddItemToObject(payload_obj, "index", p_index);

  byte_buf2str(index->data);
  if ((p_data = cJSON_CreateString((char const*)index->data->data)) == NULL) {
    printf("[%s:%d] creating data failed\n", __func__, __LINE__);
    cJSON_Delete(payload_obj);
    return NULL;
  }
  cJSON_AddItemToObject(payload_obj, "data", p_data);

  return payload_obj;
}

static cJSON* tx_essence_to_json(transaction_essence_t* es) {
  // TODO
  return NULL;
}

static cJSON* tx_to_json(transaction_payload_t* tx) {
  // TODO
  return NULL;
}

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
  cJSON* net_id = NULL;
  cJSON* p1_id = NULL;
  cJSON* p2_id = NULL;
  cJSON* payload = NULL;
  cJSON* nonce = NULL;
  char tmp_str[IOTA_MESSAGE_ID_BYTES * 2 + 1] = {};

  // create message object
  if ((msg_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    return NULL;
  }

  // add network ID
  if (msg->network_id > 0) {
    if ((net_id = cJSON_CreateNumber(msg->network_id)) == NULL) {
      printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if ((net_id = cJSON_CreateNull()) == NULL) {
      printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  }
  cJSON_AddItemToObject(msg_obj, "networkId", net_id);

  // add parent1
  bin2hex(msg->parent1, IOTA_MESSAGE_ID_BYTES, tmp_str, sizeof(tmp_str));
  if ((p1_id = cJSON_CreateString(tmp_str)) == NULL) {
    printf("[%s:%d] creating parent1 failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }
  cJSON_AddItemToObject(msg_obj, "parent1MessageId", p1_id);

  // add parent1
  bin2hex(msg->parent2, IOTA_MESSAGE_ID_BYTES, tmp_str, sizeof(tmp_str));
  if ((p2_id = cJSON_CreateString(tmp_str)) == NULL) {
    printf("[%s:%d] creating parent2 failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }
  cJSON_AddItemToObject(msg_obj, "parent2MessageId", p2_id);

  // add payload
  switch (msg->payload_type) {
    case 0:
    case 1:
      printf("[%s:%d] TODO\n", __func__, __LINE__);
      break;
    case 2:
      payload = indexation_to_json((indexation_t*)msg->pyaload);
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
    if ((nonce = cJSON_CreateNumber(msg->nonce)) == NULL) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if ((nonce = cJSON_CreateNull()) == NULL) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  }
  cJSON_AddItemToObject(msg_obj, "nonce", nonce);

  // json object to json string
  if ((json_str = cJSON_PrintUnformatted(msg_obj)) == NULL) {
    printf("[%s:%d] convert to string failed\n", __func__, __LINE__);
  }
  cJSON_Delete(msg_obj);

  return json_str;
}
