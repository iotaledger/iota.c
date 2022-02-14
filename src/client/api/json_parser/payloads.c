// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/inputs.h"
#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/outputs.h"
#include "client/api/json_parser/payloads.h"
#include "client/api/json_parser/unlock_blocks.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"

static cJSON* json_tx_essence_serialize(transaction_essence_t* es) {
  /*
  {
    "type": 0,
    "inputs": input_array
    "outputs": output_array
    "payload": payload object
  }
  */

  cJSON* es_obj = NULL;
  cJSON* input_arr = NULL;
  cJSON* output_arr = NULL;
  cJSON* payload_obj = NULL;

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
  if (!cJSON_AddNumberToObject(es_obj, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TRANSACTION)) {
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
    if ((payload_obj = json_tagged_serialize(es->payload)) == NULL) {
      printf("[%s:%d] add payload failed\n", __func__, __LINE__);
      cJSON_Delete(es_obj);
      return NULL;
    }
    cJSON_AddItemToObject(es_obj, JSON_KEY_PAYLOAD, payload_obj);
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

static int json_essence_payload_deserialize(cJSON* essence_payload, tagged_data_t** tagged_data,
                                            uint32_t* payload_len) {
  if (!essence_payload || !tagged_data) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // type
  uint8_t type;
  if (json_get_uint8(essence_payload, JSON_KEY_TYPE, &type) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
    return -1;
  }

  switch (type) {
    case CORE_MESSAGE_PAYLOAD_TAGGED:
      if (json_tagged_deserialize(essence_payload, tagged_data) != 0) {
        printf("[%s:%d] Can not deserialize tagged data\n", __func__, __LINE__);
        return -1;
      }
      *payload_len = tagged_data_serialize_len(*tagged_data);
      break;
    default:
      printf("[%s:%d] Unknown payload type\n", __func__, __LINE__);
      return -1;
  }

  return 0;
}

int json_transaction_deserialize(cJSON* payload, transaction_payload_t* tx) {
  if (!payload || !tx) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // parsing essence
  cJSON* essence_obj = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_ESSENCE);
  if (essence_obj) {
    // network ID
    char str_buff[32];
    if ((json_get_string(essence_obj, JSON_KEY_NET_ID, str_buff, sizeof(str_buff))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NET_ID);
      return -1;
    }
    sscanf(str_buff, "%" SCNu64, &tx->essence->tx_network_id);

    // inputs array
    cJSON* inputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
    if (cJSON_IsArray(inputs_obj)) {
      if (json_inputs_deserialize(inputs_obj, &tx->essence->inputs) != 0) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
      return -1;
    }

    // outputs array
    cJSON* outputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_OUTPUTS);
    if (cJSON_IsArray(outputs_obj)) {
      if (json_outputs_deserialize(outputs_obj, &tx->essence->outputs) != 0) {
        return -1;
      }
    } else {
      printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
      return -1;
    }

    // payload in an essence
    cJSON* payload_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_PAYLOAD);
    if (!cJSON_IsNull(payload_obj)) {
      if (json_essence_payload_deserialize(payload_obj, (tagged_data_t**)(&tx->essence->payload),
                                           &tx->essence->payload_len) != 0) {
        return -1;
      }
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
  if (!cJSON_AddNumberToObject(tx_payload, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TRANSACTION)) {
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

cJSON* json_tagged_serialize(tagged_data_t* tagged_data) {
  /*
  {
    "type": 5,
    "tag": "484f524e455420464155434554"
    "data": "494f5441202d2041206e6577206461776e0a436f756e743a203138393030350a5032c2b573"
  }
  */
  cJSON* tagged_data_payload = NULL;

  if (!tagged_data) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create payload object
  if ((tagged_data_payload = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating tagged data payload object failed\n", __func__, __LINE__);
    return NULL;
  }

  // "type": 5,
  if (!cJSON_AddNumberToObject(tagged_data_payload, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TAGGED)) {
    printf("[%s:%d] add payload type failed\n", __func__, __LINE__);
    cJSON_Delete(tagged_data_payload);
    return NULL;
  }

  // tag
  if (tagged_data->tag) {
    if (!cJSON_AddStringToObject(tagged_data_payload, JSON_KEY_TAG, (const char* const)tagged_data->tag->data)) {
      printf("[%s:%d] add tag type failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
  } else {
    // add a null tag to tagged data
    if (!cJSON_AddNullToObject(tagged_data_payload, JSON_KEY_TAG)) {
      printf("[%s:%d] add null tag payload failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
  }

  // data
  if (tagged_data->data) {
    char* data_str = malloc(BIN_TO_HEX_STR_BYTES(tagged_data->data->len));
    if (!data_str) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
    if (bin_2_hex(tagged_data->data->data, tagged_data->data->len, data_str, sizeof(data_str)) != 0) {
      printf("[%s:%d] bin to hex data conversion failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      free(data_str);
      return NULL;
    }
    if (!cJSON_AddStringToObject(tagged_data_payload, JSON_KEY_DATA, data_str)) {
      printf("[%s:%d] add data type failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      free(data_str);
      return NULL;
    }
    free(data_str);
  } else {
    // add a null data to tagged data
    if (!cJSON_AddNullToObject(tagged_data_payload, JSON_KEY_DATA)) {
      printf("[%s:%d] add null data payload failed\n", __func__, __LINE__);
      cJSON_Delete(tagged_data_payload);
      return NULL;
    }
  }

  return tagged_data_payload;
}

int json_tagged_deserialize(cJSON* payload, tagged_data_t** tagged_data) {
  if (!payload) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // tag
  cJSON* json_tag = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_TAG);
  if (json_tag == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, JSON_KEY_TAG);
    return -1;
  }

  // data
  cJSON* json_data = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_DATA);
  if (json_tag == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, JSON_KEY_DATA);
    return -1;
  }

  // create a new tagged data
  if (cJSON_IsString(json_tag) && cJSON_IsString(json_data)) {
    *tagged_data =
        tagged_data_create(json_tag->valuestring, (byte_t*)json_data->valuestring, strlen(json_data->valuestring));
    if (!*tagged_data) {
      printf("[%s:%d]: can not create a new tagged data payload\n", __func__, __LINE__);
      return -1;
    }
  } else {
    printf("[%s:%d] tag or data is not a string\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}
