// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/inputs/inputs.h"
#include "client/constants.h"
#include "core/models/message.h"
#include "core/utils/macros.h"
#include "utlist.h"

/*
  [
    {
      "type": 0,
      "transactionId": "0xb3e2d5466b68f7876e5647ada5dc6153bedd11182743dfde7b8e547cdd459d1e",
      "transactionOutputIndex": 1
    },
  ]
*/
int json_inputs_deserialize(cJSON *inputs_obj, utxo_inputs_list_t **inputs) {
  if (!inputs_obj || !inputs) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, inputs_obj) {
    // type
    uint8_t input_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &input_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // transactionId
    byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];
    if (json_get_hex_str_to_bin(elm, JSON_KEY_TX_ID, tx_id, sizeof(tx_id)) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_TX_ID);
      return -1;
    }

    // transactionOutputIndex
    uint16_t output_index;
    if (json_get_uint16(elm, JSON_KEY_TX_OUT_INDEX, &output_index) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_TX_OUT_INDEX);
      return -1;
    }

    // add new input to inputs list
    if (utxo_inputs_add(inputs, input_type, tx_id, output_index) != 0) {
      printf("[%s:%d] can not add new input into a list\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}

cJSON *json_inputs_serialize(utxo_inputs_list_t *inputs) {
  char tx_id_str[JSON_STR_WITH_PREFIX_BYTES(IOTA_TRANSACTION_ID_BYTES)] = {};
  cJSON *input_arr = NULL;

  // empty array
  if (!inputs) {
    return cJSON_CreateArray();
  }

  if ((input_arr = cJSON_CreateArray()) == NULL) {
    printf("[%s:%d] creating input array failed\n", __func__, __LINE__);
    return NULL;
  }

  utxo_inputs_list_t *elm;
  LL_FOREACH(inputs, elm) {
    cJSON *item = cJSON_CreateObject();
    if (!item) {
      printf("[%s:%d] creating input item object failed\n", __func__, __LINE__);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add type
    if (!cJSON_AddNumberToObject(item, JSON_KEY_TYPE, 0)) {
      printf("[%s:%d] add input type failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add tx id
    if (bin_2_hex(elm->input->tx_id, IOTA_TRANSACTION_ID_BYTES, JSON_HEX_ENCODED_STRING_PREFIX, tx_id_str,
                  sizeof(tx_id_str)) != 0) {
      printf("[%s:%d] tx id convertion failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    if (!cJSON_AddStringToObject(item, JSON_KEY_TX_ID, tx_id_str)) {
      printf("[%s:%d] add tx id to item failed\n", __func__, __LINE__);
      cJSON_Delete(item);
      cJSON_Delete(input_arr);
      return NULL;
    }

    // add index
    if (!cJSON_AddNumberToObject(item, JSON_KEY_TX_OUT_INDEX, elm->input->output_index)) {
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
