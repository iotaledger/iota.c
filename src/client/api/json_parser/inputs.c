// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/inputs.h"
#include "core/models/message.h"

/*
  "inputs": [
    {
      "type": 0,
      "transactionId": "2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03",
      "transactionOutputIndex": 1
    },
  ]
*/
int json_inputs_deserialize(cJSON *essence_obj, transaction_essence_t *essence) {
  if (essence_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // inputs
  cJSON *inputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
  if (!cJSON_IsArray(inputs_obj)) {
    printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, inputs_obj) {
    // type
    cJSON *input_type_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TYPE);
    if (!cJSON_IsNumber(input_type_obj)) {
      printf("[%s:%d] %s is not a number\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // transactionId
    cJSON *input_tx_id_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TX_ID);
    byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];
    char *id_str = cJSON_GetStringValue(input_tx_id_obj);
    if (id_str) {
      if (hex_2_bin(id_str, IOTA_TRANSACTION_ID_HEX_BYTES, tx_id, IOTA_TRANSACTION_ID_BYTES) != 0) {
        printf("[%s:%d] can not convert hex to bin number\n", __func__, __LINE__);
        return -1;
      }
    } else {
      printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_TX_ID);
      return -1;
    }

    // transactionOutputIndex
    cJSON *input_tx_out_index_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TX_OUT_INDEX);
    if (!cJSON_IsNumber(input_tx_out_index_obj)) {
      printf("[%s:%d] %s is not a number\n", __func__, __LINE__, JSON_KEY_TX_OUT_INDEX);
      return -1;
    }

    // add new input to inputs list
    if (utxo_inputs_add(&essence->inputs, input_type_obj->valueint, tx_id, input_tx_out_index_obj->valueint) != 0) {
      printf("[%s:%d] can not add new input into a list\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}
