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
int json_inputs_deserialize(cJSON *essence_obj, utxo_inputs_list_t *inputs) {
  if (essence_obj == NULL || inputs == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // inputs array
  cJSON *inputs_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
  if (!cJSON_IsArray(inputs_obj)) {
    printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
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
    char transaction_id_hex[ADDRESS_ED25519_HEX_BYTES];
    byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];
    if (json_get_string(elm, JSON_KEY_TX_ID, transaction_id_hex, IOTA_TRANSACTION_ID_HEX_BYTES) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_TX_ID);
      return -1;
    }
    if (hex_2_bin(transaction_id_hex, IOTA_TRANSACTION_ID_HEX_BYTES, tx_id, IOTA_TRANSACTION_ID_BYTES) != 0) {
      printf("[%s:%d] can not convert hex to bin number\n", __func__, __LINE__);
      return -1;
    }

    // transactionOutputIndex
    uint16_t output_index;
    if (json_get_uint16(elm, JSON_KEY_TX_OUT_INDEX, &output_index) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_TX_OUT_INDEX);
      return -1;
    }

    // add new input to inputs list
    if (utxo_inputs_add(&inputs, input_type, tx_id, output_index) != 0) {
      printf("[%s:%d] can not add new input into a list\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}
