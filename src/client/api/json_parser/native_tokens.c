// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/native_tokens.h"

/*
  "nativeTokens": [
    { "id": "08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000000000000000000000000",
      "amount": "93847598347598347598347598",
    },
  ]
*/
int json_native_tokens_deserialize(cJSON *output_obj, native_tokens_t **native_tokens) {
  if (output_obj == NULL || native_tokens == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // native tokens array
  cJSON *native_tokens_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_NATIVE_TOKENS);
  if (!cJSON_IsArray(native_tokens_obj)) {
    printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, native_tokens_obj) {
    // id
    char token_id_hex[NATIVE_TOKEN_ID_HEX_BYTES];
    byte_t token_id[NATIVE_TOKEN_ID_BYTES];
    if (json_get_string(elm, JSON_KEY_ID, token_id_hex, NATIVE_TOKEN_ID_HEX_BYTES) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_ID);
      return -1;
    }
    if (hex_2_bin(token_id_hex, NATIVE_TOKEN_ID_HEX_BYTES, token_id, NATIVE_TOKEN_ID_BYTES) != 0) {
      printf("[%s:%d] can not convert hex to bin number\n", __func__, __LINE__);
      return -1;
    }

    // amount
    char token_amount[STRING_NUMBER_MAX_CHARACTERS];
    if (json_get_string(elm, JSON_KEY_AMOUNT, token_amount, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
      return -1;
    }
    uint256_t *amount = uint256_from_str(token_amount);

    // add new token into a list
    if (native_tokens_add(native_tokens, (byte_t *)token_id, amount) != 0) {
      printf("[%s:%d] can not add new native token into a list\n", __func__, __LINE__);
      free(amount);
      return -1;
    }
    free(amount);
  }

  return 0;
}
