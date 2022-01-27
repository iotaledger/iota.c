// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/native_tokens.h"

/*
  "nativeTokens": [
    { "id": "9s8dfzh987shfd098fjhg0b98du",
      "amount": "93847598347598347598347598",
    },
  ]
*/
int json_native_tokens_deserialize(cJSON *output_obj, native_tokens_t *native_tokens) {
  if (output_obj == NULL || native_tokens == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // native tokens
  cJSON *native_tokens_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_NATIVE_TOKENS);
  if (!cJSON_IsArray(native_tokens_obj)) {
    printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_INPUTS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, native_tokens_obj) {
    cJSON *token_id_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_ID);
    cJSON *token_amount_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_AMOUNT);

    if (cJSON_IsString(token_id_obj) && cJSON_IsString(token_amount_obj)) {
      byte_t token_id[NATIVE_TOKEN_ID_BYTES];
      memcpy(token_id, token_id_obj->valuestring, NATIVE_TOKEN_ID_BYTES);

      uint256_t *amount = uint256_from_str(token_amount_obj->valuestring);

      if (native_tokens_add(&native_tokens, token_id, amount) != 0) {
        printf("[%s:%d] can not add new native token into a list\n", __func__, __LINE__);
        free(amount);
        return -1;
      }
      free(amount);
    } else {
      printf("[%s:%d] %s or %s is not a string\n", __func__, __LINE__, JSON_KEY_ID, JSON_KEY_AMOUNT);
      return -1;
    }
  }

  return 0;
}
