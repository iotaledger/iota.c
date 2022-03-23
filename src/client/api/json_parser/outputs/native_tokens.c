// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/outputs/native_tokens.h"
#include "core/utils/macros.h"

/*
  "nativeTokens": [
    { "id": "0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000000000000000000000000",
      "amount": "0x93847598347598347598347598",
    },
  ]
*/
int json_native_tokens_deserialize(cJSON *output_obj, native_tokens_list_t **native_tokens) {
  if (output_obj == NULL || *native_tokens != NULL) {
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
    byte_t token_id[NATIVE_TOKEN_ID_BYTES];
    if (json_get_hex_str_to_bin(elm, JSON_KEY_ID, token_id, NATIVE_TOKEN_ID_BYTES) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_ID);
      return -1;
    }

    // amount
    char token_amount[STRING_NUMBER_MAX_CHARACTERS];
    if (json_get_string_with_prefix(elm, JSON_KEY_AMOUNT, token_amount, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
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

cJSON *json_native_tokens_serialize(native_tokens_list_t *native_tokens) {
  cJSON *tokens = cJSON_CreateArray();
  if (tokens) {
    if (!native_tokens) {
      // empty native tokens
      return tokens;
    }

    char token_id[BIN_TO_HEX_STR_BYTES(NATIVE_TOKEN_ID_BYTES) + JSON_HEX_ENCODED_STRING_PREFIX_LEN] = {};
    native_tokens_list_t *elm;
    LL_FOREACH(native_tokens, elm) {
      cJSON *item = cJSON_CreateObject();
      if (item) {
        // add token id
        token_id[0] = '0';
        token_id[1] = 'x';
        if (bin_2_hex(elm->token->token_id, NATIVE_TOKEN_ID_BYTES, token_id + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                      sizeof(token_id) - JSON_HEX_ENCODED_STRING_PREFIX_LEN) != 0) {
          goto item_err;
        }
        cJSON_AddStringToObject(item, JSON_KEY_ID, token_id);

        // add amount
        char *amount = uint256_to_str(&elm->token->amount);
        if (!amount) {
          goto item_err;
        }
        cJSON_AddStringToObject(item, JSON_KEY_AMOUNT, amount);
        free(amount);
      } else {
        printf("[%s:%d] new json object error\n", __func__, __LINE__);
        cJSON_Delete(tokens);
        return NULL;
      }

      // add item to array
      if (!cJSON_AddItemToArray(tokens, item)) {
      item_err:
        printf("[%s:%d] add item to array error\n", __func__, __LINE__);
        cJSON_Delete(item);
        cJSON_Delete(tokens);
        return NULL;
      }
    }
  }
  return tokens;
}
