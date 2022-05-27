// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/outputs/features.h"
#include "client/api/json_parser/outputs/native_tokens.h"
#include "client/api/json_parser/outputs/output_basic.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "core/models/outputs/outputs.h"

/*
  "outputs": [
    { "type": 3,
      "amount": "10000000",
      "nativeTokens": [],
      "unlockConditions": [],
      "featureBlocks": []
    }
  ]
*/
int json_output_basic_deserialize(cJSON *output_obj, output_basic_t **basic) {
  if (output_obj == NULL || *basic != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_list_t *tokens = native_tokens_new();
  unlock_cond_list_t *cond_list = condition_list_new();
  feature_list_t *features = feature_list_new();

  // amount
  uint64_t amount;
  char str_buff[32];
  if (json_get_string(output_obj, JSON_KEY_AMOUNT, str_buff, sizeof(str_buff)) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    goto end;
  }
  sscanf(str_buff, "%" SCNu64, &amount);

  // native tokens array
  if (cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_NATIVE_TOKENS) != NULL) {
    if (json_native_tokens_deserialize(output_obj, &tokens) != 0) {
      printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
      goto end;
    }
  }

  // unlock conditions array
  if (json_condition_list_deserialize(output_obj, &cond_list) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    goto end;
  }

  // features array
  if (cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEATURES) != NULL) {
    if (json_features_deserialize(output_obj, false, &features) != 0) {
      printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEATURES);
      goto end;
    }
  }

  // create basic output
  *basic = output_basic_new(amount, tokens, cond_list, features);
  if (!*basic) {
    printf("[%s:%d]: creating basic output object failed \n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new basic output
  result = 0;

end:
  native_tokens_free(tokens);
  condition_list_free(cond_list);
  feature_list_free(features);

  return result;
}

cJSON *json_output_basic_serialize(output_basic_t *basic) {
  cJSON *output_obj = cJSON_CreateObject();
  if (output_obj) {
    cJSON *tmp = NULL;
    // type
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_TYPE, OUTPUT_BASIC)) {
      printf("[%s:%d] add type to basic error\n", __func__, __LINE__);
      goto err;
    }

    // amount
    char amount_str[65] = {};
    sprintf(amount_str, "%" PRIu64 "", basic->amount);
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_AMOUNT, amount_str)) {
      printf("[%s:%d] add amount to basic error\n", __func__, __LINE__);
      goto err;
    }

    // native tokens
    tmp = json_native_tokens_serialize(basic->native_tokens);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_NATIVE_TOKENS, tmp)) {
      printf("[%s:%d] add native tokens to basic error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // unlock conditions
    tmp = json_condition_list_serialize(basic->unlock_conditions);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions to basic error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // features
    tmp = json_features_serialize(basic->features);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_FEATURES, tmp)) {
      printf("[%s:%d] add features to basic error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
