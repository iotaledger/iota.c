// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/outputs/output_basic.h"
#include "client/api/json_parser/outputs/feat_blocks.h"
#include "client/api/json_parser/outputs/native_tokens.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "core/models/outputs/outputs.h"

/*
  "outputs": [
    { "type": 3,
      "amount": 10000000,
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

  native_tokens_t *tokens = native_tokens_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();

  // amount
  uint64_t amount;
  if (json_get_uint64(output_obj, JSON_KEY_AMOUNT, &amount) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint64 failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    goto end;
  }

  // native tokens array
  if (json_native_tokens_deserialize(output_obj, &tokens) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
    goto end;
  }

  // unlock conditions array
  if (json_cond_blk_list_deserialize(output_obj, &cond_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    goto end;
  }

  // feature blocks array
  if (json_feat_blocks_deserialize(output_obj, false, &feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }

  // create basic output
  *basic = output_basic_new(amount, tokens, cond_blocks, feat_blocks);
  if (!*basic) {
    printf("[%s:%d]: creating basic output object failed \n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new basic output
  result = 0;

end:
  native_tokens_free(&tokens);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);

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
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_AMOUNT, basic->amount)) {
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
    tmp = json_cond_blk_list_serialize(basic->unlock_conditions);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions to basic error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // feature blocks
    tmp = json_feat_blocks_serialize(basic->feature_blocks);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_FEAT_BLOCKS, tmp)) {
      printf("[%s:%d] add feature blocks to basic error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
