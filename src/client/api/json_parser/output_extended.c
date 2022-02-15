// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/output_extended.h"
#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/native_tokens.h"
#include "client/api/json_parser/unlock_conditions.h"

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
int json_output_extended_deserialize(cJSON *output_obj, utxo_outputs_list_t **outputs) {
  if (output_obj == NULL || outputs == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_t *tokens = native_tokens_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  output_extended_t *output = NULL;

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
  if (json_feat_blocks_deserialize(output_obj, &feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }

  // create extended output
  output = output_extended_new(amount, tokens, cond_blocks, feat_blocks);
  if (!output) {
    printf("[%s:%d]: creating output object failed \n", __func__, __LINE__);
    goto end;
  }

  // add new output into a list
  if (utxo_outputs_add(outputs, OUTPUT_EXTENDED, output) != 0) {
    printf("[%s:%d] can not add new output into a list\n", __func__, __LINE__);
    goto end;
  }

  // Successfully added new output into a list
  result = 0;

end:
  native_tokens_free(&tokens);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  output_extended_free(output);

  return result;
}

cJSON *json_output_extended_serialize(output_extended_t *extended) {
  cJSON *output_obj = cJSON_CreateObject();
  if (output_obj) {
    cJSON *tmp = NULL;
    // type
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_TYPE, OUTPUT_EXTENDED)) {
      printf("[%s:%d] add type to extended error\n", __func__, __LINE__);
      goto err;
    }

    // amount
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_AMOUNT, extended->amount)) {
      printf("[%s:%d] add amount to extended error\n", __func__, __LINE__);
      goto err;
    }

    // native tokens
    tmp = json_native_tokens_serialize(extended->native_tokens);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_NATIVE_TOKENS, tmp)) {
      printf("[%s:%d] add native tokens to extended error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // unlock conditions
    tmp = json_cond_blk_list_serialize(extended->unlock_conditions);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions to extended error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // feature blocks
    tmp = json_feat_blocks_serialize(extended->feature_blocks);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_FEAT_BLOCKS, tmp)) {
      printf("[%s:%d] add feature blocks to extended error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
