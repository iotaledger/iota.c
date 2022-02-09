// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/output_alias.h"
#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/native_tokens.h"
#include "client/api/json_parser/unlock_conditions.h"
#include "core/models/outputs/output_alias.h"

/*
  "outputs": [
    { "type": 4,
      "amount": 10000000,
      "nativeTokens": [],
      "aliasId": "a360c46a570510f7c7d915bf0eef932e5678b386",
      "stateIndex": 12345,
      "stateMetadata": "010203040506070809",
      "foundryCounter": 54321,
      "unlockConditions": [],
      "featureBlocks": []
    }
  ]
*/
int json_output_alias_deserialize(cJSON *output_obj, transaction_essence_t *essence) {
  if (output_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_t *tokens = native_tokens_new();
  byte_buf_t *state_metadata = byte_buf_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  output_alias_t *output = NULL;

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

  // aliasId
  byte_t alias_id[ADDRESS_ALIAS_BYTES];
  if (json_get_string(output_obj, JSON_KEY_ALIAS_ID, (char *)alias_id, ADDRESS_ALIAS_BYTES) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_ALIAS_ID);
    goto end;
  }

  // stateIndex
  uint32_t state_index;
  if (json_get_uint32(output_obj, JSON_KEY_STATE_INDEX, &state_index) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_STATE_INDEX);
    goto end;
  }

  // stateMetadata
  if (json_get_byte_buf_str(output_obj, JSON_KEY_STATE_METADATA, state_metadata) != JSON_OK) {
    printf("[%s:%d]: getting %s json byte buffer failed\n", __func__, __LINE__, JSON_KEY_STATE_METADATA);
    goto end;
  }

  // foundryCounter
  uint32_t foundry_counter;
  if (json_get_uint32(output_obj, JSON_KEY_FOUNDRY_COUNTER, &foundry_counter) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_FOUNDRY_COUNTER);
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

  // create alias output
  output = output_alias_new(amount, tokens, alias_id, state_index, state_metadata->data, state_metadata->len,
                            foundry_counter, cond_blocks, feat_blocks);
  if (!output) {
    printf("[%s:%d]: creating output object failed \n", __func__, __LINE__);
    goto end;
  }

  // add new output into a list
  if (tx_essence_add_output(essence, OUTPUT_ALIAS, output) != 0) {
    printf("[%s:%d] can not add new output into a list\n", __func__, __LINE__);
    goto end;
  }

  // Successfully added new output into a list
  result = 0;

end:
  native_tokens_free(&tokens);
  byte_buf_free(state_metadata);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  output_alias_free(output);

  return result;
}

cJSON *json_output_alias_serialize(output_alias_t *alias) {
  // TODO
  return NULL;
}
