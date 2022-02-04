// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/output_extended.h"
#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/native_tokens.h"
#include "client/api/json_parser/unlock_conditions.h"
#include "core/models/outputs/output_extended.h"

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
int json_output_extended_deserialize(cJSON *output_obj, transaction_essence_t *essence) {
  if (output_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  // amount
  uint64_t amount;
  if (json_get_uint64(output_obj, JSON_KEY_AMOUNT, &amount) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint64 failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    goto end;
  }

  // native tokens array
  native_tokens_t *tokens = native_tokens_new();
  if (json_native_tokens_deserialize(output_obj, &tokens) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
    goto end;
  }

  // unlock conditions array
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  if (json_cond_blk_list_deserialize(output_obj, &cond_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    goto end;
  }

  // feature blocks array
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  if (json_feat_blocks_deserialize(output_obj, &feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }

  // create extended output
  output_extended_t *output = output_extended_new(amount, tokens, cond_blocks, feat_blocks);
  if (!output) {
    printf("[%s:%d]: creating output object failed \n", __func__, __LINE__);
    goto end;
  }

  // add new output into a list
  if (tx_essence_add_output(essence, OUTPUT_EXTENDED, output) != 0) {
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
