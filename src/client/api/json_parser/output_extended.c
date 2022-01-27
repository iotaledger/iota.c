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
      "blocks": []
    }
  ]
*/
int json_output_extended_deserialize(cJSON *output_obj, transaction_essence_t *essence) {
  if (output_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  output_extended_t output = {};

  cJSON *amount_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_AMOUNT);
  if (cJSON_IsNumber(amount_obj)) {
    output.amount = (uint64_t)amount_obj->valuedouble;
  } else {
    printf("[%s:%d] parsing %s failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    return -1;
  }

  cJSON *nativeTokens_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_NATIVE_TOKENS);
  if (!cJSON_IsArray(nativeTokens_obj) ||
      (json_native_tokens_deserialize(nativeTokens_obj, output.native_tokens) != 0)) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
    return -1;
  }

#if 0  // FIXME
  cJSON *unlock_conditions_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_UNLOCK_CONDITIONS);
  if (!cJSON_IsArray(unlock_conditions_obj) || (json_cond_blk_list_deserialize(unlock_conditions_obj, output.unlockConds) != 0)) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    return -1;
  }
#endif

  cJSON *feature_blocks_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEAT_BLOCKS);
  if (!cJSON_IsArray(feature_blocks_obj) ||
      (json_feat_blocks_deserialize(feature_blocks_obj, output.feature_blocks) != 0)) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    return -1;
  }

  if (tx_essence_add_output(essence, OUTPUT_EXTENDED, &output) != 0) {
    printf("[%s:%d] can not add new output into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}
