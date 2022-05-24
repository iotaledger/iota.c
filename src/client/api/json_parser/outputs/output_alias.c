// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/outputs/feat_blocks.h"
#include "client/api/json_parser/outputs/native_tokens.h"
#include "client/api/json_parser/outputs/output_alias.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

/*
  "outputs": [
    { "type": 4,
      "amount": "10000000",
      "nativeTokens": [],
      "aliasId": "0x01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248",
      "stateIndex": 12345,
      "stateMetadata": "0x010203040506070809",
      "foundryCounter": 54321,
      "unlockConditions": [],
      "featureBlocks": [],
      "immutableFeatureBlocks" : []
    }
  ]
*/
int json_output_alias_deserialize(cJSON *output_obj, output_alias_t **alias) {
  if (output_obj == NULL || *alias != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_list_t *tokens = native_tokens_new();
  byte_buf_t *state_metadata = byte_buf_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  feat_blk_list_t *immut_feat_blocks = feat_blk_list_new();

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

  // aliasId
  byte_t alias_id[ALIAS_ID_BYTES];
  if (json_get_hex_str_to_bin(output_obj, JSON_KEY_ALIAS_ID, alias_id, ALIAS_ID_BYTES) != JSON_OK) {
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
  json_error_t ret = json_get_byte_buf_str(output_obj, JSON_KEY_STATE_METADATA, state_metadata);
  if ((ret != JSON_OK) && (ret != JSON_KEY_NOT_FOUND)) {
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
  if (cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEAT_BLOCKS) != NULL) {
    if (json_feat_blocks_deserialize(output_obj, false, &feat_blocks) != 0) {
      printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
      goto end;
    }
  }

  // immutable feature blocks array
  if (cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_IMMUTABLE_BLOCKS) != NULL) {
    if (json_feat_blocks_deserialize(output_obj, true, &immut_feat_blocks) != 0) {
      printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_IMMUTABLE_BLOCKS);
      goto end;
    }
  }

  // create alias output
  *alias = output_alias_new(amount, tokens, alias_id, state_index, state_metadata->data, state_metadata->len,
                            foundry_counter, cond_blocks, feat_blocks, immut_feat_blocks);
  if (!*alias) {
    printf("[%s:%d]: creating alias output object failed \n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new alias output
  result = 0;

end:
  native_tokens_free(tokens);
  byte_buf_free(state_metadata);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);

  return result;
}

cJSON *json_output_alias_serialize(output_alias_t *alias) {
  cJSON *alias_obj = cJSON_CreateObject();
  if (alias_obj) {
    cJSON *tmp = NULL;
    // type
    if (!cJSON_AddNumberToObject(alias_obj, JSON_KEY_TYPE, OUTPUT_ALIAS)) {
      printf("[%s:%d] add type into alias error\n", __func__, __LINE__);
      goto err;
    }

    // amount
    char amount_str[65] = {};
    sprintf(amount_str, "%" PRIu64 "", alias->amount);
    if (!cJSON_AddStringToObject(alias_obj, JSON_KEY_AMOUNT, amount_str)) {
      printf("[%s:%d] add amount to alias error\n", __func__, __LINE__);
      goto err;
    }

    // native tokens
    tmp = json_native_tokens_serialize(alias->native_tokens);
    if (!cJSON_AddItemToObject(alias_obj, JSON_KEY_NATIVE_TOKENS, tmp)) {
      printf("[%s:%d] add native tokens into alias error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // alias id
    char alias_id_str[JSON_STR_WITH_PREFIX_BYTES(ALIAS_ID_BYTES)] = {};
    if (bin_2_hex(alias->alias_id, ALIAS_ID_BYTES, JSON_HEX_ENCODED_STRING_PREFIX, alias_id_str,
                  sizeof(alias_id_str)) != 0) {
      printf("[%s:%d] convert alias id to hex string error\n", __func__, __LINE__);
      goto err;
    }
    if (!cJSON_AddStringToObject(alias_obj, JSON_KEY_ALIAS_ID, alias_id_str)) {
      printf("[%s:%d] add alias id into alias error\n", __func__, __LINE__);
      goto err;
    }

    // state index
    if (!cJSON_AddNumberToObject(alias_obj, JSON_KEY_STATE_INDEX, alias->state_index)) {
      printf("[%s:%d] add amount into alias error\n", __func__, __LINE__);
      goto err;
    }

    // state metadata
    if (alias->state_metadata) {
      char *meta = malloc(JSON_STR_WITH_PREFIX_BYTES(alias->state_metadata->len));
      if (!meta) {
        printf("[%s:%d] allocate metadata error\n", __func__, __LINE__);
        goto err;
      }
      if (bin_2_hex(alias->state_metadata->data, alias->state_metadata->len, JSON_HEX_ENCODED_STRING_PREFIX, meta,
                    JSON_STR_WITH_PREFIX_BYTES(alias->state_metadata->len)) != 0) {
        printf("[%s:%d] convert metadata to hex string error\n", __func__, __LINE__);
        free(meta);
        goto err;
      }
      if (!cJSON_AddStringToObject(alias_obj, JSON_KEY_STATE_METADATA, meta)) {
        printf("[%s:%d] add metadata into alias error\n", __func__, __LINE__);
        free(meta);
        cJSON_Delete(tmp);
        goto err;
      }
      free(meta);
    }

    // foundry counter
    if (!cJSON_AddNumberToObject(alias_obj, JSON_KEY_FOUNDRY_COUNTER, alias->foundry_counter)) {
      printf("[%s:%d] add foundry counter to alias error\n", __func__, __LINE__);
      goto err;
    }

    // unlock conditions
    tmp = json_cond_blk_list_serialize(alias->unlock_conditions);
    if (!cJSON_AddItemToObject(alias_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions into alias error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // feature blocks
    tmp = json_feat_blocks_serialize(alias->feature_blocks);
    if (!cJSON_AddItemToObject(alias_obj, JSON_KEY_FEAT_BLOCKS, tmp)) {
      printf("[%s:%d] add feature blocks into alias error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // immutable feature blocks
    tmp = json_feat_blocks_serialize(alias->immutable_blocks);
    if (!cJSON_AddItemToObject(alias_obj, JSON_KEY_IMMUTABLE_BLOCKS, tmp)) {
      printf("[%s:%d] add immutable feature blocks to Alias error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }
  }
  return alias_obj;

err:
  cJSON_Delete(alias_obj);
  return NULL;
}
