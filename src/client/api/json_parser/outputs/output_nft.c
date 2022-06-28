// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/outputs/features.h"
#include "client/api/json_parser/outputs/native_tokens.h"
#include "client/api/json_parser/outputs/output_nft.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

/*
  "outputs": [
    { "type": 6,
      "amount": "10000000",
      "nativeTokens": [],
      "nftId": "0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f",
      "unlockConditions": [],
      "features": [],
      "immutableFeatures": []
    }
  ]
*/
int json_output_nft_deserialize(cJSON *output_obj, output_nft_t **nft) {
  if (output_obj == NULL || *nft != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_list_t *tokens = native_tokens_new();
  unlock_cond_list_t *cond_list = condition_list_new();
  feature_list_t *features = feature_list_new();
  feature_list_t *immut_features = feature_list_new();

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

  // nftId
  byte_t nft_id[NFT_ID_BYTES];
  if (json_get_hex_str_to_bin(output_obj, JSON_KEY_NFT_ID, nft_id, NFT_ID_BYTES) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_NFT_ID);
    goto end;
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

  // immutable features array
  if (cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_IMMUTABLE_FEATS) != NULL) {
    if (json_features_deserialize(output_obj, true, &immut_features) != 0) {
      printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_IMMUTABLE_FEATS);
      goto end;
    }
  }

  // create NFT output
  *nft = output_nft_new(amount, tokens, nft_id, cond_list, features, immut_features);
  if (!*nft) {
    printf("[%s:%d]: creating NFT output object failed \n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new NFT output
  result = 0;

end:
  native_tokens_free(tokens);
  condition_list_free(cond_list);
  feature_list_free(features);
  feature_list_free(immut_features);

  return result;
}

cJSON *json_output_nft_serialize(output_nft_t *nft) {
  cJSON *output_obj = cJSON_CreateObject();
  if (output_obj) {
    cJSON *tmp = NULL;
    // type
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_TYPE, OUTPUT_NFT)) {
      printf("[%s:%d] add type to NFT error\n", __func__, __LINE__);
      goto err;
    }

    // amount
    char amount_str[65] = {0};
    sprintf(amount_str, "%" PRIu64 "", nft->amount);
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_AMOUNT, amount_str)) {
      printf("[%s:%d] add amount to NFT error\n", __func__, __LINE__);
      goto err;
    }

    // native tokens
    tmp = json_native_tokens_serialize(nft->native_tokens);
    if (tmp) {
      if (!cJSON_AddItemToObject(output_obj, JSON_KEY_NATIVE_TOKENS, tmp)) {
        printf("[%s:%d] add native tokens to NFT error\n", __func__, __LINE__);
        cJSON_Delete(tmp);
        goto err;
      }
    }

    // NFT ID
    char id_str[JSON_STR_WITH_PREFIX_BYTES(NFT_ID_BYTES)] = {0};
    if (bin_2_hex(nft->nft_id, NFT_ID_BYTES, JSON_HEX_ENCODED_STRING_PREFIX, id_str, sizeof(id_str)) != 0) {
      printf("[%s:%d] convert NFT ID to hex string error\n", __func__, __LINE__);
      goto err;
    }
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_NFT_ID, id_str)) {
      printf("[%s:%d] add ID to NFT error\n", __func__, __LINE__);
      goto err;
    }

    // unlock conditions
    tmp = json_condition_list_serialize(nft->unlock_conditions);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions to NFT error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // features
    tmp = json_features_serialize(nft->features);
    if (tmp) {
      if (!cJSON_AddItemToObject(output_obj, JSON_KEY_FEATURES, tmp)) {
        printf("[%s:%d] add features to NFT error\n", __func__, __LINE__);
        cJSON_Delete(tmp);
        goto err;
      }
    }

    // immutable features
    tmp = json_features_serialize(nft->immutable_features);
    if (tmp) {
      if (!cJSON_AddItemToObject(output_obj, JSON_KEY_IMMUTABLE_FEATS, tmp)) {
        printf("[%s:%d] add immutable features to NFT error\n", __func__, __LINE__);
        cJSON_Delete(tmp);
        goto err;
      }
    }
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
