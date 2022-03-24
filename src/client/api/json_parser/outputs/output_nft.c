// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/outputs/feat_blocks.h"
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
      "nftId": "0xbebc45994f6bd9394f552b62c6e370ce1ab52d2e",
      "unlockConditions": [],
      "featureBlocks": [],
      "immutableFeatureBlocks": []
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
  if (json_native_tokens_deserialize(output_obj, &tokens) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_NATIVE_TOKENS);
    goto end;
  }

  // nftId
  byte_t nft_id[NFT_ID_BYTES];
  if (json_get_hex_str_to_bin(output_obj, JSON_KEY_NFT_ID, nft_id, NFT_ID_BYTES) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_NFT_ID);
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

  // immutable feature blocks array
  if (json_feat_blocks_deserialize(output_obj, true, &immut_feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_IMMUTABLE_BLOCKS);
    goto end;
  }

  // create NFT output
  *nft = output_nft_new(amount, tokens, nft_id, cond_blocks, feat_blocks, immut_feat_blocks);
  if (!*nft) {
    printf("[%s:%d]: creating NFT output object failed \n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new NFT output
  result = 0;

end:
  native_tokens_free(tokens);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);

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
    char amount_str[65] = {};
    sprintf(amount_str, "%" PRIu64 "", nft->amount);
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_AMOUNT, amount_str)) {
      printf("[%s:%d] add amount to NFT error\n", __func__, __LINE__);
      goto err;
    }

    // native tokens
    tmp = json_native_tokens_serialize(nft->native_tokens);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_NATIVE_TOKENS, tmp)) {
      printf("[%s:%d] add native tokens to NFT error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // NFT ID
    char id_str[BIN_TO_HEX_STR_BYTES(NFT_ID_BYTES) + JSON_HEX_ENCODED_STRING_PREFIX_LEN] = {};
    memcpy(id_str, "0x", JSON_HEX_ENCODED_STRING_PREFIX_LEN);
    if (bin_2_hex(nft->nft_id, NFT_ID_BYTES, id_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                  sizeof(id_str) - JSON_HEX_ENCODED_STRING_PREFIX_LEN) != 0) {
      printf("[%s:%d] convert NFT ID to hex string error\n", __func__, __LINE__);
      goto err;
    }
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_NFT_ID, id_str)) {
      printf("[%s:%d] add ID to NFT error\n", __func__, __LINE__);
      goto err;
    }

    // unlock conditions
    tmp = json_cond_blk_list_serialize(nft->unlock_conditions);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions to NFT error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // feature blocks
    tmp = json_feat_blocks_serialize(nft->feature_blocks);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_FEAT_BLOCKS, tmp)) {
      printf("[%s:%d] add feature blocks to NFT error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // immutable feature blocks
    tmp = json_feat_blocks_serialize(nft->immutable_blocks);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_IMMUTABLE_BLOCKS, tmp)) {
      printf("[%s:%d] add immutable feature blocks to NFT error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
