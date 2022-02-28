// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/output_nft.h"
#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/native_tokens.h"
#include "client/api/json_parser/unlock_conditions.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

/*
  "outputs": [
    { "type": 6,
      "amount": 10000000,
      "nativeTokens": [],
      "nftId": "bebc45994f6bd9394f552b62c6e370ce1ab52d2e",
      "unlockConditions": [],
      "featureBlocks": [],
      "immutableData": "testMetadata"
    }
  ]
*/
int json_output_nft_deserialize(cJSON *output_obj, output_nft_t **nft) {
  if (output_obj == NULL || *nft != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_t *tokens = native_tokens_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  byte_buf_t *immutable_metadata = byte_buf_new();

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

  // nftId
  char nft_id_hex[ADDRESS_NFT_HEX_BYTES];
  byte_t nft_id[ADDRESS_NFT_BYTES];
  if (json_get_string(output_obj, JSON_KEY_NFT_ID, (char *)nft_id_hex, ADDRESS_NFT_HEX_BYTES) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_NFT_ID);
    goto end;
  }
  if (hex_2_bin(nft_id_hex, ADDRESS_NFT_HEX_BYTES, nft_id, ADDRESS_NFT_BYTES) != 0) {
    printf("[%s:%d] can not convert hex to bin number\n", __func__, __LINE__);
    goto end;
  }

  // unlock conditions array
  if (json_cond_blk_list_deserialize(output_obj, &cond_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    goto end;
  }

  // feature blocks array
  if (json_feat_blocks_deserialize(output_obj, &feat_blocks, false) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }

  // immutable metadata
  if (json_get_byte_buf_str(output_obj, JSON_KEY_IMMUTABLE_DATA, immutable_metadata) != JSON_OK) {
    printf("[%s:%d]: getting %s json byte buffer failed\n", __func__, __LINE__, JSON_KEY_IMMUTABLE_DATA);
    goto end;
  }

  // create NFT output
  *nft = output_nft_new(amount, tokens, nft_id, immutable_metadata->data, immutable_metadata->len, cond_blocks,
                        feat_blocks);
  if (!*nft) {
    printf("[%s:%d]: creating NFT output object failed \n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new NFT output
  result = 0;

end:
  native_tokens_free(&tokens);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  byte_buf_free(immutable_metadata);

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
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_AMOUNT, nft->amount)) {
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
    char id_str[BIN_TO_HEX_STR_BYTES(NFT_ID_BYTES)] = {};
    if (bin_2_hex(nft->nft_id, NFT_ID_BYTES, id_str, sizeof(id_str)) != 0) {
      printf("[%s:%d] convert NFT ID to hex string error\n", __func__, __LINE__);
      goto err;
    }
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_NFT_ID, id_str)) {
      printf("[%s:%d] add ID to NFT error\n", __func__, __LINE__);
      goto err;
    }

    // immutable metadata
    char *meta = malloc(BIN_TO_HEX_STR_BYTES(nft->immutable_metadata->len));
    if (!meta) {
      printf("[%s:%d] allocate metadata error\n", __func__, __LINE__);
      goto err;
    }
    if (bin_2_hex(nft->immutable_metadata->data, nft->immutable_metadata->len, meta,
                  BIN_TO_HEX_STR_BYTES(nft->immutable_metadata->len)) != 0) {
      printf("[%s:%d] convert metadata to hex string error\n", __func__, __LINE__);
      free(meta);
      goto err;
    }
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_IMMUTABLE_DATA, meta)) {
      printf("[%s:%d] add metadata into NFT error\n", __func__, __LINE__);
      free(meta);
      cJSON_Delete(tmp);
      goto err;
    }
    free(meta);

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
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
