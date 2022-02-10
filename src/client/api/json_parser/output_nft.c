// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/output_nft.h"
#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/native_tokens.h"
#include "client/api/json_parser/unlock_conditions.h"
#include "core/models/outputs/output_nft.h"

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
int json_output_nft_deserialize(cJSON *output_obj, transaction_essence_t *essence) {
  if (output_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  native_tokens_t *tokens = native_tokens_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  byte_buf_t *immutable_metadata = byte_buf_new();
  output_nft_t *output = NULL;

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
  if (json_feat_blocks_deserialize(output_obj, &feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed \n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }

  // immutable metadata
  if (json_get_byte_buf_str(output_obj, JSON_KEY_IMMUTABLE_DATA, immutable_metadata) != JSON_OK) {
    printf("[%s:%d]: getting %s json byte buffer failed\n", __func__, __LINE__, JSON_KEY_IMMUTABLE_DATA);
    goto end;
  }

  // create NFT output
  output = output_nft_new(amount, tokens, nft_id, immutable_metadata->data, immutable_metadata->len, cond_blocks,
                          feat_blocks);
  if (!output) {
    printf("[%s:%d]: creating output object failed \n", __func__, __LINE__);
    goto end;
  }

  // add new output into a list
  if (tx_essence_add_output(essence, OUTPUT_NFT, output) != 0) {
    printf("[%s:%d] can not add new output into a list\n", __func__, __LINE__);
    goto end;
  }

  // Successfully added new output into a list
  result = 0;

end:
  native_tokens_free(&tokens);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  byte_buf_free(immutable_metadata);
  output_nft_free(output);

  return result;
}
