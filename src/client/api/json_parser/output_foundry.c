// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/output_foundry.h"
#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/native_tokens.h"
#include "client/api/json_parser/unlock_conditions.h"
#include "core/models/outputs/output_foundry.h"

/*
  "outputs": [
    { "type": 5,
      "amount": 10000000,
      "nativeTokens": [],
      "serialNumber": 123456,
      "tokenTag": "TokenTAGDemo",
      "circulatingSupply": "20000000000000000000000000000000000000000",
      "maximumSupply": "30000000000000000000000000000000000000000",
      "tokenScheme": 0,
      "unlockConditions": [
        {  "type": 0,
           "address": {
            "type": 8,
            "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c"
            }
        }
      ],
      "featureBlocks": [
        {
          "type": 2,
          "data": "010203040506070809"
        }
      ]
    }
  ]
*/
int json_output_foundry_deserialize(cJSON *output_obj, transaction_essence_t *essence) {
  if (output_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  uint256_t *circ_supply = NULL;
  uint256_t *max_supply = NULL;
  native_tokens_t *tokens = native_tokens_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  output_foundry_t *output = NULL;

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

  // serial number
  uint32_t serial_number;
  if (json_get_uint32(output_obj, JSON_KEY_SERIAL_NUMBER, &serial_number) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_SERIAL_NUMBER);
    goto end;
  }

  // token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  if (json_get_string(output_obj, JSON_KEY_TOKEN_TAG, (char *)token_tag, TOKEN_TAG_BYTES_LEN) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_TOKEN_TAG);
    goto end;
  }

  // circulation supply
  char supply_str[STRING_NUMBER_MAX_CHARACTERS];
  if (json_get_string(output_obj, JSON_KEY_CIRC_SUPPLY, supply_str, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_CIRC_SUPPLY);
    goto end;
  }
  circ_supply = uint256_from_str(supply_str);

  // maximum supply
  if (json_get_string(output_obj, JSON_KEY_MAX_SUPPLY, supply_str, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_MAX_SUPPLY);
    goto end;
  }
  max_supply = uint256_from_str(supply_str);

  // token scheme
  uint8_t token_scheme;
  if (json_get_uint8(output_obj, JSON_KEY_TOKEN_SCHEME, &token_scheme) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TOKEN_SCHEME);
    goto end;
  }

  // unlock conditions array
  if (json_cond_blk_list_deserialize(output_obj, &cond_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed\n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    goto end;
  }
  if (cond_blk_list_len(cond_blocks) != 1) {
    printf("[%s:%d]: there must be only one unlock condition in a list\n", __func__, __LINE__);
    goto end;
  }
  // extract alias address from unlock condition
  unlock_cond_blk_t *unlock_cond_address = cond_blk_list_get_type(cond_blocks, UNLOCK_COND_ADDRESS);
  if (!unlock_cond_address) {
    printf("[%s:%d]: there is not a address unlock condition in a list\n", __func__, __LINE__);
    goto end;
  }

  // feature blocks array
  if (json_feat_blocks_deserialize(output_obj, &feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed\n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    goto end;
  }
  if (feat_blk_list_len(feat_blocks) > 1) {
    printf("[%s:%d]: there must be at most one feature block in a list\n", __func__, __LINE__);
    goto end;
  }
  // there may be a metadata feature block
  byte_t *metadata = NULL;
  uint32_t metadata_len = 0;
  if (feat_blk_list_len(feat_blocks) == 1) {
    feat_block_t *feat_block_metadata = feat_blk_list_get_type(feat_blocks, FEAT_METADATA_BLOCK);
    if (!feat_block_metadata) {
      printf("[%s:%d]: there is not a metadata feature block in a list\n", __func__, __LINE__);
      goto end;
    }
    metadata = ((feat_metadata_blk_t *)feat_block_metadata->block)->data;
    metadata_len = ((feat_metadata_blk_t *)feat_block_metadata->block)->data_len;
  }

  // create foundry output
  output = output_foundry_new((address_t *)unlock_cond_address->block, amount, tokens, serial_number, token_tag,
                              circ_supply, max_supply, token_scheme, metadata, metadata_len);
  if (!output) {
    printf("[%s:%d]: creating output object failed\n", __func__, __LINE__);
    goto end;
  }

  // add new output into a list
  if (tx_essence_add_output(essence, OUTPUT_FOUNDRY, output) != 0) {
    printf("[%s:%d] can not add new output into a list\n", __func__, __LINE__);
    goto end;
  }

  // Successfully added new output into a list
  result = 0;

end:
  if (circ_supply) {
    free(circ_supply);
  }
  if (max_supply) {
    free(max_supply);
  }
  native_tokens_free(&tokens);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  output_foundry_free(output);

  return result;
}

cJSON *json_output_foundry_serialize(output_foundry_t *foundry) {
  // TODO
  return NULL;
}
