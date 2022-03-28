// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/outputs/output_foundry.h"
#include "client/api/json_parser/outputs/feat_blocks.h"
#include "client/api/json_parser/outputs/native_tokens.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

/*
"tokenScheme": {
  "type" : 0,
  "mintedTokens" : 200000000000000000000000000000000000000000,
  "meltedTokens" : 100000000000000000000000000000000000000000,
  "maximumSupply": "30000000000000000000000000000000000000000",
}
*/
int json_token_scheme_deserialize(cJSON *output_obj, token_scheme_t **token_scheme) {
  if (output_obj == NULL || *token_scheme != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // token scheme type
  uint8_t scheme_type;
  if (json_get_uint8(output_obj, JSON_KEY_TYPE, &scheme_type) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
    return -1;
  }

  if (scheme_type == SIMPLE_TOKEN_SCHEME) {
    uint256_t *mintedt_tokens = NULL;
    uint256_t *melted_tokens = NULL;
    uint256_t *max_supply = NULL;
    // minted tokens
    char temp_str[STRING_NUMBER_MAX_CHARACTERS];
    if (json_get_string(output_obj, JSON_KEY_MINTED_TOKENS, temp_str, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_MINTED_TOKENS);
      return -1;
    }
    mintedt_tokens = uint256_from_str(temp_str);

    // melted tokens
    memset(temp_str, 0, STRING_NUMBER_MAX_CHARACTERS);
    if (json_get_string(output_obj, JSON_KEY_MELTED_TOKENS, temp_str, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_MELTED_TOKENS);
      uint256_free(mintedt_tokens);
      return -1;
    }
    melted_tokens = uint256_from_str(temp_str);

    // maximum supply
    memset(temp_str, 0, STRING_NUMBER_MAX_CHARACTERS);
    if (json_get_string(output_obj, JSON_KEY_MAX_SUPPLY, temp_str, STRING_NUMBER_MAX_CHARACTERS) != JSON_OK) {
      printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_MAX_SUPPLY);
      uint256_free(mintedt_tokens);
      uint256_free(melted_tokens);
      return -1;
    }
    max_supply = uint256_from_str(temp_str);

    *token_scheme = token_scheme_simple_new(mintedt_tokens, melted_tokens, max_supply);
    if (!token_scheme) {
      printf("[%s:%d]: creating token scheme object failed\n", __func__, __LINE__);
      uint256_free(mintedt_tokens);
      uint256_free(melted_tokens);
      uint256_free(max_supply);
      return -1;
    }
    uint256_free(mintedt_tokens);
    uint256_free(melted_tokens);
    uint256_free(max_supply);
  } else {
    printf("[%s:%d]: unsupported token scheme type \n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

cJSON *json_token_scheme_serialize(token_scheme_t *scheme) {
  if (!scheme) {
    printf("[%s:%d] invalid block\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *scheme_obj = cJSON_CreateObject();
  if (!scheme_obj) {
    printf("[%s:%d] creating scheme object failed\n", __func__, __LINE__);
    return NULL;
  }

  // currently on simple token scheme is supported
  if (scheme->type == SIMPLE_TOKEN_SCHEME) {
    token_scheme_simple_t *simple_scheme = scheme->token_scheme;
    if (simple_scheme) {
      // add type to object
      if (!cJSON_AddNumberToObject(scheme_obj, JSON_KEY_TYPE, SIMPLE_TOKEN_SCHEME)) {
        printf("[%s:%d] add type into token scheme failed\n", __func__, __LINE__);
        goto err;
      }

      char *tmp_supply = NULL;

      // minted tokens
      tmp_supply = uint256_to_str(&simple_scheme->minted_tokens);
      if (!tmp_supply) {
        goto err;
      }
      if (!cJSON_AddStringToObject(scheme_obj, JSON_KEY_MINTED_TOKENS, tmp_supply)) {
        printf("[%s:%d] add minted tokens to foundry failed\n", __func__, __LINE__);
        free(tmp_supply);
        goto err;
      }
      free(tmp_supply);

      // melted tokens
      tmp_supply = uint256_to_str(&simple_scheme->melted_tokens);
      if (!tmp_supply) {
        goto err;
      }
      if (!cJSON_AddStringToObject(scheme_obj, JSON_KEY_MELTED_TOKENS, tmp_supply)) {
        printf("[%s:%d] add melted tokens to foundry failed\n", __func__, __LINE__);
        free(tmp_supply);
        goto err;
      }
      free(tmp_supply);

      // maximum supply
      tmp_supply = uint256_to_str(&simple_scheme->max_supply);
      if (!tmp_supply) {
        goto err;
      }
      if (!cJSON_AddStringToObject(scheme_obj, JSON_KEY_MAX_SUPPLY, tmp_supply)) {
        printf("[%s:%d] add max supply to foundry failed\n", __func__, __LINE__);
        free(tmp_supply);
        goto err;
      }
      free(tmp_supply);
    }
    return scheme_obj;
  }
err:
  cJSON_Delete(scheme_obj);
  return NULL;
}

/*
  "outputs": [
    { "type": 5,
      "amount": 10000000,
      "nativeTokens": [],
      "serialNumber": 123456,
      "tokenTag": "TokenTAGDemo",
      "tokenScheme": {
        "type" : 0,
        "mintedTokens" : 100000000000000000000000000000000000000000,
        "meltedTokens" : 200000000000000000000000000000000000000000,
        "maximumSupply": "30000000000000000000000000000000000000000",
      },
      "unlockConditions": [
        {  "type": 0,
           "address": {
            "type": 8,
            "aliasId": "194eb32b9b6c61207192c7073562a0b3adf50a7c"
            }
        }
      ],
      "featureBlocks": [
        {
          "type": 2,
          "data": "010203040506070809"
        }
      ],
      "immutableFeatureBlocks": [
        {
          "type": 2,
          "data": "090807060504030201"
        }
      ]
    }
  ]
*/
int json_output_foundry_deserialize(cJSON *output_obj, output_foundry_t **foundry) {
  if (output_obj == NULL || *foundry != NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int result = -1;

  token_scheme_t *token_scheme = NULL;
  native_tokens_list_t *tokens = native_tokens_new();
  cond_blk_list_t *cond_blocks = cond_blk_list_new();
  feat_blk_list_t *feat_blocks = feat_blk_list_new();
  feat_blk_list_t *immut_feat_blocks = feat_blk_list_new();

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

  // token scheme
  cJSON *json_token_scheme = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_TOKEN_SCHEME);
  if (!json_token_scheme) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, JSON_KEY_TOKEN_SCHEME);
    goto end;
  }
  if (json_token_scheme_deserialize(json_token_scheme, &token_scheme) != 0) {
    printf("[%s:%d]: parsing %s object failed\n", __func__, __LINE__, JSON_KEY_TOKEN_SCHEME);
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
  unlock_cond_blk_t *unlock_cond_address = cond_blk_list_get_type(cond_blocks, UNLOCK_COND_IMMUT_ALIAS);
  if (!unlock_cond_address) {
    printf("[%s:%d]: there is not a address unlock condition in a list\n", __func__, __LINE__);
    goto end;
  }

  // feature blocks array
  if (json_feat_blocks_deserialize(output_obj, false, &feat_blocks) != 0) {
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

  // immutable feature blocks array
  if (json_feat_blocks_deserialize(output_obj, true, &immut_feat_blocks) != 0) {
    printf("[%s:%d]: parsing %s object failed\n", __func__, __LINE__, JSON_KEY_IMMUTABLE_BLOCKS);
    goto end;
  }
  if (feat_blk_list_len(immut_feat_blocks) > 1) {
    printf("[%s:%d]: there must be at most one immutable feature block in a list\n", __func__, __LINE__);
    goto end;
  }
  // there may be a metadata immutable feature block
  byte_t *immut_metadata = NULL;
  uint32_t immut_metadata_len = 0;
  if (feat_blk_list_len(immut_feat_blocks) == 1) {
    feat_block_t *immut_feat_block_metadata = feat_blk_list_get_type(immut_feat_blocks, FEAT_METADATA_BLOCK);
    if (!immut_feat_block_metadata) {
      printf("[%s:%d]: there is not a metadata immutable feature block in a list\n", __func__, __LINE__);
      goto end;
    }
    immut_metadata = ((feat_metadata_blk_t *)immut_feat_block_metadata->block)->data;
    immut_metadata_len = ((feat_metadata_blk_t *)immut_feat_block_metadata->block)->data_len;
  }

  // create foundry output
  *foundry = output_foundry_new((address_t *)unlock_cond_address->block, amount, tokens, serial_number, token_tag,
                                token_scheme, metadata, metadata_len, immut_metadata, immut_metadata_len);
  if (!*foundry) {
    printf("[%s:%d]: creating foundry output object failed\n", __func__, __LINE__);
    goto end;
  }

  // Successfully created new foundry output
  result = 0;

end:
  native_tokens_free(tokens);
  token_scheme_free(token_scheme);
  cond_blk_list_free(cond_blocks);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);

  return result;
}

cJSON *json_output_foundry_serialize(output_foundry_t *foundry) {
  cJSON *output_obj = cJSON_CreateObject();
  if (output_obj) {
    cJSON *tmp = NULL;
    // type
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_TYPE, OUTPUT_FOUNDRY)) {
      printf("[%s:%d] add type to foundry error\n", __func__, __LINE__);
      goto err;
    }

    // amount
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_AMOUNT, foundry->amount)) {
      printf("[%s:%d] add amount to foundry error\n", __func__, __LINE__);
      goto err;
    }

    // native tokens
    tmp = json_native_tokens_serialize(foundry->native_tokens);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_NATIVE_TOKENS, tmp)) {
      printf("[%s:%d] add native tokens to foundry error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // serialNumber
    if (!cJSON_AddNumberToObject(output_obj, JSON_KEY_SERIAL_NUMBER, foundry->serial)) {
      printf("[%s:%d] add type to foundry error\n", __func__, __LINE__);
      goto err;
    }

    // tokenTag
    char tag_str[BIN_TO_HEX_STR_BYTES(TOKEN_TAG_BYTES_LEN)] = {};
    memcpy(tag_str, foundry->token_tag, TOKEN_TAG_BYTES_LEN);
    if (!cJSON_AddStringToObject(output_obj, JSON_KEY_TOKEN_TAG, tag_str)) {
      printf("[%s:%d] add token tag to foundry error\n", __func__, __LINE__);
      goto err;
    }

    // token scheme
    tmp = json_token_scheme_serialize(foundry->token_scheme);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_TOKEN_SCHEME, tmp)) {
      printf("[%s:%d] add token scheme to foundry error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // unlock conditions
    tmp = json_cond_blk_list_serialize(foundry->unlock_conditions);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_UNLOCK_CONDITIONS, tmp)) {
      printf("[%s:%d] add unlock conditions to foundry error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // feature blocks
    tmp = json_feat_blocks_serialize(foundry->feature_blocks);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_FEAT_BLOCKS, tmp)) {
      printf("[%s:%d] add feature blocks to foundry error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }

    // immutable feature blocks
    tmp = json_feat_blocks_serialize(foundry->immutable_blocks);
    if (!cJSON_AddItemToObject(output_obj, JSON_KEY_IMMUTABLE_BLOCKS, tmp)) {
      printf("[%s:%d] add immutable feature blocks to foundry error\n", __func__, __LINE__);
      cJSON_Delete(tmp);
      goto err;
    }
  }
  return output_obj;

err:
  cJSON_Delete(output_obj);
  return NULL;
}
