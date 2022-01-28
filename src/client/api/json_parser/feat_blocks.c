// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/common.h"

/*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  }
*/
int json_feat_blk_sender_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(feat_block_obj, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new sender feature block into a list
  if (feat_blk_list_add_sender(&feat_blocks, &address) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

/*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  }
*/
int json_feat_blk_issuer_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(feat_block_obj, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new issuer feature block into a list
  if (feat_blk_list_add_issuer(&feat_blocks, &address) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

/*
  "data": "89dfjg0s9djfgdsfgjsdfg98sjdf98g23id0gjf0sdffgj098sdgcvb0xcuubx9b"
*/
int json_feat_blk_metadata_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // metadata
  cJSON *metadata_obj = cJSON_GetObjectItemCaseSensitive(feat_block_obj, JSON_KEY_DATA);
  if (!cJSON_IsString(metadata_obj)) {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_DATA);
    return -1;
  }

  // add new metadata feature block into a list
  if (feat_blk_list_add_metadata(&feat_blocks, (byte_t *)metadata_obj->valuestring,
                                 sizeof(metadata_obj->valuestring)) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

/*
  "data": "89dfjg0s9djfgdsfgjsdfg98sjdf98g23id0gjf0sdffgj098sdgcvb0xcuubx9b"
*/
int json_feat_blk_tag_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // tag
  cJSON *tag_obj = cJSON_GetObjectItemCaseSensitive(feat_block_obj, JSON_KEY_DATA);
  if (!cJSON_IsString(tag_obj)) {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_DATA);
    return -1;
  }

  // add new tag feature block into a list
  if (feat_blk_list_add_tag(&feat_blocks, (byte_t *)tag_obj->valuestring, sizeof(tag_obj->valuestring)) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

/*
  "blocks": [],
*/
int json_feat_blocks_deserialize(cJSON *output_obj, feat_blk_list_t *feat_blocks) {
  if (output_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // blocks array
  cJSON *feat_blocks_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEAT_BLOCKS);
  if (!cJSON_IsArray(feat_blocks_obj)) {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, feat_blocks_obj) {
    // type
    uint8_t feat_block_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &feat_block_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // feature block
    switch (feat_block_type) {
      case FEAT_SENDER_BLOCK:
        if (json_feat_blk_sender_deserialize(elm, feat_blocks) != 0) {
          printf("[%s:%d] parsing sender feature block failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case FEAT_ISSUER_BLOCK:
        if (json_feat_blk_issuer_deserialize(elm, feat_blocks) != 0) {
          printf("[%s:%d] parsing issuer feature block failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case FEAT_METADATA_BLOCK:
        if (json_feat_blk_metadata_deserialize(elm, feat_blocks) != 0) {
          printf("[%s:%d] parsing metadata feature block failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case FEAT_TAG_BLOCK:
        if (json_feat_blk_tag_deserialize(elm, feat_blocks) != 0) {
          printf("[%s:%d] parsing tag feature block failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      default:
        printf("[%s:%d] unsupported unlock condition\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}
