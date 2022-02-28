// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/feat_blocks.h"
#include "client/api/json_parser/common.h"
#include "core/utils/macros.h"
#include "utlist.h"

/*
  "type": 0,
  "address": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_feat_blk_sender_deserialize(cJSON *feat_block_obj, feat_blk_list_t **feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(feat_block_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new sender feature block into a list
  if (feat_blk_list_add_sender(feat_blocks, &address) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static cJSON *json_feat_blk_sender_serialize(feat_block_t *block) {
  if (!block || block->type != FEAT_SENDER_BLOCK) {
    printf("[%s:%d] invalid block\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *sender_obj = cJSON_CreateObject();
  if (sender_obj) {
    // add type to sender
    cJSON_AddNumberToObject(sender_obj, JSON_KEY_TYPE, FEAT_SENDER_BLOCK);

    // add address to sender
    cJSON *addr = json_parser_common_address_serialize((address_t *)block->block);
    if (addr) {
      cJSON_AddObjectToObject(addr, JSON_KEY_ADDR);
    } else {
      printf("[%s:%d] adding address into block error\n", __func__, __LINE__);
      cJSON_Delete(sender_obj);
      return NULL;
    }
  }
  return sender_obj;
}

/*
  "type": 1,
  "address": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_feat_blk_issuer_deserialize(cJSON *feat_block_obj, feat_blk_list_t **feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(feat_block_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new issuer feature block into a list
  if (feat_blk_list_add_issuer(feat_blocks, &address) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static cJSON *json_feat_blk_issuer_serialize(feat_block_t *block) {
  if (!block || block->type != FEAT_ISSUER_BLOCK) {
    printf("[%s:%d] invalid block\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *issuer_obj = cJSON_CreateObject();
  if (issuer_obj) {
    // add type
    cJSON_AddNumberToObject(issuer_obj, JSON_KEY_TYPE, FEAT_ISSUER_BLOCK);

    // add address
    cJSON *addr = json_parser_common_address_serialize((address_t *)block->block);
    if (addr) {
      cJSON_AddObjectToObject(addr, JSON_KEY_ADDR);
    } else {
      printf("[%s:%d] adding address into block error\n", __func__, __LINE__);
      cJSON_Delete(issuer_obj);
      return NULL;
    }
  }
  return issuer_obj;
}

/*
  "type": 2,
  "data": "010203040506070809"
*/
int json_feat_blk_metadata_deserialize(cJSON *feat_block_obj, feat_blk_list_t **feat_blocks) {
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
  if (feat_blk_list_add_metadata(feat_blocks, (byte_t *)metadata_obj->valuestring, strlen(metadata_obj->valuestring)) !=
      0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static cJSON *json_feat_blk_metadata_serialize(feat_metadata_blk_t *block) {
  if (!block) {
    printf("[%s:%d] invalid block\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *meta = cJSON_CreateObject();
  if (meta) {
    // add type
    cJSON_AddNumberToObject(meta, JSON_KEY_TYPE, FEAT_METADATA_BLOCK);

    // add metadata
    char *data_str = malloc(BIN_TO_HEX_STR_BYTES(block->data_len));
    if (!data_str) {
      printf("[%s:%d] allocate data error\n", __func__, __LINE__);
      cJSON_Delete(meta);
      return NULL;
    }

    // TODO, is data contain data length in JSON object?
    // convert data to hex string
    if (bin_2_hex(block->data, block->data_len, data_str, BIN_TO_HEX_STR_BYTES(block->data_len)) != 0) {
      printf("[%s:%d] convert data to hex string error\n", __func__, __LINE__);
      cJSON_Delete(meta);
      free(data_str);
      return NULL;
    }

    // add string to json
    cJSON_AddStringToObject(meta, JSON_KEY_DATA, data_str);
    free(data_str);
  }
  return meta;
}

/*
  "type": 3,
  "tag": "01020304"
*/
int json_feat_blk_tag_deserialize(cJSON *feat_block_obj, feat_blk_list_t **feat_blocks) {
  if (feat_block_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // tag
  cJSON *tag_obj = cJSON_GetObjectItemCaseSensitive(feat_block_obj, JSON_KEY_TAG);
  if (!cJSON_IsString(tag_obj)) {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_TAG);
    return -1;
  }

  // add new tag feature block into a list
  if (feat_blk_list_add_tag(feat_blocks, (byte_t *)tag_obj->valuestring, strlen(tag_obj->valuestring)) != 0) {
    printf("[%s:%d] can not add new feature block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static cJSON *json_feat_blk_tag_serialize(feat_tag_blk_t *block) {
  if (!block) {
    printf("[%s:%d] invalid block\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *meta = cJSON_CreateObject();
  if (meta) {
    // add type
    cJSON_AddNumberToObject(meta, JSON_KEY_TYPE, FEAT_TAG_BLOCK);

    // add tag
    char tag_str[BIN_TO_HEX_STR_BYTES(MAX_INDEX_TAG_BYTES)] = {};
    // TODO, is tag contain tag length in JSON object?
    // convert tag to hex string
    if (bin_2_hex(block->tag, block->tag_len, tag_str, sizeof(tag_str)) != 0) {
      printf("[%s:%d] convert tag to hex string error\n", __func__, __LINE__);
      cJSON_Delete(meta);
      return NULL;
    }

    // add string to json
    cJSON_AddStringToObject(meta, JSON_KEY_DATA, tag_str);
  }
  return meta;
}

/*
  "featureBlocks": [],
  or
  "immutableFeatureBlocks": [],
*/
int json_feat_blocks_deserialize(cJSON *output_obj, bool immutable, feat_blk_list_t **feat_blocks) {
  if (output_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *feat_blocks_obj = NULL;

  if (immutable) {
    // immutable feature blocks array
    feat_blocks_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_IMMUTABLE_BLOCKS);
    if (!cJSON_IsArray(feat_blocks_obj)) {
      printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_IMMUTABLE_BLOCKS);
      return -1;
    }
  } else {
    // feature blocks array
    feat_blocks_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEAT_BLOCKS);
    if (!cJSON_IsArray(feat_blocks_obj)) {
      printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_FEAT_BLOCKS);
      return -1;
    }
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
        printf("[%s:%d] unsupported feature block\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}

cJSON *json_feat_blocks_serialize(feat_blk_list_t *feat_blocks) {
  // create block array
  cJSON *blocks = cJSON_CreateArray();
  if (blocks) {
    if (!feat_blocks) {
      // empty feature blocks
      return blocks;
    }

    cJSON *item = NULL;
    feat_blk_list_t *elm;
    LL_FOREACH(feat_blocks, elm) {
      switch (elm->blk->type) {
        case FEAT_SENDER_BLOCK:
          item = json_feat_blk_sender_serialize(elm->blk);
          break;
        case FEAT_ISSUER_BLOCK:
          item = json_feat_blk_issuer_serialize(elm->blk);
          break;
        case FEAT_METADATA_BLOCK:
          item = json_feat_blk_metadata_serialize((feat_metadata_blk_t *)elm->blk);
          break;
        case FEAT_TAG_BLOCK:
          item = json_feat_blk_tag_serialize((feat_tag_blk_t *)elm->blk);
          break;
        default:
          printf("[%s:%d] unsupported feature block\n", __func__, __LINE__);
          break;
      }

      if (item) {
        // add item to array
        if (!cJSON_AddItemToArray(blocks, item)) {
          printf("[%s:%d] add block to array error\n", __func__, __LINE__);
          cJSON_Delete(item);
          cJSON_Delete(blocks);
          return NULL;
        }
      } else {
        printf("[%s:%d] serialize feature block error\n", __func__, __LINE__);
        cJSON_Delete(blocks);
        return NULL;
      }
    }
  }

  return blocks;
}
