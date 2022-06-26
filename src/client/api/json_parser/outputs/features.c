// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/outputs/features.h"
#include "client/api/json_parser/common.h"
#include "core/models/outputs/features.h"
#include "core/utils/macros.h"
#include "utlist.h"

/*
  "type": 0,
  "address": {
    "type": 0,
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_feat_sender_deserialize(cJSON *feat_obj, feature_list_t **feat_list) {
  if (feat_obj == NULL || feat_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(feat_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new sender feature into a list
  if (feature_list_add_sender(feat_list, &address) != 0) {
    printf("[%s:%d] can not add new feature into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static cJSON *json_feat_sender_serialize(output_feature_t *feat) {
  if (!feat || feat->type != FEAT_SENDER_TYPE) {
    printf("[%s:%d] invalid feat\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *sender_obj = cJSON_CreateObject();
  if (sender_obj) {
    // add type to sender
    cJSON_AddNumberToObject(sender_obj, JSON_KEY_TYPE, FEAT_SENDER_TYPE);

    // add address to sender
    cJSON *addr = json_parser_common_address_serialize((address_t *)feat->obj);
    if (addr) {
      cJSON_AddItemToObject(sender_obj, JSON_KEY_ADDR, addr);
    } else {
      printf("[%s:%d] adding address into feat error\n", __func__, __LINE__);
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
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_feat_issuer_deserialize(cJSON *feat_obj, feature_list_t **feat_list) {
  if (feat_obj == NULL || feat_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(feat_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new issuer feature into a list
  if (feature_list_add_issuer(feat_list, &address) != 0) {
    printf("[%s:%d] can not add new feature into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static cJSON *json_feat_issuer_serialize(output_feature_t *feat) {
  if (!feat || feat->type != FEAT_ISSUER_TYPE) {
    printf("[%s:%d] invalid feat\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *issuer_obj = cJSON_CreateObject();
  if (issuer_obj) {
    // add type
    cJSON_AddNumberToObject(issuer_obj, JSON_KEY_TYPE, FEAT_ISSUER_TYPE);

    // add address
    cJSON *addr = json_parser_common_address_serialize((address_t *)feat->obj);
    if (addr) {
      cJSON_AddItemToObject(issuer_obj, JSON_KEY_ADDR, addr);
    } else {
      printf("[%s:%d] adding address into feat error\n", __func__, __LINE__);
      cJSON_Delete(issuer_obj);
      return NULL;
    }
  }
  return issuer_obj;
}

/*
  "type": 2,
  "data": "0x010203040506070809"
*/
int json_feat_metadata_deserialize(cJSON *feat_obj, feature_list_t **feat_list) {
  if (feat_obj == NULL || feat_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // metadata
  cJSON *metadata_obj = cJSON_GetObjectItemCaseSensitive(feat_obj, JSON_KEY_DATA);
  if (!cJSON_IsString(metadata_obj)) {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_DATA);
    return -1;
  }

  // convert hex string into binary data
  byte_t *metadata = NULL;
  uint32_t metadata_len = 0;
  uint32_t metadata_str_len = strlen(metadata_obj->valuestring);
  if (metadata_str_len >= 2) {
    if (memcmp(metadata_obj->valuestring, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
      printf("[%s:%d] hex string without JSON_HEX_ENCODED_STRING_PREFIX prefix \n", __func__, __LINE__);
      return -1;
    }
    metadata_len = (metadata_str_len - JSON_HEX_ENCODED_STR_PREFIX_LEN) / 2;
    metadata = malloc(metadata_len);
    if (!metadata) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      return -1;
    }
    if (hex_2_bin(metadata_obj->valuestring, metadata_str_len, JSON_HEX_ENCODED_STRING_PREFIX, metadata,
                  metadata_len) != 0) {
      printf("[%s:%d] can not covert hex value into a bin value\n", __func__, __LINE__);
      free(metadata);
      return -1;
    }
  }

  // add new metadata feature into a list
  if (feature_list_add_metadata(feat_list, metadata, metadata_len) != 0) {
    printf("[%s:%d] can not add new feature into a list\n", __func__, __LINE__);
    if (metadata) {
      free(metadata);
    }
    return -1;
  }

  // clean up
  if (metadata) {
    free(metadata);
  }

  return 0;
}

static cJSON *json_feat_metadata_serialize(feature_metadata_t *meta) {
  if (!meta) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *meta_obj = cJSON_CreateObject();
  if (meta_obj) {
    // add type
    cJSON_AddNumberToObject(meta_obj, JSON_KEY_TYPE, FEAT_METADATA_TYPE);

    // add metadata
    char *data_str = malloc(JSON_STR_WITH_PREFIX_BYTES(meta->data_len));
    if (!data_str) {
      printf("[%s:%d] allocate data error\n", __func__, __LINE__);
      cJSON_Delete(meta_obj);
      return NULL;
    }

    // TODO, is data contain data length in JSON object?
    // convert data to hex string
    if (bin_2_hex(meta->data, meta->data_len, JSON_HEX_ENCODED_STRING_PREFIX, data_str,
                  JSON_STR_WITH_PREFIX_BYTES(meta->data_len)) != 0) {
      printf("[%s:%d] convert data to hex string error\n", __func__, __LINE__);
      cJSON_Delete(meta_obj);
      free(data_str);
      return NULL;
    }

    // add string to json
    cJSON_AddStringToObject(meta_obj, JSON_KEY_DATA, data_str);
    free(data_str);
  }
  return meta_obj;
}

/*
  "type": 3,
  "tag": "0x01020304"
*/
int json_feat_tag_deserialize(cJSON *feat_obj, feature_list_t **feat_list) {
  if (feat_obj == NULL || feat_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // tag
  cJSON *tag_obj = cJSON_GetObjectItemCaseSensitive(feat_obj, JSON_KEY_TAG);
  if (!cJSON_IsString(tag_obj)) {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_TAG);
    return -1;
  }

  // convert hex string into binary data
  byte_t *tag = NULL;
  uint32_t tag_len = 0;
  uint32_t tag_str_len = strlen(tag_obj->valuestring);
  if (tag_str_len >= 2) {
    if (memcmp(tag_obj->valuestring, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
      printf("[%s:%d] hex string without %s prefix \n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
      return -1;
    }
    tag_len = (tag_str_len - JSON_HEX_ENCODED_STR_PREFIX_LEN) / 2;
    tag = malloc(tag_len);
    if (!tag) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      return -1;
    }
    if (hex_2_bin(tag_obj->valuestring, tag_str_len, JSON_HEX_ENCODED_STRING_PREFIX, tag, tag_len) != 0) {
      printf("[%s:%d] can not covert hex value into a bin value\n", __func__, __LINE__);
      free(tag);
      return -1;
    }
  }

  // add new tag feature into a list
  if (feature_list_add_tag(feat_list, tag, tag_len) != 0) {
    printf("[%s:%d] can not add new feature into a list\n", __func__, __LINE__);
    if (tag) {
      free(tag);
    }
    return -1;
  }

  // clean up
  if (tag) {
    free(tag);
  }

  return 0;
}

static cJSON *json_feat_tag_serialize(feature_tag_t *tag) {
  if (!tag) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *meta = cJSON_CreateObject();
  if (meta) {
    // add type
    cJSON_AddNumberToObject(meta, JSON_KEY_TYPE, FEAT_TAG_TYPE);

    // add tag
    char tag_str[JSON_STR_WITH_PREFIX_BYTES(MAX_INDEX_TAG_BYTES)] = {0};

    // TODO, is tag contain tag length in JSON object?
    // convert tag to hex string
    if (bin_2_hex(tag->tag, tag->tag_len, JSON_HEX_ENCODED_STRING_PREFIX, tag_str, sizeof(tag_str)) != 0) {
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
  "features": [],
  or
  "immutableFeatures": [],
*/
int json_features_deserialize(cJSON *output_obj, bool immutable, feature_list_t **feat_list) {
  if (output_obj == NULL || feat_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *feat_list_obj = NULL;

  if (immutable) {
    // immutable features array
    feat_list_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_IMMUTABLE_FEATS);
    if (!cJSON_IsArray(feat_list_obj)) {
      printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_IMMUTABLE_FEATS);
      return -1;
    }
  } else {
    // features array
    feat_list_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_FEATURES);
    if (!cJSON_IsArray(feat_list_obj)) {
      printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_FEATURES);
      return -1;
    }
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, feat_list_obj) {
    // type
    uint8_t output_feature_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &output_feature_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // feature
    switch (output_feature_type) {
      case FEAT_SENDER_TYPE:
        if (json_feat_sender_deserialize(elm, feat_list) != 0) {
          printf("[%s:%d] parsing sender feature failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case FEAT_ISSUER_TYPE:
        if (json_feat_issuer_deserialize(elm, feat_list) != 0) {
          printf("[%s:%d] parsing issuer feature failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case FEAT_METADATA_TYPE:
        if (json_feat_metadata_deserialize(elm, feat_list) != 0) {
          printf("[%s:%d] parsing metadata feature failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case FEAT_TAG_TYPE:
        if (json_feat_tag_deserialize(elm, feat_list) != 0) {
          printf("[%s:%d] parsing tag feature failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      default:
        printf("[%s:%d] unsupported feature\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}

cJSON *json_features_serialize(feature_list_t *feat_list) {
  // omit an empty array
  if (feature_list_len(feat_list) == 0) {
    return NULL;
  }

  // create feature array
  cJSON *feats = cJSON_CreateArray();
  if (feats) {
    if (!feat_list) {
      // empty feature list
      return feats;
    }

    cJSON *item = NULL;
    feature_list_t *elm;
    LL_FOREACH(feat_list, elm) {
      switch (elm->current->type) {
        case FEAT_SENDER_TYPE:
          item = json_feat_sender_serialize(elm->current);
          break;
        case FEAT_ISSUER_TYPE:
          item = json_feat_issuer_serialize(elm->current);
          break;
        case FEAT_METADATA_TYPE:
          item = json_feat_metadata_serialize((feature_metadata_t *)elm->current);
          break;
        case FEAT_TAG_TYPE:
          item = json_feat_tag_serialize((feature_tag_t *)elm->current);
          break;
        default:
          printf("[%s:%d] unsupported feature\n", __func__, __LINE__);
          break;
      }

      if (item) {
        // add item to array
        if (!cJSON_AddItemToArray(feats, item)) {
          printf("[%s:%d] add feature to array error\n", __func__, __LINE__);
          cJSON_Delete(item);
          cJSON_Delete(feats);
          return NULL;
        }
      } else {
        printf("[%s:%d] serialize feature error\n", __func__, __LINE__);
        cJSON_Delete(feats);
        return NULL;
      }
    }
  }

  return feats;
}
