// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "core/constants.h"
#include "core/models/outputs/features.h"
#include "core/utils/macros.h"
#include "utlist.h"

static feature_metadata_t* metadata_new(byte_t const data[], uint16_t data_len) {
  if (!data || data_len == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (data_len > MAX_METADATA_LENGTH_BYTES) {
    printf("[%s:%d] data length must be smaller than %d\n", __func__, __LINE__, MAX_METADATA_LENGTH_BYTES);
    return NULL;
  }

  feature_metadata_t* meta = malloc(sizeof(feature_metadata_t));
  if (meta) {
    meta->data = malloc(data_len);
    if (!meta->data) {
      free(meta);
      return NULL;
    }
    memcpy(meta->data, data, data_len);
    meta->data_len = data_len;
    return meta;
  }
  return meta;
}

static size_t metadata_serialized_len(feature_metadata_t* meta) {
  if (meta) {
    return sizeof(meta->data_len) + meta->data_len;
  }
  return 0;
}

static size_t metadata_serialize(feature_metadata_t* meta, byte_t buf[], size_t buf_len) {
  size_t offset = 0;
  if (meta) {
    if (buf_len >= metadata_serialized_len(meta)) {
      memcpy(buf, &meta->data_len, sizeof(meta->data_len));
      offset += sizeof(meta->data_len);
      memcpy(buf + offset, meta->data, meta->data_len);
      offset += meta->data_len;
    } else {
      printf("[%s:%d] insufficent buffer size\n", __func__, __LINE__);
    }
  }
  return offset;
}

static feature_metadata_t* metadata_deserialize(byte_t const buf[], size_t buf_len) {
  // allocate metadata object
  feature_metadata_t* meta = malloc(sizeof(feature_metadata_t));

  // meta/buf are not null and buf_len can contain one byte
  if (meta && buf && (buf_len >= sizeof(meta->data_len) + sizeof(byte_t))) {
    // fetch the length of metadata
    size_t offset = sizeof(meta->data_len);
    memcpy(&meta->data_len, buf, sizeof(meta->data_len));

    // check if buffer length smaller than metadata length
    if ((buf_len - offset) >= meta->data_len) {
      // allocate metadata memory
      meta->data = malloc(meta->data_len);
      if (meta->data) {
        // copy buffer data to metadata
        memcpy(meta->data, buf + offset, meta->data_len);
        return meta;
      } else {
        printf("[%s:%d] buffer length doesn't match with data length\n", __func__, __LINE__);
      }
    } else {
      printf("[%s:%d] buffer length doesn't match with data length\n", __func__, __LINE__);
    }
  }
  free(meta);
  return NULL;
}

static void metadata_free(feature_metadata_t* meta) {
  if (meta) {
    if (meta->data) {
      free(meta->data);
    }
    free(meta);
  }
}

static feature_tag_t* tag_new(byte_t const tag[], uint8_t tag_len) {
  if (!tag || tag_len == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (tag_len > MAX_INDEX_TAG_BYTES) {
    printf("[%s:%d] tag length must smaller than %d\n", __func__, __LINE__, MAX_INDEX_TAG_BYTES);
    return NULL;
  }

  feature_tag_t* idx = malloc(sizeof(feature_tag_t));
  if (idx) {
    memcpy(idx->tag, tag, tag_len);
    idx->tag_len = tag_len;
    return idx;
  }
  return idx;
}

static size_t tag_serialize_len(feature_tag_t* tag) {
  if (tag) {
    return sizeof(tag->tag_len) + tag->tag_len;
  }
  return 0;
}

static size_t tag_serialize(feature_tag_t* tag, byte_t buf[], size_t buf_len) {
  size_t offset = 0;
  if (tag) {
    if (buf_len >= tag_serialize_len(tag)) {
      memcpy(buf, &tag->tag_len, sizeof(tag->tag_len));
      offset += sizeof(tag->tag_len);
      memcpy(buf + offset, tag->tag, tag->tag_len);
      offset += tag->tag_len;
    } else {
      printf("[%s:%d] insufficent buffer size\n", __func__, __LINE__);
    }
  }
  return offset;
}

static feature_tag_t* tag_deserialize(byte_t const buf[], size_t buf_len) {
  // allocate tag object
  feature_tag_t* tag = malloc(sizeof(feature_tag_t));

  // tag/buf are not null and buf_len can contain more than one byte
  if (tag && buf && (buf_len >= sizeof(tag->tag_len) + sizeof(byte_t))) {
    // fetch the length of tag
    size_t offset = sizeof(tag->tag_len);
    memcpy(&tag->tag_len, buf, sizeof(tag->tag_len));

    // check if buffer length smaller than tag length and tag length smaller than MAX_INDEX_TAG_BYTES
    if (((buf_len - offset) >= tag->tag_len) && (tag->tag_len <= MAX_INDEX_TAG_BYTES)) {
      memcpy(tag->tag, buf + offset, tag->tag_len);
      return tag;
    } else {
      printf("[%s:%d] buffer length doesn't match with tag length\n", __func__, __LINE__);
    }
  }
  free(tag);
  return NULL;
}

static void tag_free(feature_tag_t* tag) {
  if (tag) {
    free(tag);
  }
}

// features must be sorted in ascending order based on feature type
static int feature_type_sort(feature_list_t* feat1, feature_list_t* feat2) {
  return memcmp(&feat1->current->type, &feat2->current->type, sizeof(uint8_t));
}

output_feature_t* feature_sender_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  output_feature_t* feat = malloc(sizeof(output_feature_t));
  if (feat) {
    feat->obj = address_clone(addr);
    if (!feat->obj) {
      free(feat);
      return NULL;
    }
    feat->type = FEAT_SENDER_TYPE;
    return feat;
  }
  return feat;
}

output_feature_t* feature_issuer_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  output_feature_t* feat = malloc(sizeof(output_feature_t));
  if (feat) {
    feat->obj = address_clone(addr);
    if (!feat->obj) {
      free(feat);
      return NULL;
    }
    feat->type = FEAT_ISSUER_TYPE;
    return feat;
  }
  return feat;
}

output_feature_t* feature_metadata_new(byte_t const data[], uint32_t data_len) {
  if (!data) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  output_feature_t* feat = malloc(sizeof(output_feature_t));
  if (feat) {
    feat->obj = metadata_new(data, data_len);
    if (!feat->obj) {
      free(feat);
      return NULL;
    }
    feat->type = FEAT_METADATA_TYPE;
    return feat;
  }
  return feat;
}

output_feature_t* feature_tag_new(byte_t const tag[], uint8_t tag_len) {
  if (!tag || !tag_len || (tag_len > MAX_INDEX_TAG_BYTES)) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  output_feature_t* feat = malloc(sizeof(output_feature_t));
  if (feat) {
    feat->obj = tag_new(tag, tag_len);
    if (!feat->obj) {
      free(feat);
      return NULL;
    }
    feat->type = FEAT_TAG_TYPE;
    return feat;
  }
  return feat;
}

size_t feature_serialize_len(output_feature_t const* const feat) {
  if (!feat) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  switch (feat->type) {
    case FEAT_SENDER_TYPE:
    case FEAT_ISSUER_TYPE:
      // feature type + address
      return sizeof(uint8_t) + address_serialized_len((address_t*)feat->obj);
    case FEAT_METADATA_TYPE:
      // feature type + metadata feature
      return sizeof(uint8_t) + metadata_serialized_len((feature_metadata_t*)feat->obj);
    case FEAT_TAG_TYPE:
      // feature type + tag feature
      return sizeof(uint8_t) + tag_serialize_len((feature_tag_t*)feat->obj);
    default:
      printf("[%s:%d] unknown feature type\n", __func__, __LINE__);
      return 0;
  }
}

size_t feature_serialize(output_feature_t* feat, byte_t buf[], size_t buf_len) {
  if (!feat || !buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = feature_serialize_len(feat);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  // fillin feature type
  memcpy(buf, &feat->type, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  switch (feat->type) {
    case FEAT_SENDER_TYPE:
    case FEAT_ISSUER_TYPE:
      // serialize address object
      offset += address_serialize((address_t*)feat->obj, buf + offset, buf_len - offset);
      break;
    case FEAT_METADATA_TYPE:
      // serialize metadata feature
      offset += metadata_serialize((feature_metadata_t*)feat->obj, buf + offset, buf_len - offset);
      break;
    case FEAT_TAG_TYPE:
      // serialize tag feature
      offset += tag_serialize((feature_tag_t*)feat->obj, buf + offset, buf_len - offset);
      break;
    default:
      break;
  }
  return offset;
}

output_feature_t* feature_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_feature_t* feat = malloc(sizeof(output_feature_t));
  if (!feat) {
    printf("[%s:%d] allocate a feature object failed\n", __func__, __LINE__);
    return NULL;
  }

  size_t offset = sizeof(uint8_t);
  // fetch feature type
  feat->type = buf[0];
  feat->obj = NULL;

  switch (feat->type) {
    case FEAT_SENDER_TYPE:
    case FEAT_ISSUER_TYPE:
      feat->obj = address_deserialize(buf + offset, buf_len - offset);
      break;
    case FEAT_METADATA_TYPE:
      feat->obj = metadata_deserialize(buf + offset, buf_len - offset);
      break;
    case FEAT_TAG_TYPE:
      feat->obj = tag_deserialize(buf + offset, buf_len - offset);
      break;
    default:
      break;
  }

  if (!feat->obj) {
    printf("[%s:%d] feature deserialization failed\n", __func__, __LINE__);
    feature_free(feat);
    return NULL;
  }
  return feat;
}

void feature_free(output_feature_t* feat) {
  if (feat) {
    if (feat->obj) {
      switch (feat->type) {
        case FEAT_ISSUER_TYPE:
        case FEAT_SENDER_TYPE:
          address_free((address_t*)feat->obj);
          break;
        case FEAT_METADATA_TYPE:
          metadata_free((feature_metadata_t*)feat->obj);
          break;
        case FEAT_TAG_TYPE:
          tag_free((feature_tag_t*)feat->obj);
          break;
        default:
          break;
      }
    }
    free(feat);
  }
}

void feature_print(output_feature_t* feat) {
  if (!feat) {
    return;
  }

  switch (feat->type) {
    case FEAT_SENDER_TYPE:
      printf("Sender:");
      address_print((address_t*)feat->obj);
      break;
    case FEAT_ISSUER_TYPE:
      printf("Issuer:");
      address_print((address_t*)feat->obj);
      break;
    case FEAT_METADATA_TYPE:
      printf("Metadata: ");
      dump_hex_str(((feature_metadata_t*)feat->obj)->data, ((feature_metadata_t*)feat->obj)->data_len);
      break;
    case FEAT_TAG_TYPE:
      printf("Tag: ");
      dump_hex_str(((feature_tag_t*)feat->obj)->tag, ((feature_tag_t*)feat->obj)->tag_len);
      break;
    default:
      break;
  }
}

feature_list_t* feature_list_new() { return NULL; }

uint8_t feature_list_len(feature_list_t* list) {
  feature_list_t* elm = NULL;
  uint8_t len = 0;

  if (list) {
    LL_COUNT(list, elm, len);
    return len;
  }
  return len;
}

output_feature_t* feature_list_get_type(feature_list_t* list, feature_type_e type) {
  feature_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (elm->current->type == type) {
        return elm->current;
      }
    }
  }
  return NULL;
}

output_feature_t* feature_list_get(feature_list_t* list, uint8_t index) {
  uint8_t count = 0;
  feature_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (count == index) {
        return elm->current;
      }
      count++;
    }
  }
  return NULL;
}

int feature_list_add_sender(feature_list_t** list, address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feature_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the sender feature
  if (feature_list_get_type(*list, FEAT_SENDER_TYPE)) {
    printf("[%s:%d] sender feature has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feature_list_t* next = malloc(sizeof(feature_list_t));
  if (next) {
    next->current = feature_sender_new(addr);
    if (next->current) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feature_list_add_issuer(feature_list_t** list, address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feature_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the issuer feature
  if (feature_list_get_type(*list, FEAT_ISSUER_TYPE)) {
    printf("[%s:%d] issuer feature has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feature_list_t* next = malloc(sizeof(feature_list_t));
  if (next) {
    next->current = feature_issuer_new(addr);
    if (next->current) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feature_list_add_metadata(feature_list_t** list, byte_t const data[], uint32_t data_len) {
  if (!data || !data_len) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feature_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the metadata feature
  if (feature_list_get_type(*list, FEAT_METADATA_TYPE)) {
    printf("[%s:%d] metadata feature has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feature_list_t* next = malloc(sizeof(feature_list_t));
  if (next) {
    next->current = feature_metadata_new(data, data_len);
    if (next->current) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feature_list_add_tag(feature_list_t** list, byte_t const tag[], uint8_t tag_len) {
  if (!tag || !tag_len) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feature_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the tag feature
  if (feature_list_get_type(*list, FEAT_TAG_TYPE)) {
    printf("[%s:%d] tag feature has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feature_list_t* next = malloc(sizeof(feature_list_t));
  if (next) {
    next->current = feature_tag_new(tag, tag_len);
    if (next->current) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }
  return -1;
}

size_t feature_list_serialize_len(feature_list_t* list) {
  if (list) {
    feature_list_t* elm;
    // features list layout: Feature Count + Features
    // uint8_t is the serialized size of the feature count
    size_t len = sizeof(uint8_t);
    LL_FOREACH(list, elm) { len += feature_serialize_len(elm->current); }
    return len;
  }
  // return the size of feature count
  return sizeof(uint8_t);
}

void feature_list_sort(feature_list_t** list) {
  // sort features in ascending order based on the feature type
  LL_SORT(*list, feature_type_sort);
}

size_t feature_list_serialize(feature_list_t** list, byte_t buf[], size_t buf_len) {
  if ((list || *list) && buf) {
    // serialized len = feature count + features
    size_t expected_bytes = feature_list_serialize_len(*list);
    if (buf_len < expected_bytes) {
      printf("[%s:%d] insufficent buffer size\n", __func__, __LINE__);
      return 0;
    }

    size_t offset = sizeof(uint8_t);
    feature_list_t* elm;
    // fetch feature count
    buf[0] = feature_list_len(*list);

    // sort by feature types
    feature_list_sort(list);

    // serialize feature list
    LL_FOREACH(*list, elm) { offset += feature_serialize(elm->current, buf + offset, buf_len - offset); }
    // check the length of the serialized data
    if (offset != expected_bytes) {
      printf("[%s:%d] offset is not matched with expectation\n", __func__, __LINE__);
      return 0;
    }
    return offset;
  }
  return 0;
}

feature_list_t* feature_list_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len <= 1) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  feature_list_t* list = feature_list_new();
  size_t offset = sizeof(uint8_t);
  uint8_t feat_cnt = buf[0];
  for (uint8_t i = 0; i < feat_cnt; i++) {
    // create a new feature list object
    feature_list_t* new_feat = malloc(sizeof(feature_list_t));
    if (new_feat) {
      // get feature from serialized data
      new_feat->current = feature_deserialize(buf + offset, buf_len - offset);
      if (new_feat->current) {
        // offset of the next feature
        offset += feature_serialize_len(new_feat->current);
        LL_APPEND(list, new_feat);

      } else {
        // error on feature deserialize
        free(new_feat);
        feature_list_free(list);
        return NULL;
      }
    } else {
      // error on new feature list
      feature_list_free(list);
      return NULL;
    }
  }

  return list;
}

feature_list_t* feature_list_clone(feature_list_t const* const list) {
  if (list == NULL) {
    return NULL;
  }

  feature_list_t* new_list = feature_list_new();

  int res = -1;
  feature_list_t* elm;
  LL_FOREACH((feature_list_t*)list, elm) {
    switch (elm->current->type) {
      case FEAT_SENDER_TYPE:
        res = feature_list_add_sender(&new_list, (address_t*)elm->current->obj);
        break;
      case FEAT_ISSUER_TYPE:
        res = feature_list_add_issuer(&new_list, (address_t*)elm->current->obj);
        break;
      case FEAT_METADATA_TYPE:
        res = feature_list_add_metadata(&new_list, ((feature_metadata_t*)elm->current->obj)->data,
                                        ((feature_metadata_t*)elm->current->obj)->data_len);
        break;
      case FEAT_TAG_TYPE:
        res = feature_list_add_tag(&new_list, ((feature_tag_t*)elm->current->obj)->tag,
                                   ((feature_tag_t*)elm->current->obj)->tag_len);
        break;
      default:
        break;
    }
    if (res == -1) {
      printf("[%s:%d] can not clone the feature list\n", __func__, __LINE__);
      feature_list_free(new_list);
      return NULL;
    }
  }

  return new_list;
}

void feature_list_print(feature_list_t* list, bool immutable, uint8_t indentation) {
  feature_list_t* elm;
  uint8_t index = 0;

  if (immutable) {
    printf("%sImmutable Features: [\n", PRINT_INDENTATION(indentation));
  } else {
    printf("%sFeatures: [\n", PRINT_INDENTATION(indentation));
  }

  printf("%s\tFeature Count: %d\n", PRINT_INDENTATION(indentation), feature_list_len(list));
  if (list) {
    LL_FOREACH(list, elm) {
      printf("%s\t#%d ", PRINT_INDENTATION(indentation), index);
      feature_print(elm->current);
      index++;
    }
  }
  printf("%s]\n", PRINT_INDENTATION(indentation));
}

void feature_list_free(feature_list_t* list) {
  feature_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      feature_free(elm->current);
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}
