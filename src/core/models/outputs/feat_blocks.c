// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/outputs/feat_blocks.h"
#include "utlist.h"

static feat_metadata_blk_t* feat_metadata_new(byte_t const data[], uint32_t data_len) {
  if (!data || data_len == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (data_len > MAX_METADATA_LENGTH_BYTES) {
    printf("[%s:%d] data must smaller than %d\n", __func__, __LINE__, MAX_METADATA_LENGTH_BYTES);
    return NULL;
  }

  feat_metadata_blk_t* meta = malloc(sizeof(feat_metadata_blk_t));
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

static size_t feat_metadata_serialized_len(feat_metadata_blk_t* meta) {
  if (meta) {
    return sizeof(meta->data_len) + meta->data_len;
  }
  return 0;
}

static size_t feat_metadata_serialize(feat_metadata_blk_t* meta, byte_t buf[], size_t buf_len) {
  size_t offset = 0;
  if (meta) {
    if (buf_len >= feat_metadata_serialized_len(meta)) {
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

static feat_metadata_blk_t* feat_metadata_deserialize(byte_t const buf[], size_t buf_len) {
  // allocate metadata object
  feat_metadata_blk_t* meta = malloc(sizeof(feat_metadata_blk_t));

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

static void feat_metadata_free(feat_metadata_blk_t* meta) {
  if (meta) {
    if (meta->data) {
      free(meta->data);
    }
    free(meta);
  }
}

static feat_tag_blk_t* feat_tag_new(byte_t const tag[], uint8_t tag_len) {
  if (!tag || tag_len == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (tag_len > MAX_INDEX_TAG_BYTES) {
    printf("[%s:%d] tag length must smaller than %d\n", __func__, __LINE__, MAX_INDEX_TAG_BYTES);
    return NULL;
  }

  feat_tag_blk_t* idx = malloc(sizeof(feat_tag_blk_t));
  if (idx) {
    memcpy(idx->tag, tag, tag_len);
    idx->tag_len = tag_len;
    return idx;
  }
  return idx;
}

static size_t feat_tag_serialize_len(feat_tag_blk_t* tag) {
  if (tag) {
    return sizeof(tag->tag_len) + tag->tag_len;
  }
  return 0;
}

static size_t feat_tag_serialize(feat_tag_blk_t* tag, byte_t buf[], size_t buf_len) {
  size_t offset = 0;
  if (tag) {
    if (buf_len >= feat_tag_serialize_len(tag)) {
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

static feat_tag_blk_t* feat_tag_deserialize(byte_t const buf[], size_t buf_len) {
  // allocate tag object
  feat_tag_blk_t* tag = malloc(sizeof(feat_tag_blk_t));

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

static void feat_tag_free(feat_tag_blk_t* tag) {
  if (tag) {
    free(tag);
  }
}

// feature blocks must be sorted in ascending order based on feature block type
static int feat_blk_type_sort(feat_blk_list_t* blk1, feat_blk_list_t* blk2) {
  return memcmp(&blk1->blk->type, &blk2->blk->type, sizeof(uint8_t));
}

feat_block_t* feat_blk_sender_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = address_clone(addr);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_SENDER_BLOCK;
    return blk;
  }
  return blk;
}

feat_block_t* feat_blk_issuer_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = address_clone(addr);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_ISSUER_BLOCK;
    return blk;
  }
  return blk;
}

feat_block_t* feat_blk_metadata_new(byte_t const data[], uint32_t data_len) {
  if (!data) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = feat_metadata_new(data, data_len);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_METADATA_BLOCK;
    return blk;
  }
  return blk;
}

feat_block_t* feat_blk_tag_new(byte_t const tag[], uint8_t tag_len) {
  if (!tag || !tag_len || (tag_len > MAX_INDEX_TAG_BYTES)) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = feat_tag_new(tag, tag_len);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_TAG_BLOCK;
    return blk;
  }
  return blk;
}

size_t feat_blk_serialize_len(feat_block_t const* const blk) {
  if (!blk) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
    case FEAT_ISSUER_BLOCK:
      // block type + address
      return sizeof(uint8_t) + address_serialized_len((address_t*)blk->block);
    case FEAT_METADATA_BLOCK:
      // block type + metadata block
      return sizeof(uint8_t) + feat_metadata_serialized_len((feat_metadata_blk_t*)blk->block);
    case FEAT_TAG_BLOCK:
      // block type + tag block
      return sizeof(uint8_t) + feat_tag_serialize_len((feat_tag_blk_t*)blk->block);
    default:
      printf("[%s:%d] unknown feature block type\n", __func__, __LINE__);
      return 0;
  }
}

size_t feat_blk_serialize(feat_block_t* blk, byte_t buf[], size_t buf_len) {
  if (!blk || !buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = feat_blk_serialize_len(blk);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  // fillin block type
  memcpy(buf, &blk->type, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
    case FEAT_ISSUER_BLOCK:
      // serialize address object
      offset += address_serialize((address_t*)blk->block, buf + offset, buf_len - offset);
      break;
    case FEAT_METADATA_BLOCK:
      // serialize metadata
      offset += feat_metadata_serialize((feat_metadata_blk_t*)blk->block, buf + offset, buf_len - offset);
      break;
    case FEAT_TAG_BLOCK:
      // serialize tag block
      offset += feat_tag_serialize((feat_tag_blk_t*)blk->block, buf + offset, buf_len - offset);
      break;
    default:
      break;
  }
  return offset;
}

feat_block_t* feat_blk_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (!blk) {
    printf("[%s:%d] new feature block failed\n", __func__, __LINE__);
    return NULL;
  }

  size_t offset = sizeof(uint8_t);
  // fetch block type
  blk->type = buf[0];
  blk->block = NULL;

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
    case FEAT_ISSUER_BLOCK:
      blk->block = address_deserialize(buf + offset, buf_len - offset);
      break;
    case FEAT_METADATA_BLOCK:
      blk->block = feat_metadata_deserialize(buf + offset, buf_len - offset);
      break;
    case FEAT_TAG_BLOCK:
      blk->block = feat_tag_deserialize(buf + offset, buf_len - offset);
      break;
    default:
      break;
  }

  if (!blk->block) {
    printf("[%s:%d] block deserialization failed\n", __func__, __LINE__);
    feat_blk_free(blk);
    return NULL;
  }
  return blk;
}

void feat_blk_free(feat_block_t* blk) {
  if (blk) {
    if (blk->block) {
      switch (blk->type) {
        case FEAT_ISSUER_BLOCK:
        case FEAT_SENDER_BLOCK:
          free_address((address_t*)blk->block);
          break;
        case FEAT_METADATA_BLOCK:
          feat_metadata_free((feat_metadata_blk_t*)blk->block);
          break;
        case FEAT_TAG_BLOCK:
          feat_tag_free((feat_tag_blk_t*)blk->block);
          break;
        default:
          break;
      }
    }
    free(blk);
  }
}

void feat_blk_print(feat_block_t* blk) {
  if (!blk) {
    return;
  }

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
      printf("Sender:");
      address_print((address_t*)blk->block);
      break;
    case FEAT_ISSUER_BLOCK:
      printf("Issuer:");
      address_print((address_t*)blk->block);
      break;
    case FEAT_METADATA_BLOCK:
      printf("Metadata: ");
      dump_hex_str(((feat_metadata_blk_t*)blk->block)->data, ((feat_metadata_blk_t*)blk->block)->data_len);
      break;
    case FEAT_TAG_BLOCK:
      printf("Tag: ");
      dump_hex_str(((feat_tag_blk_t*)blk->block)->tag, ((feat_tag_blk_t*)blk->block)->tag_len);
      break;
    default:
      break;
  }
}

feat_blk_list_t* feat_blk_list_new() { return NULL; }

uint8_t feat_blk_list_len(feat_blk_list_t* list) {
  feat_blk_list_t* elm = NULL;
  uint8_t len = 0;

  if (list) {
    LL_COUNT(list, elm, len);
    return len;
  }
  return len;
}

feat_block_t* feat_blk_list_get_type(feat_blk_list_t* list, feat_block_e type) {
  feat_blk_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (elm->blk->type == type) {
        return elm->blk;
      }
    }
  }
  return NULL;
}

feat_block_t* feat_blk_list_get(feat_blk_list_t* list, uint8_t index) {
  uint8_t count = 0;
  feat_blk_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (count == index) {
        return elm->blk;
      }
      count++;
    }
  }
  return NULL;
}

int feat_blk_list_add_sender(feat_blk_list_t** list, address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the sender block
  if (feat_blk_list_get_type(*list, FEAT_SENDER_BLOCK)) {
    printf("[%s:%d] sender block has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = feat_blk_sender_new(addr);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feat_blk_list_add_issuer(feat_blk_list_t** list, address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the issuer block
  if (feat_blk_list_get_type(*list, FEAT_ISSUER_BLOCK)) {
    printf("[%s:%d] issuer block has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = feat_blk_issuer_new(addr);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feat_blk_list_add_metadata(feat_blk_list_t** list, byte_t const data[], uint32_t data_len) {
  if (!data || !data_len) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the metadata block
  if (feat_blk_list_get_type(*list, FEAT_METADATA_BLOCK)) {
    printf("[%s:%d] metadata block has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = feat_blk_metadata_new(data, data_len);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feat_blk_list_add_tag(feat_blk_list_t** list, byte_t const tag[], uint8_t tag_len) {
  if (!tag || !tag_len) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= MAX_FEATURE_BLOCK_COUNT) {
    printf("[%s:%d]list count must smaller than %d\n", __func__, __LINE__, MAX_FEATURE_BLOCK_COUNT);
    return -1;
  }

  // at most one of the metadata block
  if (feat_blk_list_get_type(*list, FEAT_TAG_BLOCK)) {
    printf("[%s:%d] tag block has exist in the list\n", __func__, __LINE__);
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = feat_blk_tag_new(tag, tag_len);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }
  return -1;
}

size_t feat_blk_list_serialize_len(feat_blk_list_t* list) {
  if (list) {
    feat_blk_list_t* elm;
    // feature blocks layout: Block Count + Blocks
    // uint8_t is the serialized size of block count
    size_t len = sizeof(uint8_t);
    LL_FOREACH(list, elm) { len += feat_blk_serialize_len(elm->blk); }
    return len;
  }
  return 0;
}

void feat_blk_list_sort(feat_blk_list_t** list) {
  // sort feature blocks in ascending order based on feature block type
  LL_SORT(*list, feat_blk_type_sort);
}

size_t feat_blk_list_serialize(feat_blk_list_t** list, byte_t buf[], size_t buf_len) {
  if ((list || *list) && buf) {
    // serialized len = block count + blocks
    size_t expected_bytes = feat_blk_list_serialize_len(*list);
    if (buf_len < expected_bytes) {
      printf("[%s:%d] insufficent buffer size\n", __func__, __LINE__);
      return 0;
    }

    size_t offset = sizeof(uint8_t);
    feat_blk_list_t* elm;
    // fetch block count
    buf[0] = feat_blk_list_len(*list);

    // sort by block types
    feat_blk_list_sort(list);

    // serialize feature blocks
    LL_FOREACH(*list, elm) { offset += feat_blk_serialize(elm->blk, buf + offset, buf_len - offset); }
    // check the length of the serialized data
    if (offset != expected_bytes) {
      printf("[%s:%d] offset is not matched with expectation\n", __func__, __LINE__);
      return 0;
    }
    return offset;
  }
  return 0;
}

feat_blk_list_t* feat_blk_list_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len <= 1) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  feat_blk_list_t* list = feat_blk_list_new();
  size_t offset = sizeof(uint8_t);
  uint8_t blk_cnt = buf[0];
  for (uint8_t i = 0; i < blk_cnt; i++) {
    // create a new feature block list object
    feat_blk_list_t* new_blk = malloc(sizeof(feat_blk_list_t));
    if (new_blk) {
      // get feature block from serialized data
      new_blk->blk = feat_blk_deserialize(buf + offset, buf_len - offset);
      if (new_blk->blk) {
        // offset of the next block
        offset += feat_blk_serialize_len(new_blk->blk);
        LL_APPEND(list, new_blk);

      } else {
        // error on feature block deserialize
        free(new_blk);
        feat_blk_list_free(list);
        return NULL;
      }
    } else {
      // error on new feature block list
      feat_blk_list_free(list);
      return NULL;
    }
  }

  return list;
}

feat_blk_list_t* feat_blk_list_clone(feat_blk_list_t const* const list) {
  if (list == NULL) {
    return NULL;
  }

  feat_blk_list_t* new_list = feat_blk_list_new();

  int res;
  feat_blk_list_t* elm;
  LL_FOREACH((feat_blk_list_t*)list, elm) {
    switch (elm->blk->type) {
      case FEAT_SENDER_BLOCK:
        res = feat_blk_list_add_sender(&new_list, (address_t*)elm->blk->block);
        break;
      case FEAT_ISSUER_BLOCK:
        res = feat_blk_list_add_issuer(&new_list, (address_t*)elm->blk->block);
        break;
      case FEAT_METADATA_BLOCK:
        res = feat_blk_list_add_metadata(&new_list, ((feat_metadata_blk_t*)elm->blk->block)->data,
                                         ((feat_metadata_blk_t*)elm->blk->block)->data_len);
        break;
      case FEAT_TAG_BLOCK:
        res = feat_blk_list_add_tag(&new_list, ((feat_tag_blk_t*)elm->blk->block)->tag,
                                    ((feat_tag_blk_t*)elm->blk->block)->tag_len);
        break;
      default:
        break;
    }
    if (res == -1) {
      printf("[%s:%d] can not clone feature blocks\n", __func__, __LINE__);
      feat_blk_list_free(new_list);
      return NULL;
    }
  }

  return new_list;
}

void feat_blk_list_print(feat_blk_list_t* list, uint8_t indentation) {
  feat_blk_list_t* elm;
  uint8_t index = 0;
  printf("%sFeature Blocks: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tBlock Count: %d\n", PRINT_INDENTATION(indentation), feat_blk_list_len(list));
  if (list) {
    LL_FOREACH(list, elm) {
      printf("%s\t#%d ", PRINT_INDENTATION(indentation), index);
      feat_blk_print(elm->blk);
      index++;
    }
  }
  printf("%s]\n", PRINT_INDENTATION(indentation));
}

void feat_blk_list_free(feat_blk_list_t* list) {
  feat_blk_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      feat_blk_free(elm->blk);
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}
