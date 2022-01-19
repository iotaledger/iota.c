// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/outputs/feat_blocks.h"
#include "utlist.h"

static feat_metadata_blk_t* new_feat_metadata(byte_t const data[], uint32_t data_len) {
  if (!data || data_len == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
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

static void free_feat_metadata(feat_metadata_blk_t* meta) {
  if (meta) {
    if (meta->data) {
      free(meta->data);
    }
    free(meta);
  }
}

static feat_tag_blk_t* new_feat_tag(byte_t const tag[], uint8_t tag_len) {
  if (!tag || tag_len == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
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

// feature blocks must be sorted in ascending order based on feature block type
static int feat_blk_type_sort(feat_blk_list_t* blk1, feat_blk_list_t* blk2) {
  return memcmp(&blk1->blk->type, &blk2->blk->type, sizeof(uint8_t));
}

feat_block_t* new_feat_blk_sender(address_t const* const addr) {
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

feat_block_t* new_feat_blk_issuer(address_t const* const addr) {
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

feat_block_t* new_feat_blk_metadata(byte_t const data[], uint32_t data_len) {
  if (!data) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = new_feat_metadata(data, data_len);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_METADATA_BLOCK;
    return blk;
  }
  return blk;
}

feat_block_t* new_feat_blk_tag(byte_t const tag[], uint8_t tag_len) {
  if (!tag) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = malloc(sizeof(feat_tag_blk_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_TAG_BLOCK;
    ((feat_tag_blk_t*)blk->block)->tag_len = tag_len;
    memcpy(((feat_tag_blk_t*)blk->block)->tag, tag, tag_len);
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
      // block type + data len + data
      return sizeof(uint8_t) + sizeof(uint32_t) + ((feat_metadata_blk_t*)blk->block)->data_len;
    case FEAT_TAG_BLOCK:
      // block type + tag len + tag
      return sizeof(uint8_t) + sizeof(uint8_t) + ((feat_tag_blk_t*)blk->block)->tag_len;
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

  // fillin block type
  memcpy(buf, &blk->type, sizeof(uint8_t));

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
    case FEAT_ISSUER_BLOCK:
      // serialize address object
      if (address_serialize((address_t*)blk->block, buf + 1, buf_len - 1) != 0) {
        printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
      }
      break;
    case FEAT_METADATA_BLOCK:
      // serialize data_len and data
      memcpy(buf + sizeof(uint8_t), &((feat_metadata_blk_t*)blk->block)->data_len, sizeof(uint32_t));
      memcpy(buf + sizeof(uint8_t) + sizeof(uint32_t), ((feat_metadata_blk_t*)blk->block)->data,
             ((feat_metadata_blk_t*)blk->block)->data_len);
      break;
    case FEAT_TAG_BLOCK:
      // serialize tag_len and tag
      memcpy(buf + sizeof(uint8_t), &((feat_tag_blk_t*)blk->block)->tag_len, sizeof(uint8_t));
      memcpy(buf + sizeof(uint8_t) + sizeof(uint8_t), ((feat_tag_blk_t*)blk->block)->tag,
             ((feat_tag_blk_t*)blk->block)->tag_len);
      break;
    default:
      break;
  }
  return expected_bytes;
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

  // fetch block type
  blk->type = buf[0];
  blk->block = NULL;

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
    case FEAT_ISSUER_BLOCK: {
      // serialize address
      address_t* addr = malloc(sizeof(address_t));
      if (!addr) {
        free_feat_blk(blk);
        printf("[%s:%d] new address failed\n", __func__, __LINE__);
        return NULL;
      }
      // fetch address type
      addr->type = buf[1];
      // point address object to the feature block member
      blk->block = addr;
      // validating data length for address object
      if (buf_len < (sizeof(uint8_t) + address_serialized_len(addr))) {
        printf("[%s:%d] invalid data length\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      memcpy(addr->address, buf + sizeof(uint8_t) * 2, address_len(addr));
    } break;

    case FEAT_METADATA_BLOCK: {
      uint32_t offset = sizeof(uint8_t) + sizeof(uint32_t);
      if (buf_len <= offset) {
        printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      // get data length
      uint32_t data_len = 0;
      memcpy(&data_len, buf + sizeof(uint8_t), sizeof(uint32_t));
      blk->block = new_feat_metadata(buf + offset, data_len);
      if (!blk->block) {
        printf("[%s:%d] deserialize metadata failed\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
    } break;
    case FEAT_TAG_BLOCK: {
      uint32_t offset = sizeof(uint8_t) + sizeof(uint8_t);
      if (buf_len <= offset) {
        printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      // get tag length
      uint32_t tag_len = 0;
      memcpy(&tag_len, buf + sizeof(uint8_t), sizeof(uint8_t));
      blk->block = new_feat_tag(buf + offset, tag_len);
      if (!blk->block) {
        printf("[%s:%d] deserialize metadata failed\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
    } break;
    default:
      break;
  }
  return blk;
}

void free_feat_blk(feat_block_t* blk) {
  if (blk) {
    if (blk->block) {
      if (blk->type == FEAT_METADATA_BLOCK) {
        free_feat_metadata((feat_metadata_blk_t*)blk->block);
      } else {
        free(blk->block);
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

feat_blk_list_t* new_feat_blk_list() { return NULL; }

uint8_t feat_blk_list_len(feat_blk_list_t* list) {
  feat_blk_list_t* elm = NULL;
  uint8_t len = 0;

  if (list) {
    LL_COUNT(list, elm, len);
    return len;
  }
  return len;
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
    return -1;
  }

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_sender(addr);
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
    return -1;
  }

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_issuer(addr);
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
  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_metadata(data, data_len);
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
  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_tag(tag, tag_len);
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
  feat_blk_list_t* elm;
  // feature blocks layout: Block Count + Blocks
  // uint8_t is the serialized size of block count
  size_t len = sizeof(uint8_t);
  if (list) {
    LL_FOREACH(list, elm) { len += feat_blk_serialize_len(elm->blk); }
  }
  return len;
}

size_t feat_blk_list_serialize(feat_blk_list_t* list, byte_t buf[], size_t buf_len) {
  if (list) {
    // serialized len = block count + blocks
    size_t expected_bytes = feat_blk_list_serialize_len(list);
    if (buf_len < expected_bytes) {
      return 0;
    }

    size_t offset = sizeof(uint8_t);
    feat_blk_list_t* elm;
    int ret = 0;
    // block count
    buf[0] = feat_blk_list_len(list);
    // sort feature blocks in ascending order based on feature block type
    LL_SORT(list, feat_blk_type_sort);
    // feature blocks
    LL_FOREACH(list, elm) { offset += feat_blk_serialize(elm->blk, buf + offset, buf_len - offset); }
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
    return NULL;
  }

  feat_blk_list_t* list = new_feat_blk_list();
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
        free_feat_blk_list(list);
        return NULL;
      }
    } else {
      // error on new feature block list
      free_feat_blk_list(list);
      return NULL;
    }
  }

  return list;
}

feat_blk_list_t* feat_blk_list_clone(feat_blk_list_t const* const list) {
  if (list == NULL) {
    return NULL;
  }

  feat_blk_list_t* new_list = new_feat_blk_list();

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
      free_feat_blk_list(new_list);
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

void free_feat_blk_list(feat_blk_list_t* list) {
  feat_blk_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      free_feat_blk(elm->blk);
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}
