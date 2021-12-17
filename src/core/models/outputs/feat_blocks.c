// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/models/outputs/feat_blocks.h"
#include "utlist.h"

static feat_metadata_blk_t* new_feat_metadata(byte_t const data[], uint32_t data_len) {
  if (!data || data_len == 0) {
    printf("[%s:%d] invalid paramter\n", __func__, __LINE__);
    return NULL;
  }

  feat_metadata_blk_t* meta = (feat_metadata_blk_t*)malloc(sizeof(feat_metadata_blk_t));
  if (meta) {
    meta->data = (byte_t*)malloc(data_len);
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

static feat_indexaction_blk_t* new_feat_indexaztion(byte_t const tag[], uint8_t tag_len) {
  if (!tag || tag_len == 0) {
    printf("[%s:%d] invalid paramter\n", __func__, __LINE__);
    return NULL;
  }

  feat_indexaction_blk_t* idx = (feat_indexaction_blk_t*)malloc(sizeof(feat_indexaction_blk_t));
  if (idx) {
    memcpy(idx->tag, tag, tag_len);
    idx->tag_len = tag_len;
    return idx;
  }
  return idx;
}

feat_block_t* new_feat_blk_sender(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid paramter\n", __func__, __LINE__);
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
    printf("[%s:%d] invalid paramter\n", __func__, __LINE__);
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

feat_block_t* new_feat_blk_ddr(uint64_t amount) {
  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = (uint64_t*)malloc(sizeof(uint64_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_DUST_DEP_RET_BLOCK;
    *((uint64_t*)blk->block) = amount;
    return blk;
  }
  return blk;
}

feat_block_t* new_feat_blk_tmi(uint32_t ms_idx) {
  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = (uint32_t*)malloc(sizeof(uint32_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_TIMELOCK_MS_INDEX_BLOCK;
    *((uint32_t*)blk->block) = ms_idx;
    return blk;
  }
  return blk;
}

feat_block_t* new_feat_blk_tu(uint32_t time) {
  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = (uint32_t*)malloc(sizeof(uint32_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_TIMELOCK_UNIX_BLOCK;
    *((uint32_t*)blk->block) = time;
    return blk;
  }
  return blk;
}

feat_block_t* new_feat_blk_emi(uint32_t ms_idx) {
  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = (uint32_t*)malloc(sizeof(uint32_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_EXPIRATION_MS_INDEX_BLOCK;
    *((uint32_t*)blk->block) = ms_idx;
    return blk;
  }
  return blk;
}

feat_block_t* new_feat_blk_eu(uint32_t time) {
  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = (uint32_t*)malloc(sizeof(uint32_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_EXPIRATION_UNIX_BLOCK;
    *((uint32_t*)blk->block) = time;
    return blk;
  }
  return blk;
}

feat_block_t* new_feat_blk_metadata(byte_t const data[], uint32_t data_len) {
  if (!data) {
    printf("[%s:%d] invalid paramter\n", __func__, __LINE__);
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

feat_block_t* new_feat_blk_indexaction(byte_t const tag[], uint8_t tag_len) {
  if (!tag) {
    printf("[%s:%d] invalid paramter\n", __func__, __LINE__);
    return NULL;
  }

  feat_block_t* blk = malloc(sizeof(feat_block_t));
  if (blk) {
    blk->block = (feat_indexaction_blk_t*)malloc(sizeof(feat_indexaction_blk_t));
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = FEAT_INDEXATION_BLOCK;
    ((feat_indexaction_blk_t*)blk->block)->tag_len = tag_len;
    memcpy(((feat_indexaction_blk_t*)blk->block)->tag, tag, tag_len);
    return blk;
  }
  return blk;
}

size_t feat_blk_serialize_len(feat_block_t const* const blk) {
  if (!blk) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return 0;
  }

  switch (blk->type) {
    case FEAT_SENDER_BLOCK:
    case FEAT_ISSUER_BLOCK:
      // block type + address
      return sizeof(uint8_t) + address_serialized_len((address_t*)blk->block);
    case FEAT_DUST_DEP_RET_BLOCK:
      // block type + amount
      return sizeof(uint8_t) + sizeof(uint64_t);
    case FEAT_TIMELOCK_MS_INDEX_BLOCK:
    case FEAT_TIMELOCK_UNIX_BLOCK:
    case FEAT_EXPIRATION_MS_INDEX_BLOCK:
    case FEAT_EXPIRATION_UNIX_BLOCK:
      // block type + index
      return sizeof(uint8_t) + sizeof(uint32_t);
    case FEAT_METADATA_BLOCK:
      // block type + data len + data
      return sizeof(uint8_t) + sizeof(uint32_t) + ((feat_metadata_blk_t*)blk->block)->data_len;
    case FEAT_INDEXATION_BLOCK:
      // block type + tag len + tag
      return sizeof(uint8_t) + sizeof(uint8_t) + ((feat_indexaction_blk_t*)blk->block)->tag_len;
    default:
      printf("[%s:%d] unknow featrue block type\n", __func__, __LINE__);
      return 0;
  }
}

int feat_blk_serialize(feat_block_t* blk, byte_t buf[], size_t buf_len) {
  if (!blk || !buf || buf_len == 0) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return -1;
  }

  if (buf_len < feat_blk_serialize_len(blk)) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return -1;
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
    case FEAT_DUST_DEP_RET_BLOCK:
      // serialize amount
      memcpy(buf + sizeof(uint8_t), blk->block, sizeof(uint64_t));
      break;
    case FEAT_TIMELOCK_MS_INDEX_BLOCK:
    case FEAT_TIMELOCK_UNIX_BLOCK:
    case FEAT_EXPIRATION_MS_INDEX_BLOCK:
    case FEAT_EXPIRATION_UNIX_BLOCK:
      // serialize index or time
      memcpy(buf + sizeof(uint8_t), blk->block, sizeof(uint32_t));
      break;
    case FEAT_METADATA_BLOCK:
      // serialize data_len and data
      memcpy(buf + sizeof(uint8_t), &((feat_metadata_blk_t*)blk->block)->data_len, sizeof(uint32_t));
      memcpy(buf + sizeof(uint8_t) + sizeof(uint32_t), ((feat_metadata_blk_t*)blk->block)->data,
             ((feat_metadata_blk_t*)blk->block)->data_len);
      break;
    case FEAT_INDEXATION_BLOCK:
      // serialize tag_len and tag
      memcpy(buf + sizeof(uint8_t), &((feat_indexaction_blk_t*)blk->block)->tag_len, sizeof(uint8_t));
      memcpy(buf + sizeof(uint8_t) + sizeof(uint8_t), ((feat_indexaction_blk_t*)blk->block)->tag,
             ((feat_indexaction_blk_t*)blk->block)->tag_len);
      break;
    default:
      break;
  }
  return 0;
}

feat_block_t* feat_blk_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
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

    case FEAT_DUST_DEP_RET_BLOCK:
      // serialize amount
      if (buf_len < (sizeof(uint8_t) + sizeof(uint64_t))) {
        printf("[%s:%d] invalid data length\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      blk->block = malloc(sizeof(uint64_t));
      if (!blk->block) {
        printf("[%s:%d] new uint64_t failed\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      memcpy(blk->block, buf + sizeof(uint8_t), sizeof(uint64_t));
      break;

    case FEAT_TIMELOCK_MS_INDEX_BLOCK:
    case FEAT_TIMELOCK_UNIX_BLOCK:
    case FEAT_EXPIRATION_MS_INDEX_BLOCK:
    case FEAT_EXPIRATION_UNIX_BLOCK:
      // serialize index or time
      if (buf_len < (sizeof(uint8_t) + sizeof(uint32_t))) {
        printf("[%s:%d] invalid data length\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      blk->block = malloc(sizeof(uint32_t));
      if (!blk->block) {
        printf("[%s:%d] new uint32_t failed\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      memcpy(blk->block, buf + sizeof(uint8_t), sizeof(uint32_t));
      break;
    case FEAT_METADATA_BLOCK: {
      uint32_t offset = sizeof(uint8_t) + sizeof(uint32_t);
      if (buf_len <= offset) {
        printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      blk->block = new_feat_metadata(buf + offset, buf_len - offset);
      if (!blk->block) {
        printf("[%s:%d] deserialize metadata failed\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
    } break;
    case FEAT_INDEXATION_BLOCK: {
      uint32_t offset = sizeof(uint8_t) + sizeof(uint8_t);
      if (buf_len <= offset) {
        printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
        free_feat_blk(blk);
        return NULL;
      }
      blk->block = new_feat_indexaztion(buf + offset, buf_len - offset);
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
    case FEAT_DUST_DEP_RET_BLOCK:
      printf("Dust Deposit Return: %" PRIu64 "\n", *((uint64_t*)blk->block));
      break;
    case FEAT_TIMELOCK_MS_INDEX_BLOCK:
      printf("Timelock Milestone Index: %" PRIu32 "\n", *((uint32_t*)blk->block));
      break;
    case FEAT_TIMELOCK_UNIX_BLOCK:
      printf("Timelock Unix: %" PRIu32 "\n", *((uint32_t*)blk->block));
      break;
    case FEAT_EXPIRATION_MS_INDEX_BLOCK:
      printf("Expiration Milestone Index: %" PRIu32 "\n", *((uint32_t*)blk->block));
      break;
    case FEAT_EXPIRATION_UNIX_BLOCK:
      printf("Expiration Unix: %" PRIu32 "\n", *((uint32_t*)blk->block));
      break;
    case FEAT_METADATA_BLOCK:
      printf("Metadata: ");
      dump_hex_str(((feat_metadata_blk_t*)blk->block)->data, ((feat_metadata_blk_t*)blk->block)->data_len);
      break;
    case FEAT_INDEXATION_BLOCK:
      printf("Indexaction: ");
      dump_hex_str(((feat_indexaction_blk_t*)blk->block)->tag, ((feat_indexaction_blk_t*)blk->block)->tag_len);
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

int feat_blk_list_add_sender(feat_blk_list_t** list, address_t const* const addr) {
  if (!addr) {
    return -1;
  }

  // TODO: make sure the block type is not duplicated in the list.

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
  // TODO: make sure the block type is not duplicated in the list.

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

int feat_blk_list_add_ddr(feat_blk_list_t** list, uint64_t amount) {
  // TODO: make sure the block type is not duplicated in the list.

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_ddr(amount);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feat_blk_list_add_tmi(feat_blk_list_t** list, uint32_t index) {
  // TODO: make sure the block type is not duplicated in the list.

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_tmi(index);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}

int feat_blk_list_add_tu(feat_blk_list_t** list, uint32_t time) {
  // TODO: make sure the block type is not duplicated in the list.

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_tu(time);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}
int feat_blk_list_add_emi(feat_blk_list_t** list, uint32_t index) {
  // TODO: make sure the block type is not duplicated in the list.

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_emi(index);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }

  return -1;
}
int feat_blk_list_add_eu(feat_blk_list_t** list, uint32_t time) {
  // TODO: make sure the block type is not duplicated in the list.

  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_eu(time);
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
  // TODO: make sure the block type is not duplicated in the list.

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

int feat_blk_list_add_indexaction(feat_blk_list_t** list, byte_t const tag[], uint8_t tag_len) {
  // check if list length is reached the limitation
  if (feat_blk_list_len(*list) >= UINT8_MAX - 1) {
    return -1;
  }

  feat_blk_list_t* next = malloc(sizeof(feat_blk_list_t));
  if (next) {
    next->blk = new_feat_blk_indexaction(tag, tag_len);
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

int feat_blk_list_serialize(feat_blk_list_t* list, byte_t buf[], size_t buf_len) {
  // TODO
  return -1;
}

feat_blk_list_t* feat_blk_list_deserialize(byte_t buf[], size_t buf_len) {
  // TODO
  return NULL;
}

void feat_blk_list_print(feat_blk_list_t* list) {
  feat_blk_list_t* elm;
  uint8_t index = 0;
  printf("Feature Blocks:[\n");
  printf("Block Counts: %d\n", feat_blk_list_len(list));
  if (list) {
    LL_FOREACH(list, elm) {
      printf("#%d ", index);
      feat_blk_print(elm->blk);
      index++;
    }
  }
  printf("]\n");
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
