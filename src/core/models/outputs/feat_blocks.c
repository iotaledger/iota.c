// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/feat_blocks.h"

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
