// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utlist.h"

#include "core/models/unlock_block.h"

#define UNLOCKED_BLOCKS_MAX_COUNT 126

unlock_list_t* unlock_blocks_new() { return NULL; }

int unlock_blocks_add(unlock_list_t** blocks, unlock_block_t* block) {
  if (block->type == UNLOCK_BLOCK_TYPE_SIGNATURE) {
    // Signature unlock block must be unique. There must not be any other signature unlock blocks in unlock block
    // list with the same signature.
    unlock_list_t* elm = NULL;
    LL_FOREACH(*blocks, elm) {
      if (elm->block.type == UNLOCK_BLOCK_TYPE_SIGNATURE) {
        if (memcmp(block->block_data, elm->block.block_data, sizeof(ED25519_SIGNATURE_BLOCK_BYTES)) == 0) {
          printf("[%s:%d] duplicated signature\n", __func__, __LINE__);
          return -1;
        }
      }
    }
  } else if (block->type == UNLOCK_BLOCK_TYPE_REFERENCE) {
    uint16_t count = unlock_blocks_count(*blocks);
    // Reference unlock block at index i must have index < i
    if (*((unlock_index_t*)block->block_data) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
    //  Unlock block at index must be a signature unlock block
    unlock_list_t* elm = *blocks;
    uint16_t index = 0;
    while (index < *((unlock_index_t*)block->block_data)) {
      elm = elm->next;
      index++;
    }
    if (elm->block.type != UNLOCK_BLOCK_TYPE_SIGNATURE) {
      printf("[%s:%d] unlock block must be signature\n", __func__, __LINE__);
      return -1;
    }
  } else if (block->type == UNLOCK_BLOCK_TYPE_ALIAS) {
    uint16_t count = unlock_blocks_count(*blocks);
    // Alias unlock block at index i must have index < i
    if (*((unlock_index_t*)block->block_data) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
  } else if (block->type == UNLOCK_BLOCK_TYPE_NFT) {
    uint16_t count = unlock_blocks_count(*blocks);
    // NFT unlock block at index i must have index < i
    if (*((unlock_index_t*)block->block_data) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
  }

  unlock_list_t* b = malloc(sizeof(unlock_list_t));
  if (b == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  memcpy(&b->block, block, sizeof(unlock_block_t));
  b->next = NULL;

  LL_APPEND(*blocks, b);
  return 0;
}

int unlock_blocks_add_signature(unlock_list_t** blocks, byte_t* sig, size_t sig_len) {
  if (sig == NULL || sig_len != ED25519_SIGNATURE_BLOCK_BYTES) {
    printf("[%s:%d] invalid signature\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_SIGNATURE;  // Signature unlock block
  b.block_data = malloc(ED25519_SIGNATURE_BLOCK_BYTES);
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate signature block failed\n", __func__, __LINE__);
    return -1;
  }

  memcpy(b.block_data, sig, ED25519_SIGNATURE_BLOCK_BYTES);

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

int unlock_blocks_add_reference(unlock_list_t** blocks, uint16_t index) {
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (index > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_REFERENCE;  // Reference unlock block
  b.block_data = malloc(sizeof(unlock_index_t));
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate reference block failed\n", __func__, __LINE__);
    return -1;
  }

  *(unlock_index_t*)b.block_data = index;

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

int unlock_blocks_add_alias(unlock_list_t** blocks, uint16_t index) {
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (index > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_ALIAS;  // Alias unlock block
  b.block_data = malloc(sizeof(unlock_index_t));
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate alias block failed\n", __func__, __LINE__);
    return -1;
  }

  *(unlock_index_t*)b.block_data = index;

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

int unlock_blocks_add_nft(unlock_list_t** blocks, uint16_t index) {
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (index > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_NFT;  // NFT unlock block
  b.block_data = malloc(sizeof(unlock_index_t));
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate NFT block failed\n", __func__, __LINE__);
    return -1;
  }

  *(unlock_index_t*)b.block_data = index;

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

size_t unlock_blocks_serialize_length(unlock_list_t* blocks) {
  unlock_list_t* elm = NULL;
  size_t serialized_size = 0;

  // empty unlocked blocks
  if (blocks == NULL) {
    return 0;
  }

  // bytes of Unlock Blocks Count
  serialized_size += sizeof(uint16_t);
  // calculate serialized bytes of unlocked blocks
  LL_FOREACH(blocks, elm) {
    if (elm->block.type == UNLOCK_BLOCK_TYPE_SIGNATURE) {
      serialized_size += UNLOCK_SIGNATURE_SERIALIZE_BYTES;
    } else if (elm->block.type == UNLOCK_BLOCK_TYPE_REFERENCE) {
      serialized_size += UNLOCK_REFERENCE_SERIALIZE_BYTES;
    } else if (elm->block.type == UNLOCK_BLOCK_TYPE_ALIAS) {
      serialized_size += UNLOCK_ALIAS_SERIALIZE_BYTES;
    } else if (elm->block.type == UNLOCK_BLOCK_TYPE_NFT) {
      serialized_size += UNLOCK_NFT_SERIALIZE_BYTES;
    } else {
      printf("[%s:%d] Unknown unlocked block type\n", __func__, __LINE__);
      return 0;
    }
  }
  return serialized_size;
}

size_t unlock_blocks_serialize(unlock_list_t* blocks, byte_t buf[]) {
  unlock_list_t* elm = NULL;
  byte_t* offset = buf;

  uint16_t block_count = unlock_blocks_count(blocks);

  // unlocked block count
  memcpy(offset, &block_count, sizeof(block_count));
  offset += sizeof(block_count);

  // serializing unlocked blocks
  LL_FOREACH(blocks, elm) {
    if (elm->block.type == UNLOCK_BLOCK_TYPE_SIGNATURE) {  // signature block
      memcpy(offset, &elm->block.type, sizeof(byte_t));
      offset += sizeof(byte_t);
      memcpy(offset, elm->block.block_data, ED25519_SIGNATURE_BLOCK_BYTES);
      offset += ED25519_SIGNATURE_BLOCK_BYTES;
    } else if ((elm->block.type == UNLOCK_BLOCK_TYPE_REFERENCE) || (elm->block.type == UNLOCK_BLOCK_TYPE_ALIAS) ||
               (elm->block.type == UNLOCK_BLOCK_TYPE_NFT)) {  // reference, alias or NFT unlock block
      memcpy(offset, &elm->block.type, sizeof(byte_t));
      offset += sizeof(byte_t);
      memcpy(offset, elm->block.block_data, sizeof(unlock_index_t));
      offset += sizeof(unlock_index_t);
    }
  }

  return (offset - buf) / sizeof(byte_t);
}

unlock_block_t* unlock_blocks_get(unlock_list_t* blocks, uint16_t index) {
  if (!blocks) {
    return NULL;
  }
  uint16_t count = 0;
  unlock_list_t* elm;
  LL_FOREACH(blocks, elm) {
    if (count == index) {
      return &elm->block;
    }
    count++;
  }
  return NULL;
}

uint16_t unlock_blocks_count(unlock_list_t* blocks) {
  unlock_list_t* elm = NULL;
  uint16_t count = 0;
  if (blocks) {
    LL_COUNT(blocks, elm, count);
  }
  return count;
}

int32_t unlock_blocks_find_pub(unlock_list_t* blocks, byte_t const* const pub_key) {
  unlock_list_t* elm;
  int32_t count = 0;
  if (blocks) {
    LL_FOREACH(blocks, elm) {
      if (elm->block.type == UNLOCK_BLOCK_TYPE_SIGNATURE) {
        if (memcmp((byte_t*)elm->block.block_data + 1, pub_key, ED_PUBLIC_KEY_BYTES) == 0) {
          return count;
        }
      }
      count++;
    }
  }
  return -1;
}

void unlock_blocks_free(unlock_list_t* blocks) {
  unlock_list_t *elm, *tmp;
  if (blocks) {
    LL_FOREACH_SAFE(blocks, elm, tmp) {
      if (elm->block.block_data) {
        free(elm->block.block_data);
      }
      LL_DELETE(blocks, elm);
      free(elm);
    }
  }
}

void unlock_blocks_print(unlock_list_t* blocks) {
  unlock_list_t* elm;
  if (blocks) {
    printf("unlocked blocks[\n");
    LL_FOREACH(blocks, elm) {
      if (elm->block.type == UNLOCK_BLOCK_TYPE_SIGNATURE) {  // signature block
        printf("\tSignature block[ ");
        printf("Type: %s\n", ((byte_t*)elm->block.block_data)[0] ? "UNKNOWN" : "ED25519");
        printf("\tPub key: ");
        dump_hex(elm->block.block_data + 1, ED_PUBLIC_KEY_BYTES);
        printf("\tSignature: ");
        dump_hex(elm->block.block_data + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES);
        printf("\t]\n");
      } else if (elm->block.type == UNLOCK_BLOCK_TYPE_REFERENCE) {  // reference block
        printf("\tReference block[ ");
        printf("ref: %" PRIu16 " ]\n", *(unlock_index_t*)elm->block.block_data);
      } else if (elm->block.type == UNLOCK_BLOCK_TYPE_ALIAS) {  // alias block
        printf("\tAlias block[ ");
        printf("ref: %" PRIu16 " ]\n", *(unlock_index_t*)elm->block.block_data);
      } else if (elm->block.type == UNLOCK_BLOCK_TYPE_NFT) {  // NFT block
        printf("\tNFT block[ ");
        printf("ref: %" PRIu16 " ]\n", *(unlock_index_t*)elm->block.block_data);
      } else {
        printf("[%s:%d] Unknown unlocked block type\n", __func__, __LINE__);
        // return 0;
      }
    }
    printf("]\n");
  }
}
