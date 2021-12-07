// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utlist.h"

#include "core/models/unlock_block.h"

#define UNLOCKED_BLOCKS_MAX_COUNT 126

unlock_blocks_t* unlock_blocks_new() { return NULL; }

int unlock_blocks_add_signature(unlock_blocks_t** blocks, byte_t* sig, size_t sig_len) {
  if (sig == NULL || sig_len != ED25519_SIGNATURE_BLOCK_BYTES) {
    printf("[%s:%d] invalid signature\n", __func__, __LINE__);
    return -1;
  }
  unlock_blocks_t* b = malloc(sizeof(unlock_blocks_t));
  if (b == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  b->type = 0;  // signature block
  b->reference = 0;
  b->sig_block = malloc(ED25519_SIGNATURE_BLOCK_BYTES);
  if (b->sig_block) {
    memcpy(b->sig_block, sig, ED25519_SIGNATURE_BLOCK_BYTES);
    LL_APPEND(*blocks, b);
    return 0;
  }

  printf("[%s:%d] allocate signature block failed\n", __func__, __LINE__);
  free(b);
  return -1;
}

int unlock_blocks_add_reference(unlock_blocks_t** blocks, uint16_t ref) {
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (ref > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] reference out of range \n", __func__, __LINE__);
    return -1;
  }

  // TODO checking if the reference index points to a valid signature block

  unlock_blocks_t* b = malloc(sizeof(unlock_blocks_t));
  if (b == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  b->type = 1;  // reference block
  b->reference = ref;
  b->sig_block = NULL;
  LL_APPEND(*blocks, b);
  return 0;
}

int unlock_blocks_add_alias(unlock_blocks_t** blocks, uint16_t ref) {
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (ref > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] alias out of range \n", __func__, __LINE__);
    return -1;
  }

  // TODO checking if the alias block index points to a valid signature block

  unlock_blocks_t* b = malloc(sizeof(unlock_blocks_t));
  if (b == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  b->type = 2;  // alias block
  b->reference = ref;
  b->sig_block = NULL;
  LL_APPEND(*blocks, b);
  return 0;
}

int unlock_blocks_add_nft(unlock_blocks_t** blocks, uint16_t ref) {
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (ref > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] NFT out of range \n", __func__, __LINE__);
    return -1;
  }

  // TODO checking if the NFT block index points to a valid signature block

  unlock_blocks_t* b = malloc(sizeof(unlock_blocks_t));
  if (b == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  b->type = 3;  // NFT block
  b->reference = ref;
  b->sig_block = NULL;
  LL_APPEND(*blocks, b);
  return 0;
}

size_t unlock_blocks_serialize_length(unlock_blocks_t* blocks) {
  unlock_blocks_t* elm = NULL;
  size_t serialized_size = 0;

  // empty unlocked blocks
  if (blocks == NULL) {
    return 0;
  }

  // bytes of Unlock Blocks Count
  serialized_size += sizeof(uint16_t);
  // calculate serialized bytes of unlocked blocks
  LL_FOREACH(blocks, elm) {
    if (elm->type == 0) {
      serialized_size += UNLOCK_SIGNATURE_SERIALIZE_BYTES;
    } else if (elm->type == 1) {
      serialized_size += UNLOCK_REFERENCE_SERIALIZE_BYTES;
    } else if (elm->type == 2) {
      serialized_size += UNLOCK_ALIAS_SERIALIZE_BYTES;
    } else if (elm->type == 3) {
      serialized_size += UNLOCK_NFT_SERIALIZE_BYTES;
    } else {
      printf("[%s:%d] Unkown unlocked block type\n", __func__, __LINE__);
      return 0;
    }
  }
  return serialized_size;
}

size_t unlock_blocks_serialize(unlock_blocks_t* blocks, byte_t buf[]) {
  unlock_blocks_t* elm = NULL;
  byte_t* offset = buf;

  uint16_t block_count = unlock_blocks_count(blocks);

  // unlocked block count
  memcpy(offset, &block_count, sizeof(block_count));
  offset += sizeof(block_count);

  // serializing unlocked blocks
  LL_FOREACH(blocks, elm) {
    if (elm->type == 0) {  // signature block
      memcpy(offset, &elm->type, sizeof(elm->type));
      offset += sizeof(elm->type);
      memcpy(offset, elm->sig_block, ED25519_SIGNATURE_BLOCK_BYTES);
      offset += ED25519_SIGNATURE_BLOCK_BYTES;
    } else if (elm->type == 1) {  // reference block
      memcpy(offset, &elm->type, sizeof(elm->type));
      offset += sizeof(elm->type);
      memcpy(offset, &elm->reference, sizeof(elm->reference));
      offset += sizeof(elm->reference);
    } else if (elm->type == 2) {  // alias block
      memcpy(offset, &elm->type, sizeof(elm->type));
      offset += sizeof(elm->type);
      memcpy(offset, &elm->reference, sizeof(elm->reference));
      offset += sizeof(elm->reference);
    } else if (elm->type == 3) {  // NFT block
      memcpy(offset, &elm->type, sizeof(elm->type));
      offset += sizeof(elm->type);
      memcpy(offset, &elm->reference, sizeof(elm->reference));
      offset += sizeof(elm->reference);
    }
  }

  return (offset - buf) / sizeof(byte_t);
}

uint16_t unlock_blocks_count(unlock_blocks_t* blocks) {
  unlock_blocks_t* elm = NULL;
  uint16_t count = 0;
  if (blocks) {
    LL_COUNT(blocks, elm, count);
  }
  return count;
}

int32_t unlock_blocks_find_pub(unlock_blocks_t* blocks, byte_t const* const pub_key) {
  unlock_blocks_t* elm;
  int32_t count = 0;
  if (blocks) {
    LL_FOREACH(blocks, elm) {
      if (elm->type == 0) {
        if (memcmp(elm->sig_block + 1, pub_key, ED_PUBLIC_KEY_BYTES) == 0) {
          return count;
        }
      }
      count++;
    }
  }
  return -1;
}

void unlock_blocks_free(unlock_blocks_t* blocks) {
  unlock_blocks_t *elm, *tmp;
  if (blocks) {
    LL_FOREACH_SAFE(blocks, elm, tmp) {
      if (elm->sig_block) {
        free(elm->sig_block);
      }
      LL_DELETE(blocks, elm);
      free(elm);
    }
  }
}

void unlock_blocks_print(unlock_blocks_t* blocks) {
  unlock_blocks_t* elm;
  if (blocks) {
    printf("unlocked blocks[\n");
    LL_FOREACH(blocks, elm) {
      if (elm->type == 0) {  // signature block
        printf("\tSignautre block[ ");
        printf("Type: %s\n", (byte_t)elm->sig_block[0] ? "UNKNOW" : "ED25519");
        printf("\tPub key: ");
        dump_hex(elm->sig_block + 1, ED_PUBLIC_KEY_BYTES);
        printf("\tSignature: ");
        dump_hex(elm->sig_block + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES);
        printf("\t]\n");
      } else if (elm->type == 1) {  // reference block
        printf("\tReference block[ ");
        printf("ref: %" PRIu16 " ]\n", elm->reference);
      } else if (elm->type == 2) {  // alias block
        printf("\tAlias block[ ");
        printf("ref: %" PRIu16 " ]\n", elm->reference);
      } else if (elm->type == 3) {  // NFT block
        printf("\tNFT block[ ");
        printf("ref: %" PRIu16 " ]\n", elm->reference);
      } else {
        printf("[%s:%d] Unkown unlocked block type\n", __func__, __LINE__);
        // return 0;
      }
    }
    printf("]\n");
  }
}
