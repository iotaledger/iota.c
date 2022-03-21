// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/unlock_block.h"
#include "utlist.h"

// Maximum Unlock Block Count == Maximum Input Count
#define UNLOCK_BLOCKS_MAX_COUNT 128

typedef struct {
  uint8_t index;              ///< Index in which position is pubKeyHash for NFT or Alias input in unlock block
  byte_t id[ALIAS_ID_BYTES];  ///< NFT or Alias identifier
} unlock_block_index_t;

typedef struct unlock_block_list {
  unlock_block_index_t* unlock_block_index;  //< Points to a current unlock block index
  struct unlock_block_list* next;            //< Points to a next unlock block index
} unlock_block_index_list_t;

static void unlock_block_index_list_free(unlock_block_index_list_t* index_list) {
  if (index_list) {
    unlock_block_index_list_t *elm, *tmp;
    LL_FOREACH_SAFE(index_list, elm, tmp) {
      free(elm->unlock_block_index);
      LL_DELETE(index_list, elm);
      free(elm);
    }
  }
}

static int update_unlock_block_index(utxo_input_t* input, byte_t id[], unlock_list_t* unlock_blocks,
                                     unlock_block_index_list_t** unlock_block_index_list) {
  if (input == NULL || id == NULL || unlock_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_index_list_t* new_index = malloc(sizeof(unlock_block_index_list_t));
  if (!new_index) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  new_index->unlock_block_index = malloc(sizeof(unlock_block_index_t));
  if (!new_index->unlock_block_index) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    free(new_index);
    return -1;
  }

  // add new unlock block index into a list
  new_index->unlock_block_index->index = unlock_blocks_find_pub(unlock_blocks, input->keypair->pub);
  memcpy(&new_index->unlock_block_index->id, id, sizeof(new_index->unlock_block_index->id));
  new_index->next = NULL;
  LL_APPEND(*unlock_block_index_list, new_index);

  return 0;
}

static int create_unlock_block_ed25519(byte_t essence_hash[], utxo_input_t* input, utxo_output_t* unspent_output,
                                       unlock_block_index_list_t** unlock_block_index_list,
                                       unlock_list_t** unlock_blocks) {
  if (essence_hash == NULL || input == NULL || unspent_output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int32_t pub_index = unlock_blocks_find_pub(*unlock_blocks, input->keypair->pub);
  if (pub_index == -1) {
    // public key is not found in the unlocked block
    byte_t sig_block[ED25519_SIGNATURE_BLOCK_BYTES] = {};
    sig_block[0] = ADDRESS_TYPE_ED25519;
    memcpy(sig_block + 1, input->keypair->pub, ED_PUBLIC_KEY_BYTES);

    // sign transaction
    if (iota_crypto_sign(input->keypair->priv, essence_hash, CRYPTO_BLAKE2B_HASH_BYTES,
                         sig_block + (1 + ED_PUBLIC_KEY_BYTES)) != 0) {
      printf("[%s:%d] signing signature failed\n", __func__, __LINE__);
      return -1;
    }

    // create a signature unlock block
    if (unlock_blocks_add_signature(unlock_blocks, sig_block, ED25519_SIGNATURE_BLOCK_BYTES) != 0) {
      printf("[%s:%d] add signature block failed\n", __func__, __LINE__);
      return -1;
    }

    // if unspent output is Alias or NFT, save its identifier in unlock block index list
    if (unspent_output->output_type == OUTPUT_ALIAS) {
      output_alias_t* alias = (output_alias_t*)unspent_output->output;
      if (update_unlock_block_index(input, alias->alias_id, *unlock_blocks, unlock_block_index_list) != 0) {
        printf("[%s:%d] can not update unlock block index list\n", __func__, __LINE__);
        return -1;
      }
    } else if (unspent_output->output_type == OUTPUT_NFT) {
      output_nft_t* nft = (output_nft_t*)unspent_output->output;
      if (update_unlock_block_index(input, nft->nft_id, *unlock_blocks, unlock_block_index_list) != 0) {
        printf("[%s:%d] can not update unlock block index list\n", __func__, __LINE__);
        return -1;
      }
    }
  } else {
    // public key is found in the unlocked block, just add a reference
    if (unlock_blocks_add_reference(unlock_blocks, (uint16_t)pub_index) != 0) {
      printf("[%s:%d] add reference block failed\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}

static int create_unlock_block_alias_or_nft(utxo_output_t* unspent_output,
                                            unlock_block_index_list_t* unlock_block_index_list,
                                            unlock_list_t** unlock_blocks) {
  if (unspent_output == NULL || unlock_block_index_list == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  byte_t id[ALIAS_ID_BYTES];
  address_type_t address_type;

  if (unspent_output->output_type == OUTPUT_BASIC) {
    output_basic_t* basic = (output_basic_t*)unspent_output->output;
    unlock_cond_blk_t* unlock_cond = cond_blk_list_get_type(basic->unlock_conditions, UNLOCK_COND_ADDRESS);

    memcpy(id, ((address_t*)unlock_cond->block)->address, sizeof(id));
    address_type = ((address_t*)unlock_cond->block)->type;
  }
  /*else if (unspent_output->output_type == OUTPUT_ALIAS) {
    output_alias_t* alias = (output_alias_t*)unspent_output->output;
    memcpy(id, alias->alias_id, sizeof(id));
    address_type = OUTPUT_ALIAS;
  } else if (unspent_output->output_type == OUTPUT_NFT) {
    output_nft_t* nft = (output_nft_t*)unspent_output->output;
    memcpy(id, nft->nft_id, sizeof(id));
    address_type = OUTPUT_NFT;
  }*/
  else {
    // printf("[%s:%d] unspent output type is not Alias or NFT\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_index_list_t* elm;
  LL_FOREACH(unlock_block_index_list, elm) {
    unlock_block_index_t* unlock_block_index = elm->unlock_block_index;
    if (memcmp(&unlock_block_index->id, id, sizeof(unlock_block_index->id)) == 0) {
      switch (address_type) {
        case ADDRESS_TYPE_ALIAS:
          if (unlock_blocks_add_alias(unlock_blocks, unlock_block_index->index) != 0) {
            printf("[%s:%d] adding Alias unlock block failed\n", __func__, __LINE__);
            return -1;
          }
          return 0;
        case ADDRESS_TYPE_NFT:
          if (unlock_blocks_add_nft(unlock_blocks, unlock_block_index->index) != 0) {
            printf("[%s:%d] adding NFT unlock block failed\n", __func__, __LINE__);
            return -1;
          }
          return 0;
      }
    }
  }

  printf("[%s:%d] Alias or NFT identifier was not found in unlock block index list.\n", __func__, __LINE__);
  return -1;
}

unlock_list_t* unlock_blocks_new() { return NULL; }

unlock_list_t* unlock_blocks_create(byte_t essence_hash[], utxo_inputs_list_t* inputs,
                                    utxo_outputs_list_t* unspent_outputs) {
  if (essence_hash == NULL || inputs == NULL || unspent_outputs == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (utxo_inputs_count(inputs) != utxo_outputs_count(unspent_outputs)) {
    printf("[%s:%d] number of inputs and unspent outputs in a lists are not the same\n", __func__, __LINE__);
    return NULL;
  }

  unlock_list_t* unlock_blocks = unlock_blocks_new();
  unlock_block_index_list_t* unlock_block_index_list = NULL;

  utxo_inputs_list_t* input_elm = NULL;
  uint8_t index = 0;
  LL_FOREACH(inputs, input_elm) {
    utxo_input_t* input = input_elm->input;
    utxo_output_t* unspent_output = utxo_outputs_get(unspent_outputs, index);

    if (input->keypair) {
      if (create_unlock_block_ed25519(essence_hash, input, unspent_output, &unlock_block_index_list, &unlock_blocks) !=
          0) {
        printf("[%s:%d] creating unlock block for ed25519 address failed.\n", __func__, __LINE__);
        unlock_block_index_list_free(unlock_block_index_list);
        unlock_blocks_free(unlock_blocks);
        return NULL;
      }
    } else {
      if (create_unlock_block_alias_or_nft(unspent_output, unlock_block_index_list, &unlock_blocks) != 0) {
        printf("[%s:%d] creating unlock block for Alias or NFT address failed.\n", __func__, __LINE__);
        unlock_block_index_list_free(unlock_block_index_list);
        unlock_blocks_free(unlock_blocks);
        return NULL;
      }
    }

    index += 1;
  }

  unlock_block_index_list_free(unlock_block_index_list);

  return unlock_blocks;
}

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
    if (*((uint16_t*)block->block_data) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
    //  Unlock block at index must be a signature unlock block
    unlock_list_t* elm = *blocks;
    uint16_t index = 0;
    while (index < *((uint16_t*)block->block_data)) {
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
    if (*((uint16_t*)block->block_data) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
  } else if (block->type == UNLOCK_BLOCK_TYPE_NFT) {
    uint16_t count = unlock_blocks_count(*blocks);
    // NFT unlock block at index i must have index < i
    if (*((uint16_t*)block->block_data) >= count) {
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
  // Reference Index must be 0 <= x < 128.
  if (index >= UNLOCK_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] invalid Reference Index\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_REFERENCE;  // Reference unlock block
  b.block_data = malloc(sizeof(uint16_t));
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate reference block failed\n", __func__, __LINE__);
    return -1;
  }

  *(uint16_t*)b.block_data = index;

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

int unlock_blocks_add_alias(unlock_list_t** blocks, uint16_t index) {
  // Alias Reference Index must be 0 <= x < 128.
  if (index >= UNLOCK_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_ALIAS;  // Alias unlock block
  b.block_data = malloc(sizeof(uint16_t));
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate alias block failed\n", __func__, __LINE__);
    return -1;
  }

  *(uint16_t*)b.block_data = index;

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

int unlock_blocks_add_nft(unlock_list_t** blocks, uint16_t index) {
  // NFT Reference Index must be 0 <= x < 128.
  if (index >= UNLOCK_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_block_t b;
  b.type = UNLOCK_BLOCK_TYPE_NFT;  // NFT unlock block
  b.block_data = malloc(sizeof(uint16_t));
  if (b.block_data == NULL) {
    printf("[%s:%d] allocate NFT block failed\n", __func__, __LINE__);
    return -1;
  }

  *(uint16_t*)b.block_data = index;

  if (unlock_blocks_add(blocks, &b) == -1) {
    free(b.block_data);
    return -1;
  }
  return 0;
}

size_t unlock_blocks_serialize_length(unlock_list_t* blocks) {
  unlock_list_t* elm = NULL;
  size_t serialized_size = 0;

  // empty unlock blocks
  if (blocks == NULL) {
    return 0;
  }

  // bytes of Unlock Blocks Count
  serialized_size += sizeof(uint16_t);
  // calculate serialized bytes of unlock blocks
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
      printf("[%s:%d] Unknown unlock block type\n", __func__, __LINE__);
      return 0;
    }
  }
  return serialized_size;
}

size_t unlock_blocks_serialize(unlock_list_t* blocks, byte_t buf[]) {
  unlock_list_t* elm = NULL;
  byte_t* offset = buf;

  uint16_t block_count = unlock_blocks_count(blocks);

  // unlock block count
  memcpy(offset, &block_count, sizeof(block_count));
  offset += sizeof(block_count);

  // serializing unlock blocks
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
      memcpy(offset, elm->block.block_data, sizeof(uint16_t));
      offset += sizeof(uint16_t);
    }
  }

  return (offset - buf) / sizeof(byte_t);
}

unlock_list_t* unlock_blocks_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len < 2) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_list_t* blocks = unlock_blocks_new();

  uint16_t blocks_count;
  memcpy(&blocks_count, &buf[0], sizeof(blocks_count));
  size_t offset = sizeof(uint16_t);

  if (blocks_count == 0) {
    return blocks;
  }

  for (uint16_t i = 0; i < blocks_count; i++) {
    // unlock block type
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      unlock_blocks_free(blocks);
      return NULL;
    }
    uint8_t block_type;
    memcpy(&block_type, &buf[offset], sizeof(uint8_t));
    offset += sizeof(uint8_t);

    switch (block_type) {
      case UNLOCK_BLOCK_TYPE_SIGNATURE: {
        // ed25519 signature
        if (buf_len < offset + ED25519_SIGNATURE_BLOCK_BYTES) {
          printf("[%s:%d] invalid data length\n", __func__, __LINE__);
          unlock_blocks_free(blocks);
          return NULL;
        }
        byte_t signature_block[ED25519_SIGNATURE_BLOCK_BYTES];
        memcpy(signature_block, &buf[offset], sizeof(signature_block));
        offset += sizeof(signature_block);

        if (unlock_blocks_add_signature(&blocks, signature_block, sizeof(signature_block)) != 0) {
          printf("[%s:%d] can not add unlock block to the list\n", __func__, __LINE__);
          unlock_blocks_free(blocks);
          return NULL;
        }
        break;
      }
      case UNLOCK_BLOCK_TYPE_REFERENCE:
      case UNLOCK_BLOCK_TYPE_ALIAS:
      case UNLOCK_BLOCK_TYPE_NFT: {
        // index
        if (buf_len < offset + sizeof(uint16_t)) {
          printf("[%s:%d] invalid data length\n", __func__, __LINE__);
          unlock_blocks_free(blocks);
          return NULL;
        }
        uint16_t index;
        memcpy(&index, &buf[offset], sizeof(uint16_t));
        offset += sizeof(uint16_t);

        int result = -1;
        if (block_type == UNLOCK_BLOCK_TYPE_REFERENCE) {
          result = unlock_blocks_add_reference(&blocks, index);
        } else if (block_type == UNLOCK_BLOCK_TYPE_ALIAS) {
          result = unlock_blocks_add_alias(&blocks, index);
        } else if (block_type == UNLOCK_BLOCK_TYPE_NFT) {
          result = unlock_blocks_add_nft(&blocks, index);
        }
        if (result != 0) {
          printf("[%s:%d] can not add unlock block to the list\n", __func__, __LINE__);
          unlock_blocks_free(blocks);
          return NULL;
        }
        break;
      }
      default:
        printf("[%s:%d] unknown unlock block type\n", __func__, __LINE__);
        unlock_blocks_free(blocks);
        return NULL;
    }
  }

  return blocks;
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

void unlock_blocks_print(unlock_list_t* blocks, uint8_t indentation) {
  unlock_list_t* elm;
  if (blocks) {
    printf("%sUnlock Blocks: [\n", PRINT_INDENTATION(indentation));
    LL_FOREACH(blocks, elm) {
      if (elm->block.type == UNLOCK_BLOCK_TYPE_SIGNATURE) {  // signature block
        printf("%s\tSignature Block: [\n", PRINT_INDENTATION(indentation));
        printf("%s\t\tType: %s\n", PRINT_INDENTATION(indentation),
               ((byte_t*)elm->block.block_data)[0] ? "UNKNOWN" : "ED25519");
        printf("%s\t\tPub key: ", PRINT_INDENTATION(indentation));
        dump_hex_str(elm->block.block_data + 1, ED_PUBLIC_KEY_BYTES);
        printf("%s\t\tSignature: ", PRINT_INDENTATION(indentation));
        dump_hex_str(elm->block.block_data + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES);
        printf("%s\t]\n", PRINT_INDENTATION(indentation));
      } else if (elm->block.type == UNLOCK_BLOCK_TYPE_REFERENCE) {  // reference block
        printf("%s\tReference block[ ", PRINT_INDENTATION(indentation));
        printf("Ref: %" PRIu16 " ]\n", *(uint16_t*)elm->block.block_data);
      } else if (elm->block.type == UNLOCK_BLOCK_TYPE_ALIAS) {  // alias block
        printf("%s\tAlias block[ ", PRINT_INDENTATION(indentation));
        printf("Ref: %" PRIu16 " ]\n", *(uint16_t*)elm->block.block_data);
      } else if (elm->block.type == UNLOCK_BLOCK_TYPE_NFT) {  // NFT block
        printf("%s\tNFT block[ ", PRINT_INDENTATION(indentation));
        printf("Ref: %" PRIu16 " ]\n", *(uint16_t*)elm->block.block_data);
      } else {
        printf("[%s:%d] Unknown unlock block type\n", __func__, __LINE__);
      }
    }
    printf("%s]\n", PRINT_INDENTATION(indentation));
  }
}
