// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/address.h"
#include "core/models/outputs/output_extended.h"
#include "core/models/outputs/outputs.h"
#include "core/types.h"
#include "uthash.h"
#include "utlist.h"

// minimum dust allowance
#define MIN_DUST_ALLOWANCE 1000000

// maximum number of feature blocks
#define MAX_FEATURE_BLOCKS_COUNT 8

output_extended_t* output_extended_new(address_t* addr, uint64_t amount, native_tokens_t* tokens,
                                       feat_blk_list_t* feat_blocks) {
  if (addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (amount < MIN_DUST_ALLOWANCE) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  if (feat_blk_list_len(feat_blocks) > MAX_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d feature blocks\n", __func__, __LINE__, MAX_FEATURE_BLOCKS_COUNT);
    return NULL;
  }

  output_extended_t* output = malloc(sizeof(output_extended_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->address = NULL;
  output->native_tokens = NULL;
  output->feature_blocks = NULL;

  output->address = address_clone(addr);
  if (!output->address) {
    printf("[%s:%d] can not add address to extended output\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }

  output->amount = amount;

  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, tokens, token, token_tmp) {
      int res = native_tokens_add(&output->native_tokens, token->token_id, token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to extended output\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
    }
  }

  if (feat_blocks != NULL) {
    output->feature_blocks = new_feat_blk_list();
    feat_blk_list_t* feat;
    int res;
    LL_FOREACH(feat_blocks, feat) {
      switch (feat->blk->type) {
        case FEAT_SENDER_BLOCK:
          res = feat_blk_list_add_sender(&output->feature_blocks, feat->blk->block);
          break;
        case FEAT_METADATA_BLOCK: {
          feat_metadata_blk_t* block_metadata = (feat_metadata_blk_t*)feat->blk->block;
          res = feat_blk_list_add_metadata(&output->feature_blocks, block_metadata->data, block_metadata->data_len);
          break;
        }
        case FEAT_TAG_BLOCK: {
          feat_tag_blk_t* indexation = (feat_tag_blk_t*)feat->blk->block;
          res = feat_blk_list_add_tag(&output->feature_blocks, indexation->tag, indexation->tag_len);
          break;
        }
        default:
          printf("[%s:%d] unsupported feature block type, can not add it to extended output\n", __func__, __LINE__);
          output_extended_free(output);
          return NULL;
      }
      if (res == -1) {
        printf("[%s:%d] can not add feature block to extended output\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
    }
  }

  return output;
}

void output_extended_free(output_extended_t* output) {
  if (output) {
    if (output->address) {
      free_address(output->address);
    }
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    if (output->feature_blocks) {
      free_feat_blk_list(output->feature_blocks);
    }
    free(output);
  }
}

size_t output_extended_serialize_len(output_extended_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // output type
  length += sizeof(uint8_t);
  // address
  length += address_serialized_len(output->address);
  // amount
  length += sizeof(uint64_t);
  // native tokens
  length += native_tokens_serialize_len(&output->native_tokens);
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);

  return length;
}

size_t output_extended_serialize(output_extended_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_extended_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;

  // fill-in Extended Output type
  memset(offset, OUTPUT_EXTENDED, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // address
  offset += address_serialize(output->address, offset, address_serialized_len(output->address));

  // amount
  memcpy(offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  if (output->native_tokens) {
    offset +=
        native_tokens_serialize(&output->native_tokens, offset, native_tokens_serialize_len(&output->native_tokens));
  } else {
    memset(offset, 0, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  // feature blocks
  if (output->feature_blocks) {
    offset +=
        feat_blk_list_serialize(output->feature_blocks, offset, feat_blk_list_serialize_len(output->feature_blocks));
  } else {
    memset(offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  return expected_bytes;
}

output_extended_t* output_extended_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_extended_t* output = malloc(sizeof(output_extended_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->address = NULL;
  output->native_tokens = NULL;
  output->feature_blocks = NULL;

  size_t offset = 0;

  // output type
  if (buf[offset] != OUTPUT_EXTENDED) {
    printf("[%s:%d] buffer does not contain Extended Output object\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // address
  output->address = address_deserialize(&buf[offset], buf_len - offset);
  if (!output->address) {
    printf("[%s:%d] can not deserialize address\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  offset += address_serialized_len(output->address);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  memcpy(&output->amount, &buf[offset], sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  uint16_t tokens_count = 0;
  memcpy(&tokens_count, &buf[offset], sizeof(uint16_t));
  if (tokens_count > 0) {
    output->native_tokens = native_tokens_deserialize(&buf[offset], buf_len - offset);
    if (!output->native_tokens) {
      printf("[%s:%d] can not deserialize native tokens\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
    }
    offset += native_tokens_serialize_len(&output->native_tokens);
  } else {
    offset += sizeof(uint16_t);
  }

  // feature blocks
  uint8_t feat_block_count = *((uint8_t*)&buf[offset]);
  if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->feature_blocks);
  } else {
    offset += sizeof(uint8_t);
  }

  return output;
}

output_extended_t* output_extended_clone(output_extended_t const* const output) {
  if (output == NULL) {
    return NULL;
  }

  output_extended_t* new_output = malloc(sizeof(output_extended_t));
  if (new_output) {
    new_output->address = address_clone(output->address);
    new_output->amount = output->amount;
    new_output->native_tokens = native_tokens_clone(output->native_tokens);
    new_output->feature_blocks = feat_blk_list_clone(output->feature_blocks);
  }

  return new_output;
}

void output_extended_print(output_extended_t* output, uint8_t indentation) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sExtended Output: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tAddress: ", PRINT_INDENTATION(indentation));
  address_print(output->address);
  printf("%s\tAmount: %" PRIu64 "\n", PRINT_INDENTATION(indentation), output->amount);

  // print native tokens
  native_tokens_print(&output->native_tokens, indentation + 1);

  // print feature blocks
  feat_blk_list_print(output->feature_blocks, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
