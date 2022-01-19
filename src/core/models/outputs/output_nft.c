// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/address.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"
#include "uthash.h"
#include "utlist.h"

// minimum dust allowance
#define MIN_DUST_ALLOWANCE 1000000

// maximum number of feature blocks
#define MAX_FEATURE_BLOCKS_COUNT 9

output_nft_t* output_nft_new(address_t* addr, uint64_t amount, native_tokens_t* tokens, byte_t nft_id[],
                             byte_t* metadata, uint32_t metadata_len, feat_blk_list_t* feat_blocks) {
  if (addr == NULL || nft_id == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (amount < MIN_DUST_ALLOWANCE) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  if (addr->type == ADDRESS_TYPE_NFT && memcmp(addr->address, nft_id, ADDRESS_NFT_BYTES) == 0) {
    printf("[%s:%d] address must not be the same as the NFT address derived from NFT ID\n", __func__, __LINE__);
    return NULL;
  }

  if (feat_blk_list_len(feat_blocks) > MAX_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d feature blocks\n", __func__, __LINE__, MAX_FEATURE_BLOCKS_COUNT);
    return NULL;
  }

  output_nft_t* output = malloc(sizeof(output_nft_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->address = NULL;
  output->native_tokens = NULL;
  output->immutable_metadata = NULL;
  output->feature_blocks = NULL;

  output->address = address_clone(addr);
  if (!output->address) {
    printf("[%s:%d] can not add address to NFT output\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }

  output->amount = amount;

  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, tokens, token, token_tmp) {
      int res = native_tokens_add(&output->native_tokens, token->token_id, token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to NFT output\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
    }
  }

  memcpy(output->nft_id, nft_id, ADDRESS_NFT_BYTES);

  if (metadata_len > 0 && metadata != NULL) {
    output->immutable_metadata = byte_buf_new_with_data(metadata, metadata_len);
    if (!output->immutable_metadata) {
      printf("[%s:%d] can not add metadata to NFT output\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
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
        case FEAT_ISSUER_BLOCK:
          res = feat_blk_list_add_issuer(&output->feature_blocks, feat->blk->block);
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
          printf("[%s:%d] unsupported feature block type, can not add it to NFT output\n", __func__, __LINE__);
          output_nft_free(output);
          return NULL;
      }
      if (res == -1) {
        printf("[%s:%d] can not add feature block to NFT output\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
    }
  }

  return output;
}

void output_nft_free(output_nft_t* output) {
  if (output) {
    if (output->address) {
      free_address(output->address);
    }
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    if (output->immutable_metadata) {
      byte_buf_free(output->immutable_metadata);
    }
    if (output->feature_blocks) {
      free_feat_blk_list(output->feature_blocks);
    }
    free(output);
  }
}

size_t output_nft_serialize_len(output_nft_t* output) {
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
  // NFT ID
  length += ADDRESS_NFT_BYTES;
  // immutable metadata length
  length += sizeof(uint32_t);
  // immutable metadata
  if (output->immutable_metadata) {
    length += output->immutable_metadata->len;
  }
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);

  return length;
}

size_t output_nft_serialize(output_nft_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_nft_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;

  // fill-in NFT Output type
  memset(offset, OUTPUT_NFT, sizeof(uint8_t));
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

  // NFT ID
  memcpy(offset, output->nft_id, ADDRESS_NFT_BYTES);
  offset += ADDRESS_NFT_BYTES;

  // immutable metadata
  if (output->immutable_metadata) {
    uint32_t metadata_len = output->immutable_metadata->len;
    memcpy(offset, &metadata_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(offset, output->immutable_metadata->data, metadata_len);
    offset += metadata_len;
  } else {
    memset(offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
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

output_nft_t* output_nft_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_nft_t* output = malloc(sizeof(output_nft_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->address = NULL;
  output->native_tokens = NULL;
  output->immutable_metadata = NULL;
  output->feature_blocks = NULL;

  size_t offset = 0;

  // output type
  if (buf[offset] != OUTPUT_NFT) {
    printf("[%s:%d] buffer does not contain NFT Output object\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // address
  output->address = address_deserialize(&buf[offset], buf_len - offset);
  if (!output->address) {
    printf("[%s:%d] can not deserialize address\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  offset += address_serialized_len(output->address);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_nft_free(output);
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
      output_nft_free(output);
      return NULL;
    }
    offset += native_tokens_serialize_len(&output->native_tokens);
  } else {
    offset += sizeof(uint16_t);
  }

  // NFT ID
  if (buf_len < offset + ADDRESS_NFT_BYTES) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  memcpy(&output->nft_id, &buf[offset], ADDRESS_NFT_BYTES);
  offset += ADDRESS_NFT_BYTES;

  // immutable metadata length
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  uint32_t metadata_len;
  memcpy(&metadata_len, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // immutable metadata
  if (metadata_len > 0) {
    if (buf_len < offset + metadata_len) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    output->immutable_metadata = byte_buf_new_with_data(&buf[offset], metadata_len);
    if (!output->immutable_metadata) {
      printf("[%s:%d] can not deserialize metadata\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += metadata_len;
  }

  // feature blocks
  uint8_t feat_block_count = *((uint8_t*)&buf[offset]);
  if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->feature_blocks);
  } else {
    offset += sizeof(uint8_t);
  }

  return output;
}

output_nft_t* output_nft_clone(output_nft_t const* const output) {
  if (output == NULL) {
    return NULL;
  }

  output_nft_t* new_output = malloc(sizeof(output_nft_t));
  if (new_output) {
    new_output->address = address_clone(output->address);
    new_output->amount = output->amount;
    new_output->native_tokens = native_tokens_clone(output->native_tokens);
    memcpy(new_output->nft_id, output->nft_id, ADDRESS_NFT_BYTES);
    new_output->immutable_metadata = byte_buf_clone(output->immutable_metadata);
    new_output->feature_blocks = feat_blk_list_clone(output->feature_blocks);
  }

  return new_output;
}

void output_nft_print(output_nft_t* output, uint8_t indentation) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sNFT Output: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tAddress: ", PRINT_INDENTATION(indentation));
  address_print(output->address);
  printf("%s\tAmount: %" PRIu64 "\n", PRINT_INDENTATION(indentation), output->amount);

  // print native tokens
  native_tokens_print(&output->native_tokens, indentation + 1);

  // print NFT ID
  printf("%s\tNFT ID: ", PRINT_INDENTATION(indentation));
  dump_hex_str(output->nft_id, ADDRESS_NFT_BYTES);

  // print immutable metadata
  printf("%s\tMetadata: ", PRINT_INDENTATION(indentation));
  if (output->immutable_metadata) {
    dump_hex_str(output->immutable_metadata->data, output->immutable_metadata->len);
  } else {
    printf("%s/\n", PRINT_INDENTATION(indentation));
  }

  // print feature blocks
  feat_blk_list_print(output->feature_blocks, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
