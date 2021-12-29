// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/outputs.h"
#include "uthash.h"
#include "utlist.h"

#define MIN_DUST_ALLOWANCE 1000000

output_foundry_t* output_foundry_new(address_t* addr, uint64_t amount, native_tokens_t* tokens, uint32_t serial_num,
                                     byte_t token_tag[], uint256_t* circ_supply, uint256_t* max_supply,
                                     token_scheme_e token_scheme, feat_blk_list_t* feat_blocks) {
  if (addr == NULL || circ_supply == NULL || max_supply == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  uint256_t* max_supply_check = uint256_from_str("0");
  if (!max_supply_check) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  if (!uint256_equal(max_supply, max_supply_check)) {
    printf("[%s:%d] maximum supply cannot be 0\n", __func__, __LINE__);
    free(max_supply_check);
    return NULL;
  }

  free(max_supply_check);

  if (amount < MIN_DUST_ALLOWANCE) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  if (uint256_equal(circ_supply, max_supply) > 0) {
    printf("[%s:%d] circulating supply must not be greater than maximum supply\n", __func__, __LINE__);
    return NULL;
  }

  // Currently only SIMPLE_TOKEN_SCHEME is supported
  if (token_scheme != SIMPLE_TOKEN_SCHEME) {
    printf("[%s:%d] token scheme not supported\n", __func__, __LINE__);
    return NULL;
  }

  // Allocate foundry output object
  output_foundry_t* output = malloc(sizeof(output_foundry_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  output->address = NULL;
  output->native_tokens = NULL;
  output->circ_supply = NULL;
  output->max_supply = NULL;
  output->feature_blocks = NULL;

  // Store address
  output->address = address_clone(addr);
  if (!output->address) {
    printf("[%s:%d] can not add address to foundry output\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }

  // Store amount
  output->amount = amount;

  // Store native tokens
  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, tokens, token, token_tmp) {
      int res = native_tokens_add(&output->native_tokens, token->token_id, token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to foundry output\n", __func__, __LINE__);
        output_foundry_free(output);
        return NULL;
      }
    }
  }

  // Store serial number
  output->serial = serial_num;

  // Copy token tag, 12 bytes
  memcpy(output->token_tag, token_tag, TOKEN_TAG_BYTES_LEN);

  // Store ciruclating supply of tokens
  output->circ_supply = malloc(sizeof(uint256_t));
  memcpy(output->circ_supply, circ_supply, sizeof(uint256_t));

  // Store maximum supply of tokens
  output->max_supply = malloc(sizeof(uint256_t));
  memcpy(output->max_supply, max_supply, sizeof(uint256_t));

  // Store token scheme
  output->token_scheme = token_scheme;

  // Store feature blocks
  if (feat_blocks != NULL) {
    output->feature_blocks = new_feat_blk_list();
    feat_blk_list_t* feat;
    int res;
    LL_FOREACH(feat_blocks, feat) {
      if (feat->blk->type == FEAT_METADATA_BLOCK) {
        feat_metadata_blk_t* block_metadata = (feat_metadata_blk_t*)feat->blk->block;
        res = feat_blk_list_add_metadata(&output->feature_blocks, block_metadata->data, block_metadata->data_len);
        if (res == -1) {
          printf("[%s:%d] can not add feature block to Foundry output\n", __func__, __LINE__);
          output_foundry_free(output);
          return NULL;
        }
      } else {
        printf("[%s:%d] unsupported feature block type, can not add it to Foundry output\n", __func__, __LINE__);
        output_foundry_free(output);
        return NULL;
      }
    }
  }
  return output;
}

void output_foundry_free(output_foundry_t* output) {
  if (output) {
    if (output->address) {
      free_address(output->address);
    }
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    if (output->circ_supply) {
      free(output->circ_supply);
    }
    if (output->max_supply) {
      free(output->max_supply);
    }
    if (output->feature_blocks) {
      free_feat_blk_list(output->feature_blocks);
    }
    free(output);
  }
}

size_t output_foundry_serialize_len(output_foundry_t* output) {
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
  // serial number
  length += sizeof(uint32_t);
  // token tag
  length += TOKEN_TAG_BYTES_LEN;
  // circulating supply
  length += sizeof(uint256_t);
  // maximum supply
  length += sizeof(uint256_t);
  // token_scheme
  length += sizeof(uint8_t);
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);

  return length;
}

size_t output_foundry_serialize(output_foundry_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_foundry_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;

  // fill-in Foundry Output type
  memset(offset, OUTPUT_FOUNDRY, sizeof(uint8_t));
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

  // serial number
  memcpy(offset, &output->serial, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // token tag
  memcpy(offset, output->token_tag, TOKEN_TAG_BYTES_LEN);
  offset += TOKEN_TAG_BYTES_LEN;

  // circulating supply
  memcpy(offset, output->circ_supply, sizeof(uint256_t));
  offset += sizeof(uint256_t);

  // maximum supply
  memcpy(offset, output->max_supply, sizeof(uint256_t));
  offset += sizeof(uint256_t);

  // token scheme
  memcpy(offset, &output->token_scheme, sizeof(uint8_t));
  offset += sizeof(uint8_t);

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

output_foundry_t* output_foundry_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  output_foundry_t* output = malloc(sizeof(output_foundry_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->address = NULL;
  output->native_tokens = NULL;
  output->circ_supply = NULL;
  output->max_supply = NULL;
  output->feature_blocks = NULL;

  size_t offset = 0;

  // Check if output type is foundry output
  if (buf[offset] != OUTPUT_FOUNDRY) {
    printf("[%s:%d] buffer does not contain Foundry Output object\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // address
  output->address = address_deserialize(&buf[offset], buf_len - offset);
  if (!output->address) {
    printf("[%s:%d] can not deserialize address\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  offset += address_serialized_len(output->address);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
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
      output_foundry_free(output);
      return NULL;
    }
    offset += native_tokens_serialize_len(&output->native_tokens);
  } else {
    offset += sizeof(uint16_t);
  }

  // serial number
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->serial, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // token tag
  if (buf_len < offset + TOKEN_TAG_BYTES_LEN) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->token_tag, &buf[offset], TOKEN_TAG_BYTES_LEN);
  offset += TOKEN_TAG_BYTES_LEN;

  // circulating supply
  if (buf_len < offset + sizeof(uint256_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  output->circ_supply = malloc(sizeof(uint256_t));
  if (!output->circ_supply) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(output->circ_supply, &buf[offset], sizeof(uint256_t));
  offset += sizeof(uint256_t);

  // maximum supply
  if (buf_len < offset + sizeof(uint256_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  output->max_supply = malloc(sizeof(uint256_t));
  if (!output->max_supply) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(output->max_supply, &buf[offset], sizeof(uint256_t));
  offset += sizeof(uint256_t);

  // token scheme
  if (buf_len < offset + sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->token_scheme, &buf[offset], sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // feature blocks
  uint8_t feat_block_count = *((uint8_t*)&buf[offset]);
  if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
  }

  return output;
}

void output_foundry_print(output_foundry_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("Foundry Output: [\n");

  printf("\tAddress: ");
  address_print(output->address);

  printf("\tAmount: %" PRIu64 "\n", output->amount);

  // print native tokens
  native_tokens_t *token, *tmp;
  char* amount_str;
  printf("\tNative Tokens: [\n");
  HASH_ITER(hh, *(&output->native_tokens), token, tmp) {
    amount_str = uint256_to_str(token->amount);
    if (amount_str != NULL) {
      printf("\t\t[%s] ", amount_str);
      dump_hex_str(token->token_id, NATIVE_TOKEN_ID_BYTES);
      free(amount_str);
    }
  }
  printf("\t]\n");

  printf("\tSerial Number: %" PRIu32 "\n", output->serial);

  // print token tag
  printf("\tToken Tag: ");
  dump_hex_str(output->token_tag, TOKEN_TAG_BYTES_LEN);

  // print circulating supply
  char* circ_supply_str;
  circ_supply_str = uint256_to_str(output->circ_supply);
  if (circ_supply_str != NULL) {
    printf("\tCirculating Supply: [%s]\n", circ_supply_str);
    free(circ_supply_str);
  }

  // print maximum supply
  char* max_supply_str;
  max_supply_str = uint256_to_str(output->max_supply);
  if (max_supply_str != NULL) {
    printf("\tMaximum Supply: [%s]\n", max_supply_str);
    free(max_supply_str);
  }

  token_scheme_e token_scheme = output->token_scheme;
  if (token_scheme == SIMPLE_TOKEN_SCHEME) {
    printf("\tToken Scheme: Simple Token Scheme\n");
  } else {
    printf("\tToken Scheme: Unknown Token Scheme\n");
  }

  // print feature blocks
  printf("\tFeature Blocks:[\n");
  feat_blk_list_t* feat_block;
  printf("\t\tBlock Counts: %d\n", feat_blk_list_len(output->feature_blocks));
  if (output->feature_blocks) {
    uint8_t index = 0;
    LL_FOREACH(output->feature_blocks, feat_block) {
      printf("\t\t#%d ", index);
      feat_blk_print(feat_block->blk);
      index++;
    }
  }
  printf("\t]\n");

  printf("]\n");
}
