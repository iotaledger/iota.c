// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/output_extended.h"
#include "core/address.h"
#include "uthash.h"

output_extended_t* output_extended_new(void* address, uint64_t amount, native_tokens_t** tokens, void* feature_blocks) {
  if (address == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (amount < 1000000) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  output_extended_t* output = malloc(sizeof(output_extended_t));
  if (!output) {
    return NULL;
  }

  switch (((address_t*)address)->type) {
    case ADDRESS_TYPE_ED25519:
      output->address = malloc(ADDRESS_ED25519_BYTES);
      if (!output->address) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(output->address, ((address_t*)address)->address, ADDRESS_ED25519_BYTES);
      break;
    case ADDRESS_TYPE_ALIAS:
      output->address = malloc(ADDRESS_ALIAS_BYTES);
      if (!output->address) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(output->address, ((address_t*)address)->address, ADDRESS_ALIAS_BYTES);
      break;
    case ADDRESS_TYPE_NFT:
      output->address = malloc(ADDRESS_NFT_BYTES);
      if (!output->address) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(output->address, ((address_t*)address)->address, ADDRESS_NFT_BYTES);
      break;
    default:
      printf("[%s:%d] unknown address type\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
  }

  output->amount = amount;

  if (tokens != NULL) {
    // output->native_tokens = native_tokens_new();

    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, *tokens, token, token_tmp) {
      /*int res = native_tokens_add(&output->native_tokens, token->token_id, uint256_to_string(token->amount));
      if (res == -1) {
        printf("[%s:%d] can not add native token to extended output\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }*/
    }
  }

  return output;
}

void output_extended_free(output_extended_t* output) {
  if (output) {
    if (output->address) {
      free(output->address);
    }
    if (output->native_tokens) {
      // native_tokens_free(&output->native_tokens);
    }
    if (output->feature_blocks) {
      // feature_blocks_free(&output->feature_blocks);
    }
    free(output);
  }
}

size_t output_extended_serialize_length(output_extended_t* output) {
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
  // native tokens count
  length += sizeof(uint16_t);
  // native tokens
  // length += native_tokens_serialize_length(output->native_tokens);
  // feature blocks count
  length += sizeof(uint8_t);
  // feature blocks
  // length += feature_blocks_serialize_length(output->native_tokens);

  return length;
}

size_t output_extended_serialize(output_extended_t* output, byte_t buf[]) {
  if (output == NULL || output->address == NULL || buf == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;

  // fill-in output type, set to value 3 to denote a Extended Output
  memset(offset, 3, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // address
  switch (((address_t*)(output->address))->type) {
    case ADDRESS_TYPE_ED25519:
      memcpy(offset, output->address, ADDRESS_ED25519_BYTES);
      offset += ADDRESS_ED25519_BYTES;
      break;
    case ADDRESS_TYPE_ALIAS:
      memcpy(offset, output->address, ADDRESS_ALIAS_BYTES);
      offset += ADDRESS_TYPE_ALIAS;
      break;
    case ADDRESS_TYPE_NFT:
      memcpy(offset, output->address, ADDRESS_NFT_BYTES);
      offset += ADDRESS_NFT_BYTES;
      break;
  }

  // amount
  memset(offset, output->amount, sizeof(uint64_t));

  // Native Tokens
  if (output->native_tokens) {
    /*memset(offset, native_tokens_len(output->native_tokens), sizeof(uint16_t));
    offset += sizeof(uint16_t);
    offset += native_tokens_serialize(output->native_tokens);*/
  } else {
    memset(offset, 0, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  // Feature Blocks
  if (output->feature_blocks) {
    /*memset(offset, feature_blocks_len(output->native_tokens), sizeof(uint8_t));
    offset += sizeof(uint8_t);
    offset += feature_blocks_serialize(output->native_tokens);*/
  } else {
    memset(offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  return (offset - buf) / sizeof(byte_t);
}
