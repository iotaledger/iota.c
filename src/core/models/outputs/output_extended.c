// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/address.h"
#include "core/models/outputs/output_extended.h"
#include "uthash.h"

output_extended_t* output_extended_new(address_t* addr, uint64_t amount, native_tokens_t** tokens, void* feat_blocks) {
  if (addr == NULL) {
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

  output->address = malloc(sizeof(address_t));
  if (!output->address) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }

  memcpy(output->address, addr, sizeof(address_t));
  output->amount = amount;

  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, *tokens, token, token_tmp) {
      char* amount_str = uint256_to_str(token->amount);
      int res = native_tokens_add(&output->native_tokens, token->token_id, amount_str);
      free(amount_str);
      if (res == -1) {
        printf("[%s:%d] can not add native token to extended output\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
    }
  } else {
    output->native_tokens = NULL;
  }

  if (feat_blocks != NULL) {
    // TODO implement this
  } else {
    output->feature_blocks = NULL;
  }

  return output;
}

void output_extended_free(output_extended_t* output) {
  if (output) {
    if (output->address) {
      free(output->address);
    }
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    if (output->feature_blocks) {
      // feature_blocks_free(&output->feature_blocks);
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
  // feature blocks count
  length += sizeof(uint8_t);
  // feature blocks
  // length += feature_blocks_serialize_length(output->native_tokens);

  return length;
}

int output_extended_serialize(output_extended_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (buf_len < output_extended_serialize_len(output)) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return -1;
  }

  byte_t* offset = buf;

  // fill-in output type, set to value 3 to denote a Extended Output
  memset(offset, 3, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // address
  int res = address_serialized(output->address, offset, address_serialized_len(output->address));
  if (res == -1) {
    printf("[%s:%d] can not serialize address\n", __func__, __LINE__);
    return -1;
  }
  offset += address_serialized_len(output->address);

  // amount
  memcpy(offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // Native Tokens
  if (output->native_tokens) {
    offset += native_tokens_serialize(&output->native_tokens, offset);
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

  return 0;
}

output_extended_t* output_extended_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
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
  if (buf[offset] != 3) {
    printf("[%s:%d] buffer does not contain Extended Output object\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // address
  if (buf_len < offset + sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  output->address = malloc(sizeof(address_t));
  if (!output->address) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  output->address->type = buf[offset];
  offset += sizeof(uint8_t);

  switch (output->address->type) {
    case ADDRESS_TYPE_ED25519:
      if (buf_len < offset + ADDRESS_ED25519_BYTES) {
        printf("[%s:%d] invalid data length\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(output->address->address, &buf[offset], ADDRESS_ED25519_BYTES);
      offset += ADDRESS_ED25519_BYTES;
      break;
    case ADDRESS_TYPE_ALIAS:
      if (buf_len < offset + ADDRESS_ALIAS_BYTES) {
        printf("[%s:%d] invalid data length\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(output->address->address, &buf[offset], ADDRESS_ALIAS_BYTES);
      offset += ADDRESS_ALIAS_BYTES;
      break;
    case ADDRESS_TYPE_NFT:
      if (buf_len < offset + ADDRESS_NFT_BYTES) {
        printf("[%s:%d] invalid data length\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(output->address->address, &buf[offset], ADDRESS_NFT_BYTES);
      offset += ADDRESS_NFT_BYTES;
      break;
    default:
      printf("[%s:%d] unknown address type\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
  }

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  memcpy(&output->amount, &buf[offset], sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // Native Tokens
  if (buf_len < offset + sizeof(uint16_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  uint16_t tokens_count = (uint16_t)buf[offset];
  if (buf_len < offset + sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  output->native_tokens =
      native_tokens_deserialize(&buf[offset], sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES));
  if (!output->native_tokens) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  offset += sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES);

  return output;
}

void output_extended_print(output_extended_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("extended_output: [\n");
  char bech32_str[65] = {};
  address_to_bech32(output->address, "iota", bech32_str, sizeof(bech32_str));
  printf("\taddress: %s\n", bech32_str);
  printf("\tammount: %" PRIu64 "\n", output->amount);

  // print Native Tokens
  native_tokens_t *elm, *tmp;
  char* amount_str;

  printf("\tNative Tokens: [\n");
  HASH_ITER(hh, *(&output->native_tokens), elm, tmp) {
    amount_str = uint256_to_str(elm->amount);
    printf("\t\t[%s] ", amount_str);
    dump_hex(elm->token_id, NATIVE_TOKEN_ID_BYTES);
    free(amount_str);
  }
  printf("\t]\n");

  // print Feature Blocks
  // TODO print feature blocks

  printf("]\n");
}
