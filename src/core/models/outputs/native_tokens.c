// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/native_tokens.h"

#define NATIVE_TOKENS_MIN_COUNT 0
#define NATIVE_TOKENS_MAX_COUNT 256

int native_tokens_add(native_tokens_t **nt, byte_t token_id[], char const *amount_str) {
  if (nt == NULL || token_id == NULL || amount_str == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (native_tokens_count(nt) >= NATIVE_TOKENS_MAX_COUNT) {
    printf("[%s:%d] Native Tokens count must be <= 256\n", __func__, __LINE__);
    return -1;
  }

  native_tokens_t *token = native_tokens_find_by_id(nt, token_id);
  if (token) {
    printf("[%s:%d] Native Token already exists\n", __func__, __LINE__);
    return -1;
  }

  token = malloc(sizeof(native_tokens_t));
  if (!token) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  token->amount = uint256_from_str(amount_str);
  if (!token->amount) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(token->token_id, token_id, NATIVE_TOKEN_ID_BYTES);
  HASH_ADD(hh, *nt, token_id, NATIVE_TOKEN_ID_BYTES, token);

  return 0;
}

bool native_tokens_equal(native_tokens_t *token1, native_tokens_t *token2) {
  if (token1 == NULL || token1 == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  int cmp = memcmp(token1->token_id, token2->token_id, sizeof(token1->token_id));
  return (cmp == 0);
}

size_t native_tokens_serialize_length(native_tokens_t **nt) {
  size_t length = 0;
  uint8_t tokens_count = native_tokens_count(nt);

  // serialized Native Tokens
  length += NATIVE_TOKENS_SERIALIZED_BYTES * tokens_count;

  return length;
}

size_t native_tokens_serialize(native_tokens_t **nt, byte_t buf[]) {
  if (nt == NULL || buf == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  native_tokens_t *elm, *tmp;
  size_t byte_count = 0;
  uint8_t elm_count = 0;

  HASH_ITER(hh, *nt, elm, tmp) {
    // ID
    memcpy(buf + byte_count, elm->token_id, NATIVE_TOKEN_ID_BYTES);
    byte_count += NATIVE_TOKEN_ID_BYTES;

    // amount
    memcpy(buf + byte_count, elm->amount, sizeof(uint256_t));
    byte_count += sizeof(uint256_t);

    elm_count++;
  }

  if (byte_count != (elm_count * NATIVE_TOKENS_SERIALIZED_BYTES)) {
    printf("[%s:%d] offset error\n", __func__, __LINE__);
    return 0;
  }

  return byte_count;
}

void native_tokens_print(native_tokens_t **nt) {
  if (nt == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  native_tokens_t *elm, *tmp;
  char *amount_str;

  printf("Native Tokens: [\n");
  HASH_ITER(hh, *nt, elm, tmp) {
    amount_str = uint256_to_str(elm->amount);
    printf("\t[%s] ", amount_str);
    dump_hex(elm->token_id, NATIVE_TOKEN_ID_BYTES);
    free(amount_str);
  }
  printf("]\n");
}
