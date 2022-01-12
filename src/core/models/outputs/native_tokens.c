// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/native_tokens.h"

#define NATIVE_TOKENS_MIN_COUNT 0
#define NATIVE_TOKENS_MAX_COUNT 256

// Native Tokens must be lexicographically sorted based on Token ID
static int token_id_sort(native_tokens_t *token1, native_tokens_t *token2) {
  return memcmp(token1->token_id, token2->token_id, NATIVE_TOKEN_ID_BYTES);
}

int native_tokens_add(native_tokens_t **nt, byte_t token_id[], uint256_t const *amount) {
  if (nt == NULL || token_id == NULL || amount == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (native_tokens_count(nt) >= NATIVE_TOKENS_MAX_COUNT) {
    printf("[%s:%d] Native Tokens count must be <= %d\n", __func__, __LINE__, NATIVE_TOKENS_MAX_COUNT);
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
  token->amount = malloc(sizeof(uint256_t));
  if (!token->amount) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    free(token);
    return -1;
  }
  memcpy(token->amount, amount, sizeof(uint256_t));
  memcpy(token->token_id, token_id, NATIVE_TOKEN_ID_BYTES);
  HASH_ADD(hh, *nt, token_id, NATIVE_TOKEN_ID_BYTES, token);

  return 0;
}

bool native_tokens_equal(native_tokens_t *token1, native_tokens_t *token2) {
  if (token1 == NULL || token2 == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  int cmp = memcmp(token1->token_id, token2->token_id, sizeof(token1->token_id));
  return (cmp == 0);
}

size_t native_tokens_serialize_len(native_tokens_t **nt) {
  size_t length = 0;
  uint8_t tokens_count = native_tokens_count(nt);

  // Native Tokens count
  length += sizeof(uint16_t);

  // serialized Native Tokens
  length += NATIVE_TOKENS_SERIALIZED_BYTES * tokens_count;

  return length;
}

size_t native_tokens_serialize(native_tokens_t **nt, byte_t buf[], size_t buf_len) {
  if (nt == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = native_tokens_serialize_len(nt);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  native_tokens_t *elm, *tmp;
  size_t offset = 0;

  // Native Tokens count
  uint16_t count = native_tokens_count(nt);
  memcpy(buf + offset, &count, sizeof(uint16_t));
  offset += sizeof(uint16_t);

  // sort Native Tokens in lexicographical order based on token ID
  HASH_SORT(*nt, token_id_sort);

  HASH_ITER(hh, *nt, elm, tmp) {
    // ID
    memcpy(buf + offset, elm->token_id, NATIVE_TOKEN_ID_BYTES);
    offset += NATIVE_TOKEN_ID_BYTES;

    // amount
    memcpy(buf + offset, elm->amount, sizeof(uint256_t));
    offset += sizeof(uint256_t);
  }

  return expected_bytes;
}

native_tokens_t *native_tokens_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len < 2) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  native_tokens_t *nt = native_tokens_new();

  uint16_t offset = 0;

  uint16_t tokens_count = (uint16_t)buf[0];
  offset += sizeof(uint16_t);

  if (tokens_count == 0) {
    return nt;
  }

  if (buf_len < sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    native_tokens_free(&nt);
    return NULL;
  }

  for (uint16_t i = 0; i < tokens_count; i++) {
    native_tokens_t *token = malloc(sizeof(native_tokens_t));
    if (!token) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      native_tokens_free(&nt);
      return NULL;
    }
    token->amount = malloc(sizeof(uint256_t));
    if (!token->amount) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      native_tokens_free(&nt);
      return NULL;
    }

    memcpy(token->token_id, &buf[offset], NATIVE_TOKEN_ID_BYTES);
    offset += NATIVE_TOKEN_ID_BYTES;
    memcpy(token->amount, &buf[offset], sizeof(uint256_t));
    offset += sizeof(uint256_t);
    HASH_ADD(hh, nt, token_id, NATIVE_TOKEN_ID_BYTES, token);
  }

  return nt;
}

native_tokens_t *native_tokens_clone(native_tokens_t const *const nt) {
  if (nt == NULL) {
    return NULL;
  }

  native_tokens_t *new_native_tokens = native_tokens_new();

  native_tokens_t *token, *token_tmp;
  HASH_ITER(hh, (native_tokens_t *)nt, token, token_tmp) {
    if (native_tokens_add(&new_native_tokens, token->token_id, token->amount) == -1) {
      printf("[%s:%d] can not clone native tokens\n", __func__, __LINE__);
      native_tokens_free(&new_native_tokens);
      return NULL;
    }
  }

  return new_native_tokens;
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
    if (amount_str != NULL) {
      printf("\t[%s] ", amount_str);
      dump_hex_str(elm->token_id, NATIVE_TOKEN_ID_BYTES);
      free(amount_str);
    }
  }
  printf("]\n");
}
