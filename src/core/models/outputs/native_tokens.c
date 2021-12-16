// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/native_tokens.h"

#define NATIVE_TOKENS_MIN_COUNT 0
#define NATIVE_TOKENS_MAX_COUNT 256

int native_tokens_add_from_amount_str(native_tokens_t **nt, byte_t token_id[], char const *amount_str) {
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

int native_tokens_add_from_amount_uint256(native_tokens_t **nt, byte_t token_id[], uint256_t const *amount) {
  if (nt == NULL || token_id == NULL || amount == NULL) {
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
  token->amount = malloc(sizeof(uint256_t));
  if (!token->amount) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(token->amount, amount, sizeof(uint256_t));
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

size_t native_tokens_serialize_len(native_tokens_t **nt) {
  size_t length = 0;
  uint8_t tokens_count = native_tokens_count(nt);

  // Native Tokens count
  length += sizeof(uint16_t);

  // serialized Native Tokens
  length += NATIVE_TOKENS_SERIALIZED_BYTES * tokens_count;

  return length;
}

int native_tokens_serialize(native_tokens_t **nt, byte_t buf[], size_t buf_len) {
  if (nt == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (buf_len < native_tokens_serialize_len(nt)) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return -1;
  }

  native_tokens_t *elm, *tmp;
  size_t byte_count = 0;
  uint8_t elm_count = 0;

  // Native Tokens count
  uint16_t count = native_tokens_count(nt);
  memcpy(buf + byte_count, &count, sizeof(uint16_t));
  byte_count += sizeof(uint16_t);

  HASH_ITER(hh, *nt, elm, tmp) {
    // ID
    memcpy(buf + byte_count, elm->token_id, NATIVE_TOKEN_ID_BYTES);
    byte_count += NATIVE_TOKEN_ID_BYTES;

    // amount
    memcpy(buf + byte_count, elm->amount, sizeof(uint256_t));
    byte_count += sizeof(uint256_t);

    elm_count++;
  }

  if (byte_count != native_tokens_serialize_len(nt)) {
    printf("[%s:%d] offset error\n", __func__, __LINE__);
    return -1;
  }

  return 0;
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
    dump_hex_str(elm->token_id, NATIVE_TOKEN_ID_BYTES);
    free(amount_str);
  }
  printf("]\n");
}
