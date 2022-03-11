// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>
#include <string.h>

#include "core/models/outputs/native_tokens.h"

#define NATIVE_TOKENS_MAX_COUNT 64

// Native Tokens must be lexicographically sorted based on Token ID
static int token_id_sort(native_tokens_list_t *token1, native_tokens_list_t *token2) {
  return memcmp(token1->token->token_id, token2->token->token_id, NATIVE_TOKEN_ID_BYTES);
}

native_tokens_list_t *native_tokens_new() { return NULL; }

native_token_t *native_tokens_find_by_id(native_tokens_list_t *nt, byte_t id[]) {
  if (nt == NULL || id == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  native_tokens_list_t *elm;
  LL_FOREACH(nt, elm) {
    if (memcmp(elm->token->token_id, id, NATIVE_TOKEN_ID_BYTES) == 0) {
      return elm->token;
    }
  }

  return NULL;
}

uint8_t native_tokens_count(native_tokens_list_t *nt) {
  native_tokens_list_t *elm = NULL;
  uint16_t len = 0;
  if (nt) {
    LL_COUNT(nt, elm, len);
  }
  return len;
}

void native_tokens_free(native_tokens_list_t *nt) {
  if (nt) {
    native_tokens_list_t *elm, *tmp;
    LL_FOREACH_SAFE(nt, elm, tmp) {
      free(elm->token);
      LL_DELETE(nt, elm);
      free(elm);
    }
  }
}

int native_tokens_add(native_tokens_list_t **nt, byte_t token_id[], uint256_t const *amount) {
  if (nt == NULL || token_id == NULL || amount == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (amount->bits[0] == 0 && amount->bits[1] == 0 && amount->bits[2] == 0 && amount->bits[3] == 0) {
    printf("[%s:%d] Amount of Native Token must not be 0\n", __func__, __LINE__);
    return -1;
  }

  if (native_tokens_count(*nt) >= NATIVE_TOKENS_MAX_COUNT) {
    printf("[%s:%d] Native Tokens count must be <= %d\n", __func__, __LINE__, NATIVE_TOKENS_MAX_COUNT);
    return -1;
  }

  native_token_t *token = native_tokens_find_by_id(*nt, token_id);
  if (token) {
    printf("[%s:%d] Native Token already exists\n", __func__, __LINE__);
    return -1;
  }

  token = malloc(sizeof(native_token_t));
  if (!token) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(&token->amount, amount, sizeof(uint256_t));
  memcpy(token->token_id, token_id, NATIVE_TOKEN_ID_BYTES);

  native_tokens_list_t *tokens_list = malloc(sizeof(native_tokens_list_t));
  if (tokens_list) {
    tokens_list->token = token;
    tokens_list->next = NULL;
    LL_APPEND(*nt, tokens_list);
    return 0;
  }

  free(token);
  return -1;
}

bool native_tokens_equal(native_token_t *token1, native_token_t *token2) {
  if (token1 == NULL || token2 == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  int cmp = memcmp(token1->token_id, token2->token_id, sizeof(token1->token_id));
  return (cmp == 0);
}

size_t native_tokens_serialize_len(native_tokens_list_t *nt) {
  size_t length = 0;
  uint8_t tokens_count = native_tokens_count(nt);

  // Native Tokens count
  length += sizeof(uint8_t);

  // serialized Native Tokens
  length += NATIVE_TOKENS_SERIALIZED_BYTES * tokens_count;

  return length;
}

size_t native_tokens_serialize(native_tokens_list_t **nt, byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = native_tokens_serialize_len(*nt);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;

  // Native Tokens count
  uint8_t count = native_tokens_count(*nt);
  memcpy(buf + offset, &count, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // sort Native Tokens in lexicographical order based on token ID
  LL_SORT(*nt, token_id_sort);

  native_tokens_list_t *elm;
  LL_FOREACH(*nt, elm) {
    // ID
    memcpy(buf + offset, elm->token->token_id, NATIVE_TOKEN_ID_BYTES);
    offset += NATIVE_TOKEN_ID_BYTES;

    // amount
    memcpy(buf + offset, &elm->token->amount, sizeof(uint256_t));
    offset += sizeof(uint256_t);
  }

  return offset;
}

native_tokens_list_t *native_tokens_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len < 2) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  native_tokens_list_t *nt = native_tokens_new();

  size_t offset = 0;

  uint8_t tokens_count = (uint8_t)buf[0];
  offset += sizeof(uint8_t);

  if (tokens_count == 0) {
    return nt;
  }

  if (buf_len < sizeof(uint8_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    native_tokens_free(nt);
    return NULL;
  }

  for (uint8_t i = 0; i < tokens_count; i++) {
    // ID
    byte_t token_id[NATIVE_TOKEN_ID_BYTES];
    memcpy(token_id, &buf[offset], NATIVE_TOKEN_ID_BYTES);
    offset += NATIVE_TOKEN_ID_BYTES;

    // amount
    uint256_t amount;
    memcpy(&amount, &buf[offset], sizeof(uint256_t));
    offset += sizeof(uint256_t);

    if (native_tokens_add(&nt, token_id, &amount) != 0) {
      printf("[%s:%d] can not add new Native Token into a list\n", __func__, __LINE__);
      native_tokens_free(nt);
      return NULL;
    }
  }

  return nt;
}

native_tokens_list_t *native_tokens_clone(native_tokens_list_t *const nt) {
  if (nt == NULL) {
    return NULL;
  }

  native_tokens_list_t *new_native_tokens = native_tokens_new();

  native_tokens_list_t *elm;
  LL_FOREACH(nt, elm) {
    if (native_tokens_add(&new_native_tokens, elm->token->token_id, &elm->token->amount) == -1) {
      printf("[%s:%d] can not clone native tokens\n", __func__, __LINE__);
      native_tokens_free(new_native_tokens);
      return NULL;
    }
  }

  return new_native_tokens;
}

void native_tokens_print(native_tokens_list_t *nt, uint8_t indentation) {
  if (nt == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  native_tokens_list_t *elm;
  char *amount_str;
  uint16_t index = 0;

  printf("%sNative Tokens: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tToken Count: %d\n", PRINT_INDENTATION(indentation), native_tokens_count(nt));
  LL_FOREACH(nt, elm) {
    amount_str = uint256_to_str(&elm->token->amount);
    if (amount_str != NULL) {
      printf("%s\t#%d [%s] ", PRINT_INDENTATION(indentation), index, amount_str);
      dump_hex_str(elm->token->token_id, NATIVE_TOKEN_ID_BYTES);
      free(amount_str);
    }
    index++;
  }
  printf("%s]\n", PRINT_INDENTATION(indentation));
}
