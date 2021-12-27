// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/outputs/native_tokens.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_native_tokens() {
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xC8, 0x23, 0xAA, 0x49, 0x94, 0xF1, 0xBF, 0xB2, 0x7C, 0x6E, 0x80, 0x63, 0x4F, 0xE,  0xC7, 0x4E, 0x2C, 0x36, 0x75,
      0xD2, 0x62, 0xB3, 0x7,  0x1,  0xA5, 0x4D, 0x58, 0x7E, 0x8D, 0x95, 0xB6, 0xBF, 0xCA, 0x2,  0x6A, 0xAC, 0xF3, 0x48};
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
      0x9,  0x59, 0x55, 0x7F, 0xB1, 0xB9, 0x32, 0xE,  0x15, 0x94, 0x1C, 0x14, 0x2F, 0xD5, 0x3E, 0xA6, 0x4C, 0x77, 0xA5,
      0xCF, 0x28, 0x8C, 0xB5, 0x6F, 0x88, 0x26, 0x90, 0x1,  0x50, 0x3D, 0x85, 0xF,  0x24, 0x42, 0x7D, 0x6F, 0x81, 0x2E};
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
      0x18, 0xF2, 0x49, 0x6F, 0x44, 0x95, 0xB2, 0x5F, 0x69, 0x98, 0x88, 0x43, 0x9F, 0xC,  0x39, 0x41, 0xF,  0x2,  0x27,
      0x60, 0xE7, 0xEA, 0x9,  0xF3, 0x4D, 0x69, 0xD9, 0xF3, 0x3B, 0xF6, 0xEF, 0x52, 0xE5, 0xFA, 0x7C, 0xEF, 0x21, 0xC8};
  byte_t native_tokens_byte[212] = {
      0x3,  0x0,  0x9,  0x59, 0x55, 0x7F, 0xB1, 0xB9, 0x32, 0xE,  0x15, 0x94, 0x1C, 0x14, 0x2F, 0xD5, 0x3E, 0xA6,
      0x4C, 0x77, 0xA5, 0xCF, 0x28, 0x8C, 0xB5, 0x6F, 0x88, 0x26, 0x90, 0x1,  0x50, 0x3D, 0x85, 0xF,  0x24, 0x42,
      0x7D, 0x6F, 0x81, 0x2E, 0x0,  0x0,  0x0,  0x0,  0x81, 0xEF, 0xAC, 0x85, 0x5B, 0x41, 0x6D, 0x2D, 0xEE, 0x4,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x18, 0xF2, 0x49, 0x6F, 0x44, 0x95, 0xB2, 0x5F, 0x69, 0x98, 0x88, 0x43, 0x9F, 0xC,  0x39, 0x41, 0xF,  0x2,
      0x27, 0x60, 0xE7, 0xEA, 0x9,  0xF3, 0x4D, 0x69, 0xD9, 0xF3, 0x3B, 0xF6, 0xEF, 0x52, 0xE5, 0xFA, 0x7C, 0xEF,
      0x21, 0xC8, 0x0,  0x0,  0x0,  0x0,  0x0,  0x80, 0x86, 0x59, 0x84, 0xDE, 0xA4, 0xA8, 0xC8, 0x5B, 0xA0, 0xB4,
      0xB3, 0x27, 0x84, 0x11, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0xC8, 0x23,
      0xAA, 0x49, 0x94, 0xF1, 0xBF, 0xB2, 0x7C, 0x6E, 0x80, 0x63, 0x4F, 0xE,  0xC7, 0x4E, 0x2C, 0x36, 0x75, 0xD2,
      0x62, 0xB3, 0x7,  0x1,  0xA5, 0x4D, 0x58, 0x7E, 0x8D, 0x95, 0xB6, 0xBF, 0xCA, 0x2,  0x6A, 0xAC, 0xF3, 0x48,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x4A, 0x83, 0xDA, 0x4A, 0x86, 0x54, 0xCB, 0xFD, 0xEB, 0x71, 0x25,
      0x9A, 0xC8, 0xB5, 0x7C, 0xC8, 0x28, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0};

  native_tokens_t* tokens = native_tokens_new();
  TEST_ASSERT_NULL(tokens);

  TEST_ASSERT_EQUAL_UINT32(0, native_tokens_count(&tokens));
  // add Native Token 1 to a set
  uint256_t* amount1 = uint256_from_str("1000000000000000000000000000000000000000000000000000000000");
  TEST_ASSERT(native_tokens_add(&tokens, token_id1, amount1) == 0);
  TEST_ASSERT_EQUAL_UINT32(1, native_tokens_count(&tokens));
  free(amount1);

  // Native Token 2 doesn't exist.
  TEST_ASSERT_NULL(native_tokens_find_by_id(&tokens, token_id2));

  // add Native Token 1 again
  amount1 = uint256_from_str("123456789");
  TEST_ASSERT(native_tokens_add(&tokens, token_id1, amount1) == -1);
  TEST_ASSERT_EQUAL_UINT32(1, native_tokens_count(&tokens));
  free(amount1);

  // add Native Token 2
  uint256_t* amount2 = uint256_from_str("100000000000000000000000000000000");
  TEST_ASSERT(native_tokens_add(&tokens, token_id2, amount2) == 0);
  TEST_ASSERT_EQUAL_UINT32(2, native_tokens_count(&tokens));
  free(amount2);

  // add Native Token 3
  uint256_t* amount3 = uint256_from_str("100000000000000000000000000000000000000000000000");
  TEST_ASSERT(native_tokens_add(&tokens, token_id3, amount3) == 0);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&tokens));
  free(amount3);

  // find and validate Native Token 2
  native_tokens_t* elm = native_tokens_find_by_id(&tokens, token_id2);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_MEMORY(token_id2, elm->token_id, NATIVE_TOKEN_ID_BYTES);
  char* str = uint256_to_str(elm->amount);
  TEST_ASSERT_EQUAL_STRING("100000000000000000000000000000000", str);
  free(str);

  // Compare Native Token 1 against Native Token 1
  native_tokens_t* token1 = native_tokens_find_by_id(&tokens, token_id1);
  TEST_ASSERT_TRUE(native_tokens_equal(token1, token1));

  // Compare Native Token 1 against Native Token 2
  token1 = native_tokens_find_by_id(&tokens, token_id1);
  native_tokens_t* token2 = native_tokens_find_by_id(&tokens, token_id2);
  TEST_ASSERT_FALSE(native_tokens_equal(token1, token2));

  // serialize Native Tokens set
  size_t native_tokens_expected_len = native_tokens_serialize_len(&tokens);
  TEST_ASSERT(native_tokens_expected_len != 0);
  byte_t* native_tokens_buf = malloc(native_tokens_expected_len);
  TEST_ASSERT_NOT_NULL(native_tokens_buf);
  TEST_ASSERT_EQUAL_INT(native_tokens_expected_len,
                        native_tokens_serialize(&tokens, native_tokens_buf, native_tokens_expected_len));
  // dump_hex(native_tokens_buf, native_tokens_expected_len);
  TEST_ASSERT_EQUAL_MEMORY(native_tokens_byte, native_tokens_buf, sizeof(native_tokens_byte));

  // deserialize Native Tokens set
  native_tokens_t* deser_tokens = native_tokens_deserialize(native_tokens_buf, native_tokens_expected_len);
  TEST_ASSERT_NOT_NULL(deser_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_tokens));

  native_tokens_print(&tokens, 0);

  free(native_tokens_buf);
  native_tokens_free(&tokens);
  native_tokens_free(&deser_tokens);
}

void test_native_tokens_sort() {
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56, 0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,
      0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75, 0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
      0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
      0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
      0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E, 0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE,
      0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42, 0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};

  // create Native Tokens
  native_tokens_t* tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("1000000000000000000000000000000000000000000000000000000000");
  native_tokens_add(&tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("100000000000000000000000000000000");
  native_tokens_add(&tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("100000000000000000000000000000000000000000000000");
  native_tokens_add(&tokens, token_id3, amount3);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&tokens));
  // native tokens are NOT sorted in lexicographical order based on token ID
  native_tokens_t* token = tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  // serialize Native Tokens set
  size_t native_tokens_expected_len = native_tokens_serialize_len(&tokens);
  byte_t* native_tokens_buf = malloc(native_tokens_expected_len);
  native_tokens_serialize(&tokens, native_tokens_buf, native_tokens_expected_len);

  // deserialize Native Tokens set
  native_tokens_t* deser_tokens = native_tokens_deserialize(native_tokens_buf, native_tokens_expected_len);
  TEST_ASSERT_NOT_NULL(deser_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  token = deser_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));

  native_tokens_print(&tokens, 0);

  free(amount1);
  free(amount2);
  free(amount3);
  free(native_tokens_buf);
  native_tokens_free(&tokens);
  native_tokens_free(&deser_tokens);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_native_tokens);
  RUN_TEST(test_native_tokens_sort);

  return UNITY_END();
}
