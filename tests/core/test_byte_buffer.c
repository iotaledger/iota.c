// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "core/utils/byte_buffer.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_byte_buf() {
  // create a byte buffer
  byte_buf_t *buf = byte_buf_new();
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_NULL(buf->data);
  TEST_ASSERT(buf->cap == 0);
  TEST_ASSERT(buf->len == 0);

  // append two data sets to the buffer
  TEST_ASSERT_TRUE(byte_buf_append(buf, (byte_t *)"ABCDE", 5));
  TEST_ASSERT(buf->cap == 5);
  TEST_ASSERT(buf->len == 5);
  TEST_ASSERT_TRUE(byte_buf_append(buf, (byte_t *)"FGHIJ", 5));
  TEST_ASSERT(buf->cap == 10);
  TEST_ASSERT(buf->len == 10);
  // set data to the buffer
  TEST_ASSERT_TRUE(byte_buf_set(buf, (byte_t *)"VWXZY", 5));
  TEST_ASSERT(buf->cap == 10);
  TEST_ASSERT(buf->len == 5);
  // byte_buf_print(buf);

  // append an null terminator to buffer data
  byte_buf2str(buf);
  TEST_ASSERT(buf->cap == 10);
  TEST_ASSERT(buf->len == 6);
  // should not append the null terminator again
  byte_buf2str(buf);
  TEST_ASSERT(buf->cap == 10);
  TEST_ASSERT(buf->len == 6);
  // printf("%s\n", buf->data);

  // reserve size smaller than capacity
  TEST_ASSERT_TRUE(byte_buf_reserve(buf, 5));
  TEST_ASSERT(buf->cap == 10);
  TEST_ASSERT(buf->len == 6);

  // reserve size bigger than capacity
  TEST_ASSERT_TRUE(byte_buf_reserve(buf, 100));
  TEST_ASSERT(buf->cap == 100);
  TEST_ASSERT(buf->len == 6);

  // byte_buf_print(buf);

  // duplicates a byte buffer
  byte_buf_t *c = byte_buf_clone(buf);
  TEST_ASSERT(c->cap == 6);
  TEST_ASSERT(c->len == 6);
  TEST_ASSERT(c != buf);
  TEST_ASSERT(c->data != buf->data);
  TEST_ASSERT_EQUAL_MEMORY(c->data, buf->data, buf->len);

  byte_buf_free(buf);
  byte_buf_free(c);
}

void test_hex_convertor() {
  char const *exp_str = "Hello world!";
  char const *exp_hex = "48656C6C6F20776F726C6421";

  byte_buf_t *buf = byte_buf_new_with_data((byte_t *)exp_str, strlen(exp_str));
  byte_buf_t *hex = byte_buf_str2hex(buf);
  TEST_ASSERT_EQUAL_STRING(exp_hex, hex->data);
  byte_buf_free(buf);
  buf = NULL;
  byte_buf_free(hex);

  buf = byte_buf_new_with_data((byte_t *)exp_hex, strlen(exp_hex));
  byte_buf_t *str = byte_buf_hex2str(buf);
  TEST_ASSERT_EQUAL_STRING(exp_str, str->data);
  byte_buf_free(buf);
  byte_buf_free(str);
}

void test_hex_bin() {
  char const *exp_hex = "48656C6C6F20776F726C6421";
  byte_t exp_bin[12] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
  byte_t bin[12] = {};

  // hex2bin
  TEST_ASSERT(hex_2_bin(exp_hex, strlen(exp_hex), bin, 12) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_bin, bin, 12);

  // bin2hex
  char hex_str[(12 * 2) + 1] = {};
  TEST_ASSERT(bin_2_hex(bin, 12, hex_str, sizeof(hex_str)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_hex, hex_str);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_byte_buf);
  RUN_TEST(test_hex_convertor);
  RUN_TEST(test_hex_bin);

  return UNITY_END();
}
