// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/utils/iota_str.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_iota_str() {
  char* c_str1 = "hello";
  // test new
  iota_str_t* str1 = iota_str_new(c_str1);
  TEST_ASSERT_NOT_NULL(str1);
  TEST_ASSERT_NOT_NULL(str1->buf);
  TEST_ASSERT_EQUAL_INT(strlen(c_str1), str1->len);
  TEST_ASSERT_EQUAL_INT(strlen(c_str1) + 1, str1->cap);
  TEST_ASSERT(strcmp(str1->buf, c_str1) == 0);

  // test append
  int ret = iota_str_append(str1, " world!");
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(strcmp(str1->buf, "hello world!") == 0);

  ret = iota_str_appendn(str1, " world!", 3);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(strcmp(str1->buf, "hello world! wo") == 0);

  ret = iota_str_append_char(str1, 'W');
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(strcmp(str1->buf, "hello world! woW") == 0);

  // test clone
  iota_str_t* str2 = iota_str_clone(str1);
  TEST_ASSERT_NOT_NULL(str2);
  TEST_ASSERT_NOT_NULL(str2->buf);
  TEST_ASSERT(strcmp(str1->buf, str2->buf) == 0);
  TEST_ASSERT_EQUAL_INT32(str1->len, str2->len);
  // test cmp
  TEST_ASSERT(iota_str_cmp(str1, str2) == 0);

  // test n clone
  iota_str_t* str3 = iota_str_clonen(str1, strlen(c_str1));
  TEST_ASSERT_NOT_NULL(str3);
  TEST_ASSERT_NOT_NULL(str3->buf);
  TEST_ASSERT_EQUAL_INT(strlen(c_str1), str3->len);
  TEST_ASSERT_EQUAL_INT(strlen(c_str1) + 1, str3->cap);
  TEST_ASSERT(strcmp(str3->buf, c_str1) == 0);

  iota_str_destroy(str1);
  iota_str_destroy(str2);
  iota_str_destroy(str3);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_iota_str);

  return UNITY_END();
}