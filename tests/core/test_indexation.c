// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <unity/unity.h>

#include "core/models/payloads/indexation.h"

void test_indexation() {
  char const* const exp_index = "HELLO";
  char const* const exp_data = "48656C6C6F20776F726C6421";

  indexation_t* idx = indexation_new();
  TEST_ASSERT_NOT_NULL(idx);
  indexation_free(idx);
  idx = NULL;

  TEST_ASSERT_NULL(idx);
  idx = indexation_create(exp_index, exp_data);
  TEST_ASSERT_NOT_NULL(idx);

  // validate index
  TEST_ASSERT_EQUAL_STRING(exp_index, idx->index->data);
  TEST_ASSERT((strlen(exp_index) + 1) == idx->index->len);

  // validate data
  TEST_ASSERT_EQUAL_STRING(exp_data, idx->data->data);
  TEST_ASSERT((strlen(exp_data) + 1) == idx->data->len);

  indexation_free(idx);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_indexation);

  return UNITY_END();
}
