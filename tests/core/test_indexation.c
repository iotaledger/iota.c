// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <unity/unity.h>

#include "core/models/payloads/indexation.h"

void setUp(void) {}

void tearDown(void) {}

void test_indexation() {
  char const* const exp_index = "HELLO";
  byte_t exp_data[12] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
  byte_t exp_serialized[27] = {0x2, 0x0,  0x0,  0x0,  0x5,  0x0,  0x48, 0x45, 0x4C, 0x4C, 0x4F, 0xC,  0x0, 0x0,
                               0x0, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};

  indexation_t* idx = indexation_new();
  TEST_ASSERT_NOT_NULL(idx);
  indexation_free(idx);
  idx = NULL;

  TEST_ASSERT_NULL(idx);
  idx = indexation_create(exp_index, exp_data, sizeof(exp_data));
  TEST_ASSERT_NOT_NULL(idx);

  // validate index
  TEST_ASSERT_EQUAL_STRING(exp_index, idx->index->data);
  TEST_ASSERT((strlen(exp_index) + 1) == idx->index->len);

  // validate data
  TEST_ASSERT_EQUAL_MEMORY(exp_data, idx->data->data, sizeof(exp_data));

  // serialization
  size_t serialized_len = indexaction_serialize_length(idx);
  byte_t* serialized_data = malloc(serialized_len);
  size_t actual_len = indexation_payload_serialize(idx, serialized_data);
  TEST_ASSERT(serialized_len = actual_len);

  TEST_ASSERT_EQUAL_MEMORY(exp_serialized, serialized_data, sizeof(exp_serialized));
  dump_hex_str(serialized_data, serialized_len);

  free(serialized_data);
  indexation_free(idx);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_indexation);

  return UNITY_END();
}
