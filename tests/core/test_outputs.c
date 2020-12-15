#include <stdio.h>

#include "core/models/outputs/sig_unlocked_single_output.h"
#include "sodium.h"
#include "unity/unity.h"

void test_output_suso() {
  sig_unlocked_single_output_t out = {0};
  uint64_t value = UINT64_MAX - 1;
  byte_t expect_addr[ED25519_ADDRESS_BYTES];
  randombytes_buf((void *const)expect_addr, ED25519_ADDRESS_BYTES);
  memcpy(&out.addr, expect_addr, ED25519_ADDRESS_BYTES);
  out.amount = value;
  output_suso_print(&out);
  TEST_ASSERT_EQUAL_UINT64(value, out.amount);

  output_suso_array_t *list = outputs_suso_new();
  TEST_ASSERT_NOT_NULL(list);

  TEST_ASSERT_EQUAL_UINT32(0, outputs_suso_len(list));

  outputs_suso_push(list, &out);
  TEST_ASSERT_EQUAL_UINT32(1, outputs_suso_len(list));

  sig_unlocked_single_output_t *elm = outputs_suso_at(list, 0);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 1, elm->amount);
  TEST_ASSERT_EQUAL_MEMORY(elm->addr, expect_addr, ED25519_ADDRESS_BYTES);

  outputs_suso_pop(list);
  TEST_ASSERT_EQUAL_UINT32(0, outputs_suso_len(list));

  for (int i = 0; i < 100; i++) {
    out.amount = i;
    out.addr[ED25519_ADDRESS_BYTES - 1] = i;
    outputs_suso_push(list, &out);
  }

  elm = outputs_suso_at(list, 200);
  TEST_ASSERT_NULL(elm);
  elm = outputs_suso_at(list, 99);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_UINT32(99, elm->amount);
  TEST_ASSERT_EQUAL_MEMORY(elm->addr, expect_addr, ED25519_ADDRESS_BYTES - 1);

  outputs_suso_array_print(list);

  outputs_suso_free(list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_suso);

  return UNITY_END();
}