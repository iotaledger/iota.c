#include <stdio.h>

#include "core/models/outputs/sig_unlocked_single_deposit.h"
#include "sodium.h"
#include "unity/unity.h"

void test_output_susd() {
  sig_unlocked_single_deposit_t out = {0};
  uint64_t value = UINT64_MAX - 1;
  byte_t expect_addr[IOTA_ADDRESS_BYTES];
  randombytes_buf((void *const)expect_addr, IOTA_ADDRESS_BYTES);
  memcpy(&out.addr, expect_addr, IOTA_ADDRESS_BYTES);
  out.amount = value;
  output_susd_print(&out);
  TEST_ASSERT_EQUAL_UINT64(value, out.amount);

  output_susd_array_t *list = outputs_susd_new();
  TEST_ASSERT_NOT_NULL(list);

  TEST_ASSERT_EQUAL_UINT32(0, outputs_susd_len(list));

  outputs_susd_push(list, &out);
  TEST_ASSERT_EQUAL_UINT32(1, outputs_susd_len(list));

  sig_unlocked_single_deposit_t *elm = outputs_susd_at(list, 0);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 1, elm->amount);
  TEST_ASSERT_EQUAL_MEMORY(elm->addr, expect_addr, IOTA_ADDRESS_BYTES);

  outputs_susd_pop(list);
  TEST_ASSERT_EQUAL_UINT32(0, outputs_susd_len(list));

  for (int i = 0; i < 100; i++) {
    out.amount = i;
    out.addr[IOTA_ADDRESS_BYTES - 1] = i;
    outputs_susd_push(list, &out);
  }

  elm = outputs_susd_at(list, 200);
  TEST_ASSERT_NULL(elm);
  elm = outputs_susd_at(list, 99);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_UINT32(99, elm->amount);
  TEST_ASSERT_EQUAL_MEMORY(elm->addr, expect_addr, IOTA_ADDRESS_BYTES - 1);

  outputs_susd_array_print(list);

  outputs_susd_free(list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_susd);

  return UNITY_END();
}