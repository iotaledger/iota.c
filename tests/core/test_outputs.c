#include <stdio.h>

#include "core/models/outputs/sig_unlocked_single_output.h"
#include "sodium.h"
#include "unity/unity.h"

void test_utxo_outputs() {
  byte_t addr1[ED25519_ADDRESS_BYTES] = {};
  byte_t addr2[ED25519_ADDRESS_BYTES] = {};
  randombytes_buf((void* const)addr1, ED25519_ADDRESS_BYTES);
  randombytes_buf((void* const)addr2, ED25519_ADDRESS_BYTES);

  sig_unlocked_outputs_ht* outputs = utxo_outputs_new();
  TEST_ASSERT_NULL(outputs);

  TEST_ASSERT_EQUAL_UINT32(0, utxo_outputs_count(&outputs));
  // add address1
  TEST_ASSERT(utxo_outputs_add(&outputs, addr1, 1000) == 0);
  TEST_ASSERT_EQUAL_UINT32(1, utxo_outputs_count(&outputs));

  // address doesn't exist.
  TEST_ASSERT_NULL(utxo_outputs_find_by_addr(&outputs, addr2));

  // add address1 again
  TEST_ASSERT(utxo_outputs_add(&outputs, addr1, 1000) == -1);
  TEST_ASSERT_EQUAL_UINT32(1, utxo_outputs_count(&outputs));

  // add address2
  TEST_ASSERT(utxo_outputs_add(&outputs, addr2, 9000000) == 0);
  TEST_ASSERT_EQUAL_UINT32(2, utxo_outputs_count(&outputs));

  // find and validate an output
  sig_unlocked_outputs_ht* elm = utxo_outputs_find_by_addr(&outputs, addr1);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_MEMORY(addr1, elm->address, ED25519_ADDRESS_BYTES);
  TEST_ASSERT(1000 == elm->amount);

  utxo_outputs_print(&outputs);

  utxo_outputs_free(&outputs);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_utxo_outputs);

  return UNITY_END();
}