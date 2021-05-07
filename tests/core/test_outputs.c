// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/outputs/outputs.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_utxo_outputs() {
  byte_t addr1[ED25519_ADDRESS_BYTES] = {};
  byte_t addr2[ED25519_ADDRESS_BYTES] = {};
  byte_t addr3[ED25519_ADDRESS_BYTES] = {};
  iota_crypto_randombytes(addr1, ED25519_ADDRESS_BYTES);
  iota_crypto_randombytes(addr2, ED25519_ADDRESS_BYTES);
  iota_crypto_randombytes(addr3, ED25519_ADDRESS_BYTES);

  outputs_ht* outputs = utxo_outputs_new();
  TEST_ASSERT_NULL(outputs);

  TEST_ASSERT_EQUAL_UINT32(0, utxo_outputs_count(&outputs));
  // add address1
  TEST_ASSERT(utxo_outputs_add(&outputs, OUTPUT_SINGLE_OUTPUT, addr1, 1000) == 0);
  TEST_ASSERT_EQUAL_UINT32(1, utxo_outputs_count(&outputs));

  // address doesn't exist.
  TEST_ASSERT_NULL(utxo_outputs_find_by_addr(&outputs, addr2));

  // add address1 again
  TEST_ASSERT(utxo_outputs_add(&outputs, OUTPUT_SINGLE_OUTPUT, addr1, 1000) == -1);
  TEST_ASSERT_EQUAL_UINT32(1, utxo_outputs_count(&outputs));

  // add address2
  TEST_ASSERT(utxo_outputs_add(&outputs, OUTPUT_SINGLE_OUTPUT, addr2, 9000000) == 0);
  TEST_ASSERT_EQUAL_UINT32(2, utxo_outputs_count(&outputs));

  // add dust
  TEST_ASSERT(utxo_outputs_add(&outputs, OUTPUT_DUST_ALLOWANCE, addr3, 100) != 0);
  TEST_ASSERT_EQUAL_UINT32(2, utxo_outputs_count(&outputs));
  TEST_ASSERT(utxo_outputs_add(&outputs, OUTPUT_DUST_ALLOWANCE, addr3, 1000000) == 0);
  TEST_ASSERT_EQUAL_UINT32(3, utxo_outputs_count(&outputs));

  // find and validate an output
  outputs_ht* elm = utxo_outputs_find_by_addr(&outputs, addr1);
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