// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/inputs/utxo_input.h"
#include "unity/unity.h"

static byte_t tx_id0[TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t tx_id1[TRANSACTION_ID_BYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                              255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                              255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
static byte_t tx_id2[TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                              190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                              90,  172, 252, 142, 91,  179, 113, 2,   177, 58};

void setUp(void) {}

void tearDown(void) {}

void test_utxo_input() {
  utxo_input_ht* inputs = utxo_inputs_new();
  TEST_ASSERT_NULL(inputs);

  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(&inputs));
  TEST_ASSERT(utxo_inputs_add(&inputs, tx_id0, UINT8_MAX) == -1);
  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(&inputs));
  TEST_ASSERT(utxo_inputs_add(&inputs, tx_id0, 0) == 0);
  TEST_ASSERT_EQUAL_UINT16(1, utxo_inputs_count(&inputs));

  // transaction ID doesn't exist.
  TEST_ASSERT_NULL(utxo_inputs_find_by_id(&inputs, tx_id2));

  // add more tx IDs
  TEST_ASSERT(utxo_inputs_add(&inputs, tx_id1, 1) == 0);
  TEST_ASSERT(utxo_inputs_add(&inputs, tx_id2, 2) == 0);
  TEST_ASSERT_EQUAL_UINT16(3, utxo_inputs_count(&inputs));

  // find and validate transaction ID
  utxo_input_ht* elm = utxo_inputs_find_by_id(&inputs, tx_id1);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_MEMORY(tx_id1, elm->tx_id, TRANSACTION_ID_BYTES);
  TEST_ASSERT(1 == elm->output_index);
  TEST_ASSERT_EQUAL_UINT16(3, utxo_inputs_count(&inputs));

  utxo_inputs_print(&inputs);

  utxo_inputs_free(&inputs);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_utxo_input);

  return UNITY_END();
}