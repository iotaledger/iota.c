// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "sodium.h"

#include "core/models/payloads/transaction.h"

static byte_t addr1[ED25519_ADDRESS_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t addr2[ED25519_ADDRESS_BYTES] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t addr3[ED25519_ADDRESS_BYTES] = {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static byte_t tx_id0[TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t tx_id1[TRANSACTION_ID_BYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                              255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                              255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
static byte_t tx_id2[TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                              190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                              90,  172, 252, 142, 91,  179, 113, 2,   177, 58};

void test_tx_essence_serialization() {
  size_t essence_buf_len = 0;
  byte_t* essence_buf = NULL;
  transaction_essence_t* essence = tx_essence_new();
  TEST_ASSERT_NOT_NULL(essence);
  TEST_ASSERT_NULL(tx_essence_serialize(essence, &essence_buf_len));

  // add inputs
  TEST_ASSERT(tx_essence_add_input(essence, tx_id2, 0) == 0);
  TEST_ASSERT(tx_essence_add_input(essence, tx_id0, 1) == 0);
  TEST_ASSERT(tx_essence_add_input(essence, tx_id1, 2) == 0);
  TEST_ASSERT_EQUAL_UINT32(3, utxo_inputs_count(&essence->inputs));

  // add outputs
  TEST_ASSERT(tx_essence_add_output(essence, addr3, 3000) == 0);
  TEST_ASSERT(tx_essence_add_output(essence, addr1, 1000) == 0);
  TEST_ASSERT(tx_essence_add_output(essence, addr2, 2000) == 0);
  TEST_ASSERT_EQUAL_UINT32(3, utxo_outputs_count(&essence->outputs));

  tx_essence_print(essence);
  tx_essence_sort_input_output(essence);
  tx_essence_print(essence);
  essence_buf = tx_essence_serialize(essence, &essence_buf_len);
  TEST_ASSERT_NOT_NULL(essence_buf);
  dump_hex(essence_buf, essence_buf_len);

  free(essence_buf);

  tx_essence_free(essence);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_tx_essence_serialization);

  return UNITY_END();
}
