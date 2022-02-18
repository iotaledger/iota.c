// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/message.h"
#include "unity/unity.h"

static byte_t tx_id0[IOTA_TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t tx_id1[IOTA_TRANSACTION_ID_BYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                                   255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                                   255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
static byte_t tx_id2[IOTA_TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 2,   177, 58};
static byte_t tx_id3[IOTA_TRANSACTION_ID_BYTES] = {30,  49,  142, 249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  200, 73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 120, 110, 70};

void setUp(void) {}

void tearDown(void) {}

void test_utxo_input() {
  utxo_inputs_list_t* inputs = utxo_inputs_new();
  TEST_ASSERT_NULL(inputs);

  // print out an empty list
  utxo_inputs_print(inputs, 0);

  // get count of empty list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(inputs));

  // test for -1 if transaction id is null
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, NULL, 2, NULL) == -1);

  // test for -1 if index more than max_output_count
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id0, UINT8_MAX, NULL) == -1);

  // test for unknown input type
  TEST_ASSERT(utxo_inputs_add(&inputs, 1, tx_id0, 2, NULL) == -1);

  // add tx_id0 and index 1
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id0, 1, NULL) == 0);

  // Check if count of inputs is 1
  TEST_ASSERT_EQUAL_UINT16(1, utxo_inputs_count(inputs));

  // add two more tx IDs
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id1, 2, NULL) == 0);
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id2, 3, NULL) == 0);

  // Check if count of inputs is 3
  TEST_ASSERT_EQUAL_UINT16(3, utxo_inputs_count(inputs));

  // trying to add txn id that is already present in list but with non existing index
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id1, 4, NULL) == 0);

  // trying to add a new txn_id with output index that is present in list
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id3, 2, NULL) == 0);

  // trying to add txn_id and output index that is present in the list in the same input
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tx_id2, 3, NULL) == -1);

  // print utxo inputs list with 5 inputs
  utxo_inputs_print(inputs, 0);

  // find and validate transaction ID
  utxo_input_t* elm = utxo_inputs_find_by_id(inputs, tx_id1);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT_EQUAL_MEMORY(tx_id1, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);
  TEST_ASSERT(2 == elm->output_index);

  // find and validate index
  elm = utxo_inputs_find_by_index(inputs, 3);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(3 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id2, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // serialize input list and validate it
  size_t expected_serialized_len = utxo_inputs_serialize_len(inputs);
  TEST_ASSERT(expected_serialized_len != 0);
  byte_t* inputs_list_buf = malloc(expected_serialized_len);
  TEST_ASSERT_NOT_NULL(inputs_list_buf);

  // Test serialize with input NULL
  TEST_ASSERT(utxo_inputs_serialize(NULL, inputs_list_buf, expected_serialized_len) == 0);

  // Test serialize with insufficient buffer len
  TEST_ASSERT(utxo_inputs_serialize(inputs, inputs_list_buf, 1) == 0);

  // Test serialize
  TEST_ASSERT(utxo_inputs_serialize(inputs, inputs_list_buf, expected_serialized_len) == expected_serialized_len);

  // deserialize outputs list and validate it
  utxo_inputs_list_t* deser_inputs = utxo_inputs_deserialize(inputs_list_buf, 1);
  TEST_ASSERT_NULL(deser_inputs);  // expect deserialization fails
  deser_inputs = utxo_inputs_deserialize(inputs_list_buf, expected_serialized_len);
  TEST_ASSERT_NOT_NULL(deser_inputs);

  // Validate input count
  TEST_ASSERT_EQUAL_INT(5, utxo_inputs_count(deser_inputs));

  // find and validate index
  elm = utxo_inputs_find_by_index(deser_inputs, 3);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(3 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id2, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  utxo_inputs_free(deser_inputs);
  free(inputs_list_buf);
  utxo_inputs_free(inputs);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_utxo_input);

  return UNITY_END();
}
