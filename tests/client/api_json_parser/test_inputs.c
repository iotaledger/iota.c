// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/inputs.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_inputs() {
  char const *const json_res =
      "{\"inputs\":[{\"type\":0,\"transactionId\":\"b3e2d5466b68f7876e5647ada5dc6153bedd11182743dfde7b8e547cdd459d1e\","
      "\"transactionOutputIndex\":1},{\"type\":0,\"transactionId\":"
      "\"c6e89ba60e64a79d174ce04a87003cf681d06f8f016909b410479bef92bf6143\",\"transactionOutputIndex\":4}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  utxo_inputs_list_t *inputs = utxo_inputs_new();
  int result = json_inputs_deserialize(json_obj, &inputs);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(2, utxo_inputs_count(inputs));

  // check 1st transaction
  byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];
  hex_2_bin("b3e2d5466b68f7876e5647ada5dc6153bedd11182743dfde7b8e547cdd459d1e", IOTA_TRANSACTION_ID_HEX_BYTES, tx_id,
            IOTA_TRANSACTION_ID_BYTES);
  utxo_input_t *input = utxo_inputs_find_by_id(inputs, tx_id);
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_UINT16(0, input->input_type);
  TEST_ASSERT_EQUAL_UINT16(1, input->output_index);

  // check 2nd transaction
  hex_2_bin("c6e89ba60e64a79d174ce04a87003cf681d06f8f016909b410479bef92bf6143", IOTA_TRANSACTION_ID_HEX_BYTES, tx_id,
            IOTA_TRANSACTION_ID_BYTES);
  input = utxo_inputs_find_by_id(inputs, tx_id);
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_UINT16(0, input->input_type);
  TEST_ASSERT_EQUAL_UINT16(4, input->output_index);

  cJSON_Delete(json_obj);
  utxo_inputs_free(inputs);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_inputs);

  return UNITY_END();
}
