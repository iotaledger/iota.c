// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/inputs.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

char const *const json_empty = "{\"inputs\":[]}";
char const *const json_example1 =
    "{\"inputs\":[{\"type\":0,\"transactionId\":\"b3e2d5466b68f7876e5647ada5dc6153bedd11182743dfde7b8e547cdd459d1e\","
    "\"transactionOutputIndex\":1},{\"type\":0,\"transactionId\":"
    "\"c6e89ba60e64a79d174ce04a87003cf681d06f8f016909b410479bef92bf6143\",\"transactionOutputIndex\":4}]}";
byte_t tmp_tx_id[IOTA_TRANSACTION_ID_BYTES];

void test_deserialize_inputs_empty() {
  cJSON *json_obj = cJSON_Parse(json_empty);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch inputs array
  cJSON *inputs_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_INPUTS);
  TEST_ASSERT_TRUE(cJSON_IsArray(inputs_data));

  // deserialize inputs
  utxo_inputs_list_t *inputs = utxo_inputs_new();
  int result = json_inputs_deserialize(inputs_data, &inputs);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(inputs));

  cJSON_Delete(json_obj);
  utxo_inputs_free(inputs);
}

void test_deserialize_inputs() {
  cJSON *json_obj = cJSON_Parse(json_example1);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch inputs array
  cJSON *inputs_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_INPUTS);
  TEST_ASSERT_TRUE(cJSON_IsArray(inputs_data));

  // deserialize inputs
  utxo_inputs_list_t *inputs = utxo_inputs_new();
  int result = json_inputs_deserialize(inputs_data, &inputs);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(2, utxo_inputs_count(inputs));

  // check 1st transaction
  hex_2_bin("b3e2d5466b68f7876e5647ada5dc6153bedd11182743dfde7b8e547cdd459d1e", IOTA_TRANSACTION_ID_HEX_BYTES,
            tmp_tx_id, IOTA_TRANSACTION_ID_BYTES);
  utxo_input_t *input = utxo_inputs_find_by_id(inputs, tmp_tx_id);
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_UINT16(0, input->input_type);
  TEST_ASSERT_EQUAL_UINT16(1, input->output_index);

  // check 2nd transaction
  hex_2_bin("c6e89ba60e64a79d174ce04a87003cf681d06f8f016909b410479bef92bf6143", IOTA_TRANSACTION_ID_HEX_BYTES,
            tmp_tx_id, IOTA_TRANSACTION_ID_BYTES);
  input = utxo_inputs_find_by_id(inputs, tmp_tx_id);
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_UINT16(0, input->input_type);
  TEST_ASSERT_EQUAL_UINT16(4, input->output_index);

  // print transaction inputs
  utxo_inputs_print(inputs, 0);

  cJSON_Delete(json_obj);
  utxo_inputs_free(inputs);
}

void test_serialize_inputs_empty() {
  utxo_inputs_list_t *inputs = utxo_inputs_new();
  TEST_ASSERT_NULL(inputs);

  cJSON *input_data = json_inputs_serialize(inputs);
  TEST_ASSERT_NOT_NULL(input_data);

  // add data to input array
  cJSON *inputs_obj = cJSON_CreateObject();
  cJSON_AddItemToObject(inputs_obj, JSON_KEY_INPUTS, input_data);

  // validate json string
  char *json_str = cJSON_PrintUnformatted(inputs_obj);
  TEST_ASSERT_NOT_NULL(json_str);
  TEST_ASSERT_EQUAL_STRING(json_str, json_empty);

  free(json_str);
  cJSON_Delete(inputs_obj);
  utxo_inputs_free(inputs);
}

void test_serialize_inputs() {
  utxo_inputs_list_t *inputs = utxo_inputs_new();
  // add 1st tx
  hex_2_bin("b3e2d5466b68f7876e5647ada5dc6153bedd11182743dfde7b8e547cdd459d1e", IOTA_TRANSACTION_ID_HEX_BYTES,
            tmp_tx_id, IOTA_TRANSACTION_ID_BYTES);
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tmp_tx_id, 1) == 0);
  // add 2nd tx
  hex_2_bin("c6e89ba60e64a79d174ce04a87003cf681d06f8f016909b410479bef92bf6143", IOTA_TRANSACTION_ID_HEX_BYTES,
            tmp_tx_id, IOTA_TRANSACTION_ID_BYTES);
  TEST_ASSERT(utxo_inputs_add(&inputs, 0, tmp_tx_id, 4) == 0);

  // serialize input data
  cJSON *input_data = json_inputs_serialize(inputs);
  TEST_ASSERT_NOT_NULL(input_data);

  // add data to input array
  cJSON *inputs_obj = cJSON_CreateObject();
  cJSON_AddItemToObject(inputs_obj, JSON_KEY_INPUTS, input_data);

  char *json_str = cJSON_PrintUnformatted(inputs_obj);
  TEST_ASSERT_NOT_NULL(json_str);

  // FIXME, use lower case hex string on both node and client.
  // TEST_ASSERT_EQUAL_STRING(json_str, json_example1);

  free(json_str);
  cJSON_Delete(inputs_obj);
  utxo_inputs_free(inputs);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deserialize_inputs_empty);
  RUN_TEST(test_deserialize_inputs);
  RUN_TEST(test_serialize_inputs_empty);
  RUN_TEST(test_serialize_inputs);

  return UNITY_END();
}
