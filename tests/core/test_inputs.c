#include <stdio.h>

#include "core/models/inputs/utxo_input.h"
#include "sodium.h"
#include "unity/unity.h"

static byte_t id0[TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t id1[TRANSACTION_ID_BYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                           255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                           255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
static byte_t id2[TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39,  46, 190, 54,  49, 73,  171,
                                           165, 88,  139, 221, 25,  199, 90,  172, 252, 142, 91, 179, 113, 2,  177, 58};

void test_utxo_input() {
  utxo_input_t utxo_in = {0};
  utxo_inputs_t* list = utxo_inputs_new();
  TEST_ASSERT_NOT_NULL(list);

  utxo_in.output_index = 0;
  memcpy(&utxo_in.tx_id, id0, TRANSACTION_ID_BYTES);
  utxo_inputs_push(list, &utxo_in);
  TEST_ASSERT_EQUAL_UINT64(1, utxo_inputs_len(list));

  utxo_in.output_index = 1;
  memcpy(&utxo_in.tx_id, id1, TRANSACTION_ID_BYTES);
  utxo_inputs_push(list, &utxo_in);
  TEST_ASSERT_EQUAL_UINT64(2, utxo_inputs_len(list));

  for (int i = 2; i < 5; i++) {
    randombytes_buf((void* const)utxo_in.tx_id, TRANSACTION_ID_BYTES);
    utxo_in.output_index = i;
    utxo_inputs_push(list, &utxo_in);
  }
  TEST_ASSERT_EQUAL_UINT64(5, utxo_inputs_len(list));

  utxo_in.output_index = 5;
  memcpy(&utxo_in.tx_id, id2, TRANSACTION_ID_BYTES);
  utxo_inputs_push(list, &utxo_in);
  TEST_ASSERT_EQUAL_UINT64(6, utxo_inputs_len(list));

  utxo_input_t* expect = utxo_inputs_at(list, 0);
  TEST_ASSERT_EQUAL_UINT64(0, expect->output_index);
  TEST_ASSERT_EQUAL_MEMORY(expect->tx_id, id0, TRANSACTION_ID_BYTES);

  expect = utxo_inputs_at(list, utxo_inputs_len(list) - 1);
  TEST_ASSERT_EQUAL_UINT64(5, expect->output_index);
  TEST_ASSERT_EQUAL_MEMORY(expect->tx_id, id2, TRANSACTION_ID_BYTES);

  expect = utxo_inputs_at(list, utxo_inputs_len(list));
  TEST_ASSERT_NULL(expect);

  utxo_inputs_pop(list);
  TEST_ASSERT_EQUAL_UINT64(5, utxo_inputs_len(list));

  utxo_inputs_print(list);
  utxo_inputs_free(list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_utxo_input);

  return UNITY_END();
}