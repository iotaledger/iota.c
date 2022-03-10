// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/restful/get_output.h"
#include "core/utils/macros.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_output() {
  char const* const output_id = "6c1249abb6fc07a3a8730db62564b10d8703a60d34debc6df545357cc11a9bfc0000";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_output_t* res = get_output_response_new();

  // invalid output id
  TEST_ASSERT(get_output(&ctx, "123445", res) == -1);

  // output id not found from node
  TEST_ASSERT(get_output(&ctx, output_id, res) == 0);
  if (res->is_error) {
    printf("%s\n", res->u.error->msg);
  } else {
    dump_output_response(res);
  }
  get_output_response_free(res);
}

void test_deser_response_error() {
  char const* const json_err1 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: output not found: "
      "1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0003: invalid parameter\"}}";

  res_output_t* res = get_output_response_new();
  int ret = deser_get_output(json_err1, res);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT(res->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res->u.error->code, "400");
  TEST_ASSERT_EQUAL_STRING(res->u.error->msg,
                           "bad request, error: output not found: "
                           "1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0003: invalid parameter");
  get_output_response_free(res);
}

void test_output_response_deserialization() {
  char const* const json_res =
      "{\"messageId\":\"1b8a036d9decfec2e053fe69bc456a22c7a039590ae5a3c9e51dddadf19f83a5\",\"transactionId\":"
      "\"6c1249abb6fc07a3a8730db62564b10d8703a60d34debc6df545357cc11a9bfc\",\"outputIndex\":0,\"isSpent\":false,"
      "\"milestoneIndexBooked\":9,\"milestoneTimestampBooked\":1644570172,\"ledgerIndex\":13,\"output\":{\"type\":3,"
      "\"amount\":10000000,\"nativeTokens\":[],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,"
      "\"pubKeyHash\":"
      "\"21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942\"}}],\"featureBlocks\":[]}}";

  res_output_t* out = get_output_response_new();
  int ret = deser_get_output(json_res, out);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(out->is_error);

  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  // validate message id
  TEST_ASSERT(
      hex_2_bin("1b8a036d9decfec2e053fe69bc456a22c7a039590ae5a3c9e51dddadf19f83a5", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->msg_id, IOTA_MESSAGE_ID_BYTES);
  // validate transaction id
  TEST_ASSERT(
      hex_2_bin("6c1249abb6fc07a3a8730db62564b10d8703a60d34debc6df545357cc11a9bfc", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->tx_id, IOTA_TRANSACTION_ID_BYTES);
  // validate output index
  TEST_ASSERT(out->u.data->output_index == 0);
  // validate isSpent
  TEST_ASSERT_FALSE(out->u.data->is_spent);
  // validate milestone index booked
  TEST_ASSERT(out->u.data->ml_index_booked == 9);
  // validate milestone timestamp booked
  TEST_ASSERT(out->u.data->ml_time_booked == 1644570172);
  // validate ledget index
  TEST_ASSERT(out->u.data->ledger_index == 13);

  // validate output object
  TEST_ASSERT(out->u.data->output->output_type == OUTPUT_BASIC);
  output_basic_t* o = (output_basic_t*)out->u.data->output->output;
  TEST_ASSERT(o->amount == 10000000);
  TEST_ASSERT_NULL(o->native_tokens);
  TEST_ASSERT_NOT_NULL(o->unlock_conditions);
  TEST_ASSERT_NULL(o->feature_blocks);

  dump_output_response(out);
  get_output_response_free(out);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_response_error);
  RUN_TEST(test_output_response_deserialization);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output);
#endif
  return UNITY_END();
}
