// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/restful/get_output.h"
#include "core/utils/macros.h"

static char const* const test_output_id = "a4679847ebafe542ab27988be47235d1ed8acc38b8874cb440344ebb5bcf653e0000";

void setUp(void) {}

void tearDown(void) {}

void test_get_output() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_output_t* res = get_output_response_new();

  // invalid output id
  TEST_ASSERT(get_output(&ctx, "123445", res) == -1);

  // output id not found from node
  TEST_ASSERT(get_output(&ctx, test_output_id, res) == 0);
  if (res->is_error) {
    printf("%s\n", res->u.error->msg);
  } else {
    dump_get_output_response(res, 0);
  }
  get_output_response_free(res);
}

void test_get_output_meta() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_output_t* res = get_output_response_new();

  // invalid output id
  TEST_ASSERT(get_output_meta(&ctx, "123445", res) == -1);

  // output id not found from node
  TEST_ASSERT(get_output_meta(&ctx, test_output_id, res) == 0);
  if (res->is_error) {
    printf("%s\n", res->u.error->msg);
  } else {
    dump_get_output_response(res, 0);
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
      "{\"messageId\":\"0x1b8a036d9decfec2e053fe69bc456a22c7a039590ae5a3c9e51dddadf19f83a5\",\"transactionId\":"
      "\"0x6c1249abb6fc07a3a8730db62564b10d8703a60d34debc6df545357cc11a9bfc\",\"outputIndex\":0,\"isSpent\":false,"
      "\"milestoneIndexBooked\":9,\"milestoneTimestampBooked\":1644570172,\"ledgerIndex\":13,\"output\":{\"type\":3,"
      "\"amount\":\"10000000\",\"nativeTokens\":[],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,"
      "\"pubKeyHash\":"
      "\"0x21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942\"}}],\"featureBlocks\":[]}}";

  res_output_t* out = get_output_response_new();
  int ret = deser_get_output(json_res, out);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(out->is_error);

  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  // validate message id
  TEST_ASSERT(hex_2_bin("1b8a036d9decfec2e053fe69bc456a22c7a039590ae5a3c9e51dddadf19f83a5", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.msg_id, IOTA_MESSAGE_ID_BYTES);
  // validate transaction id
  TEST_ASSERT(hex_2_bin("6c1249abb6fc07a3a8730db62564b10d8703a60d34debc6df545357cc11a9bfc", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.tx_id, IOTA_TRANSACTION_ID_BYTES);
  // validate output index
  TEST_ASSERT(out->u.data->meta.output_index == 0);
  // validate isSpent
  TEST_ASSERT_FALSE(out->u.data->meta.is_spent);
  // validate milestone index booked
  TEST_ASSERT(out->u.data->meta.ml_index_booked == 9);
  // validate milestone timestamp booked
  TEST_ASSERT(out->u.data->meta.ml_time_booked == 1644570172);
  // validate ledget index
  TEST_ASSERT(out->u.data->meta.ledger_index == 13);

  // validate output object
  TEST_ASSERT(out->u.data->output->output_type == OUTPUT_BASIC);
  output_basic_t* o = (output_basic_t*)out->u.data->output->output;
  TEST_ASSERT(o->amount == 10000000);
  TEST_ASSERT_NULL(o->native_tokens);
  TEST_ASSERT_NOT_NULL(o->unlock_conditions);
  TEST_ASSERT_NULL(o->feature_blocks);

  dump_get_output_response(out, 0);
  get_output_response_free(out);
}

void test_spent_output_response_deserialization() {
  char const* const json_res =
      "{\"messageId\": \"0x9cd745ef6800c8e8c80b09174ee4b250b3c43dfa62d7c6a4e61f848febf731a0\",\"transactionId\": "
      "\"0xfa0de75d225cca2799395e5fc340702fc7eac821d2bdd79911126f131ae097a2\",\"outputIndex\": 1,\"isSpent\": "
      "true,\"milestoneIndexSpent\": 1234570,\"milestoneTimestampSpent\": 1643207176,\"transactionIdSpent\": "
      "\"0xaf7579fb57746219561072c2cc0e4d0fbb8d493d075bd21bf25ae81a450c11ef\",\"milestoneIndexBooked\": "
      "1234567,\"milestoneTimestampBooked\": 1643207146,\"ledgerIndex\": 946704,\"output\": {\"type\": 3,\"amount\": "
      "\"1000\",\"nativeTokens\":[],\"unlockConditions\": [{\"type\": 0,\"address\": {\"type\": 0,\"pubKeyHash\": "
      "\"0x8eaf87ac1f52eb05f2c7c0c15502df990a228838dc37bd18de9503d69afd257d\"}}],\"featureBlocks\":[]}}";

  res_output_t* out = get_output_response_new();
  int ret = deser_get_output(json_res, out);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(out->is_error);

  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  // validate message id
  TEST_ASSERT(hex_2_bin("9cd745ef6800c8e8c80b09174ee4b250b3c43dfa62d7c6a4e61f848febf731a0", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.msg_id, IOTA_MESSAGE_ID_BYTES);
  // validate transaction id
  TEST_ASSERT(hex_2_bin("fa0de75d225cca2799395e5fc340702fc7eac821d2bdd79911126f131ae097a2", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.tx_id, IOTA_TRANSACTION_ID_BYTES);
  // validate output index
  TEST_ASSERT(out->u.data->meta.output_index == 1);
  // validate isSpent
  TEST_ASSERT_TRUE(out->u.data->meta.is_spent);
  // validate milestone index spent
  TEST_ASSERT(out->u.data->meta.ml_index_spent == 1234570);
  // validate milestone timestamp spent
  TEST_ASSERT(out->u.data->meta.ml_time_spent == 1643207176);
  // validate transaction id spent
  TEST_ASSERT(hex_2_bin("af7579fb57746219561072c2cc0e4d0fbb8d493d075bd21bf25ae81a450c11ef", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.tx_id_spent, IOTA_TRANSACTION_ID_BYTES);
  // validate milestone index booked
  TEST_ASSERT(out->u.data->meta.ml_index_booked == 1234567);
  // validate milestone timestamp booked
  TEST_ASSERT(out->u.data->meta.ml_time_booked == 1643207146);
  // validate ledget index
  TEST_ASSERT(out->u.data->meta.ledger_index == 946704);

  // validate output object
  TEST_ASSERT(out->u.data->output->output_type == OUTPUT_BASIC);
  output_basic_t* o = (output_basic_t*)out->u.data->output->output;
  TEST_ASSERT(o->amount == 1000);
  TEST_ASSERT_NULL(o->native_tokens);
  TEST_ASSERT_NOT_NULL(o->unlock_conditions);
  TEST_ASSERT_NULL(o->feature_blocks);

  dump_get_output_response(out, 0);
  get_output_response_free(out);
}

void test_output_metadata_response_deserialization() {
  char const* const json_res =
      "{\"messageId\":\"0x00a9b3ab3fb1c43c24f2af74d18f216af6a9f6e60d56c9a57e07b2d6f953d019\",\"transactionId\":"
      "\"0xa4679847ebafe542ab27988be47235d1ed8acc38b8874cb440344ebb5bcf653e\",\"outputIndex\":0,\"isSpent\":false,"
      "\"milestoneIndexBooked\":83,\"milestoneTimestampBooked\":1651051050,\"ledgerIndex\":2028}";

  res_output_t* out = get_output_response_new();
  int ret = deser_get_output(json_res, out);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(out->is_error);

  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  // validate message id
  TEST_ASSERT(hex_2_bin("00a9b3ab3fb1c43c24f2af74d18f216af6a9f6e60d56c9a57e07b2d6f953d019",
                        BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES), NULL, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.msg_id, IOTA_MESSAGE_ID_BYTES);
  // validate transaction id
  TEST_ASSERT(hex_2_bin("a4679847ebafe542ab27988be47235d1ed8acc38b8874cb440344ebb5bcf653e",
                        BIN_TO_HEX_STR_BYTES(IOTA_TRANSACTION_ID_BYTES), NULL, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, out->u.data->meta.tx_id, IOTA_TRANSACTION_ID_BYTES);
  // validate output index
  TEST_ASSERT(out->u.data->meta.output_index == 0);
  // validate isSpent
  TEST_ASSERT_FALSE(out->u.data->meta.is_spent);
  // validate milestone index booked
  TEST_ASSERT(out->u.data->meta.ml_index_booked == 83);
  // validate milestone timestamp booked
  TEST_ASSERT(out->u.data->meta.ml_time_booked == 1651051050);
  // validate ledget index
  TEST_ASSERT(out->u.data->meta.ledger_index == 2028);

  // validate output object
  TEST_ASSERT_NULL(out->u.data->output);

  dump_get_output_response(out, 0);
  get_output_response_free(out);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_response_error);
  RUN_TEST(test_output_response_deserialization);
  RUN_TEST(test_spent_output_response_deserialization);
  RUN_TEST(test_output_metadata_response_deserialization);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output);
  RUN_TEST(test_get_output_meta);
#endif
  return UNITY_END();
}
