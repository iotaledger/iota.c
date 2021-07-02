// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/v1/get_output.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_output() {
  char const* const output_id = "1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0003";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_output_t res = {};
  // invalid output id
  TEST_ASSERT(get_output(&ctx, "123445", &res) == -1);

  // output id not found from node
  TEST_ASSERT(get_output(&ctx, output_id, &res) == 0);
  TEST_ASSERT(res.is_error == true);
  res_err_free(res.u.error);
}

void test_deser_response_error() {
  char const* const json_err1 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: output not found: "
      "1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0003: invalid parameter\"}}";

  res_output_t out = {};
  int ret = deser_get_output(json_err1, &out);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT(out.is_error == true);
  TEST_ASSERT_EQUAL_STRING(out.u.error->code, "400");
  TEST_ASSERT_EQUAL_STRING(out.u.error->msg,
                           "bad request, error: output not found: "
                           "1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0003: invalid parameter");
  res_err_free(out.u.error);
  out.u.error = NULL;
}

void test_deser_response() {
  char const* const json_res =
      "{\"data\":"
      "{\"messageId\":\"ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c\","
      "\"transactionId\":\"1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d\","
      "\"outputIndex\":3,\"isSpent\":false,"
      "\"output\":{\"type\":0,"
      "\"address\":{\"type\":1,"
      "\"address\":\"7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\"},"
      "\"amount\":1338263}"
      "}"
      "}";

  res_output_t out = {};
  int ret = deser_get_output(json_res, &out);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(out.is_error);
  TEST_ASSERT_EQUAL_MEMORY(out.u.output.msg_id, "ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c", 64);
  TEST_ASSERT_EQUAL_MEMORY(out.u.output.tx_id, "1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d", 64);
  TEST_ASSERT_EQUAL_INT(out.u.output.output_idx, 3);
  TEST_ASSERT_FALSE(out.u.output.is_spent);
  TEST_ASSERT_EQUAL_INT(0, out.u.output.output_type);
  TEST_ASSERT(out.u.output.amount == 1338263);
  TEST_ASSERT_EQUAL_INT(1, out.u.output.address_type);
  TEST_ASSERT_EQUAL_MEMORY(out.u.output.addr, "7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006", 64);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_response_error);
  RUN_TEST(test_deser_response);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output);
#endif
  return UNITY_END();
}