// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/v1/get_outputs_from_address.h"

void setUp(void) {}

void tearDown(void) {}

void test_deser_outputs() {
  // empty output ids
  char const* const data_empty =
      "{\"data\":{\"address\":\"017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f0\",\"maxResults\":1000,"
      "\"count\":0,\"outputIds\":[]}}";

  res_outputs_address_t* res = res_outputs_address_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs_from_address(data_empty, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT_EQUAL_MEMORY("017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f0",
                           res->u.output_ids->address, sizeof(res->u.output_ids->address));
  TEST_ASSERT(res->u.output_ids->max_results == 1000);
  TEST_ASSERT(res->u.output_ids->count == 0);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 0);
  res_outputs_address_free(res);
  res = NULL;

  // with output ids
  char const* const data_1 =
      "{\"data\":{\"address\":\"7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\",\"maxResults\":1000,"
      "\"count\":2,\"outputIds\":[\"1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005\","
      "\"ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010\"]}}";
  res = res_outputs_address_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs_from_address(data_1, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT_EQUAL_MEMORY("7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006",
                           res->u.output_ids->address, sizeof(res->u.output_ids->address));
  TEST_ASSERT(res->u.output_ids->max_results == 1000);
  TEST_ASSERT(res_outputs_address_output_id_count(res) == 2);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 2);
  TEST_ASSERT_EQUAL_MEMORY("1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005",
                           res_outputs_address_output_id(res, 0), 69);
  TEST_ASSERT_EQUAL_MEMORY("ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010",
                           res_outputs_address_output_id(res, 1), 69);
  res_outputs_address_free(res);
  res = NULL;
}

void test_deser_outputs_err() {
  char const* const err_400 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: invalid address length: "
      "017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006: invalid parameter\"}}";

  res_outputs_address_t* res = res_outputs_address_new();
  TEST_ASSERT_NOT_NULL(res);
  int ret = deser_outputs_from_address(err_400, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res->u.error->code, "400");
  TEST_ASSERT_EQUAL_STRING(res->u.error->msg,
                           "bad request, error: invalid address length: "
                           "017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006: invalid parameter");

  res_outputs_address_free(res);
}

void test_get_output_ids() {
  char addr1[] = "017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f0";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_address_t* res = res_outputs_address_new();
  TEST_ASSERT_NOT_NULL(res);
  int ret = get_outputs_from_address(&ctx, addr1, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT_EQUAL_STRING(addr1, res->u.output_ids->address);
  res_outputs_address_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_outputs);
  RUN_TEST(test_deser_outputs_err);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output_ids);
#endif

  return UNITY_END();
}