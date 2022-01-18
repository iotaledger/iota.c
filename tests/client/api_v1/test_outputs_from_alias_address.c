// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/v1/get_outputs_from_alias_address.h"
#include "test_config.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_deserialize_outputs() {
  //=====Test empty output ids=====
  char const* const data_empty = "{\"data\":{\"maxResults\":1000,\"count\":0,\"outputIds\":[],\"ledgerIndex\":83783}}";

  res_outputs_alias_address_t* res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs_from_alias_address(data_empty, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT(res->u.output_ids->max_results == 1000);
  TEST_ASSERT(res->u.output_ids->count == 0);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 0);
  TEST_ASSERT(res->u.output_ids->ledger_idx == 83783);
  res_outputs_alias_address_free(res);

  //=====Test with output ids=====
  char const* const data_1 =
      "{\"data\":{\"maxResults\":1000,\"count\":2,"
      "\"outputIds\":[\"1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005\","
      "\"ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010\"],\"ledgerIndex\":837834}}";
  res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs_from_alias_address(data_1, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT(res->u.output_ids->max_results == 1000);
  TEST_ASSERT(res_outputs_alias_address_output_id_count(res) == 2);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 2);
  TEST_ASSERT_EQUAL_MEMORY("1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005",
                           res_outputs_alias_address_output_id(res, 0), 69);
  TEST_ASSERT_EQUAL_MEMORY("ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010",
                           res_outputs_alias_address_output_id(res, 1), 69);
  TEST_ASSERT(res->u.output_ids->ledger_idx == 837834);
  res_outputs_alias_address_free(res);
}

void test_deserialize_outputs_err() {
  //=====Test too small Alias address=====
  char const* const small_addr_err_400 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: invalid address length: "
      "efdc112efe262b304bcf379b26c31bad029f616: invalid parameter\"}}";

  res_outputs_alias_address_t* res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);
  int ret = deser_outputs_from_alias_address(small_addr_err_400, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res->u.error->code, "400");
  TEST_ASSERT_EQUAL_STRING(res->u.error->msg,
                           "bad request, error: invalid address length: "
                           "efdc112efe262b304bcf379b26c31bad029f616: invalid parameter");
  res_outputs_alias_address_free(res);

  //=====Test too big Alias address=====
  char const* const big_addr_err_400 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: invalid address length: "
      "efdc112efe262b304bcf379b26c31bad029f61623: invalid parameter\"}}";

  res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);
  ret = deser_outputs_from_alias_address(big_addr_err_400, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res->u.error->code, "400");
  TEST_ASSERT_EQUAL_STRING(res->u.error->msg,
                           "bad request, error: invalid address length: "
                           "efdc112efe262b304bcf379b26c31bad029f61623: invalid parameter");
  res_outputs_alias_address_free(res);
}

void test_get_output_ids() {
  char addr_alias[] = "efdc112efe262b304bcf379b26c31bad029f616e";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_alias_address_t* res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(NULL, addr_alias, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(&ctx, addr_alias, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(&ctx, addr_hex_invalid_length, res));

  // Re initializing res
  res_outputs_alias_address_free(res);
  res = NULL;
  res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_alias_address(&ctx, addr_hex_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_alias_address_free(res);
  res = NULL;
  res = res_outputs_alias_address_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias address=====
  int ret = get_outputs_from_alias_address(&ctx, addr_alias, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT(res->u.output_ids->max_results == 1000);

  res_outputs_alias_address_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deserialize_outputs);
  RUN_TEST(test_deserialize_outputs_err);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output_ids);
#endif

  return UNITY_END();
}
