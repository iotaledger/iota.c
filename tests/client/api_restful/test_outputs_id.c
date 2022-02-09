// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/restful/get_outputs_id.h"
#include "ctype.h"

void setUp(void) {}

void tearDown(void) {}

void test_deser_outputs() {
  // empty output ids
  char const* const data_empty = "{\"pageSize\":2,\"items\":[],\"ledgerIndex\":837834}";

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs(data_empty, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT(res->u.output_ids->page_size == 2);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 0);
  TEST_ASSERT(res->u.output_ids->ledger_idx == 837834);
  res_outputs_free(res);
  res = NULL;

  // with output ids and without cursor
  char const* const data_1 =
      "{\"pageSize\":2,\"items\":[\"1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005\","
      "\"ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010\"],\"ledgerIndex\":837834}";
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs(data_1, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT(res->u.output_ids->page_size == 2);
  TEST_ASSERT(res_outputs_output_id_count(res) == 2);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 2);
  TEST_ASSERT_EQUAL_MEMORY("1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005",
                           res_outputs_output_id(res, 0), 69);
  TEST_ASSERT_EQUAL_MEMORY("ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010",
                           res_outputs_output_id(res, 1), 69);
  TEST_ASSERT(res->u.output_ids->ledger_idx == 837834);
  res_outputs_free(res);
  res = NULL;

  // with output ids and without cursor
  char const* const data_2 =
      "{\"pageSize\":2,\"cursor\":\"62020d37c936725634911feb5a7685e715dcef50cb2b997812567021e09181ab7e67d9020100.2\","
      "\"items\":[\"1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005\","
      "\"ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010\"],\"ledgerIndex\":837834}";
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_outputs(data_2, res) == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT(res->u.output_ids->page_size == 2);
  TEST_ASSERT(res_outputs_output_id_count(res) == 2);
  TEST_ASSERT(utarray_len(res->u.output_ids->outputs) == 2);
  TEST_ASSERT_EQUAL_MEMORY("62020d37c936725634911feb5a7685e715dcef50cb2b997812567021e09181ab7e67d9020100.2",
                           res->u.output_ids->cursor, 78);
  TEST_ASSERT_EQUAL_MEMORY("1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005",
                           res_outputs_output_id(res, 0), 69);
  TEST_ASSERT_EQUAL_MEMORY("ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010",
                           res_outputs_output_id(res, 1), 69);
  TEST_ASSERT(res->u.output_ids->ledger_idx == 837834);
  res_outputs_free(res);
  res = NULL;
}

void test_deser_outputs_err() {
  char const* const err_400 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: invalid address length: "
      "017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006: invalid parameter\"}}";

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  int ret = deser_outputs(err_400, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res->u.error->code, "400");
  TEST_ASSERT_EQUAL_STRING(res->u.error->msg,
                           "bad request, error: invalid address length: "
                           "017ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006: invalid parameter");

  res_outputs_free(res);
}

void test_get_output_ids_from_address() {
  char addr[] = "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length =
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Tests for NULL cases
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_address(NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_address(NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_address(&ctx, NULL, res));

  // Test invalid address len
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_address(&ctx, addr_hex_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Test invalid address
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_address(&ctx, addr_hex_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  int ret = get_outputs_from_address(&ctx, addr, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_nft_address() {
  char addr_nft[] = "efdc112efe262b304bcf379b26c31bad029f616e";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_address(NULL, addr_nft, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_address(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_address(&ctx, addr_nft, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_address(&ctx, addr_hex_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid nft address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_nft_address(&ctx, addr_hex_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid nft address=====
  int ret = get_outputs_from_nft_address(&ctx, addr_nft, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_alias_address() {
  char addr_alias[] = "efdc112efe262b304bcf379b26c31bad029f616e";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(NULL, addr_alias, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(&ctx, addr_alias, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_address(&ctx, addr_hex_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_alias_address(&ctx, addr_hex_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias address=====
  int ret = get_outputs_from_alias_address(&ctx, addr_alias, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_foundry_address() {
  char addr_foundry[] = "c2dc1125fe272b3048cf399b21c31bad029f61fe";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_address(NULL, addr_foundry, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_address(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_address(&ctx, addr_foundry, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_address(&ctx, addr_hex_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_foundry_address(&ctx, addr_hex_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias address=====
  int ret = get_outputs_from_foundry_address(&ctx, addr_foundry, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_nft_id() {
  char nft_id[] = "efdc112efe262b304bcf379b26c31bad029f61de";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(NULL, nft_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, nft_id, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_nft_id(&ctx, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias address=====
  int ret = get_outputs_from_nft_id(&ctx, nft_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_alias_id() {
  char alias_id[] = "23dc192ede262b3f4bce379b26c31bad029f62fe";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(NULL, alias_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, alias_id, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_alias_id(&ctx, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias address=====
  int ret = get_outputs_from_alias_id(&ctx, alias_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_foundry_id() {
  char foundry_id[] = "56ec192ede262b3f4bce379b26c31bad029f63bc";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(NULL, foundry_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, foundry_id, NULL));

  //=====Test invalid address len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias address=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_foundry_id(&ctx, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias address=====
  int ret = get_outputs_from_foundry_id(&ctx, foundry_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_outputs);
  RUN_TEST(test_deser_outputs_err);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output_ids_from_address);
  RUN_TEST(test_get_output_ids_from_nft_address);
  RUN_TEST(test_get_output_ids_from_alias_address);
  RUN_TEST(test_get_output_ids_from_foundry_address);
  RUN_TEST(test_get_output_ids_from_nft_id);
  RUN_TEST(test_get_output_ids_from_alias_id);
  RUN_TEST(test_get_output_ids_from_foundry_id);
#endif

  return UNITY_END();
}
