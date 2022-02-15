// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/restful/get_outputs_id.h"
#include "ctype.h"

void setUp(void) {}

void tearDown(void) {}

void test_query_params() {
  char addr[] = "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  char const* const expected_query_str =
      "address=atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&pageSize=2&cursor="
      "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  // Check query string len with an empty list
  size_t query_str_len = get_outputs_query_str_len(list);
  TEST_ASSERT_EQUAL(0, query_str_len);
  char query_str[10];
  size_t ret = get_outputs_query_str(list, query_str, 10);
  TEST_ASSERT_EQUAL(0, ret);
  // Add address query parameter
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr) == 0);
  query_str_len = get_outputs_query_str_len(list);
  TEST_ASSERT_EQUAL(72, query_str_len);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  query_str_len = get_outputs_query_str_len(list);
  TEST_ASSERT_EQUAL(83, query_str_len);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  query_str_len = get_outputs_query_str_len(list);
  TEST_ASSERT_EQUAL(169, query_str_len);
  TEST_ASSERT_NOT_EQUAL(0, query_str_len);
  char* buffer = malloc(query_str_len + 1);
  TEST_ASSERT_NOT_NULL(buffer);
  ret = get_outputs_query_str(list, buffer, query_str_len + 1);
  TEST_ASSERT_NOT_EQUAL(0, ret);
  TEST_ASSERT_EQUAL(ret, query_str_len + 1);
  printf("Query String : %s\n", buffer);
  TEST_ASSERT_EQUAL_STRING(buffer, expected_query_str);
  free(buffer);
  outputs_query_list_free(list);
}

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
  TEST_ASSERT_EQUAL_STRING("1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005",
                           res_outputs_output_id(res, 0));
  TEST_ASSERT_EQUAL_STRING("ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010",
                           res_outputs_output_id(res, 1));
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
  TEST_ASSERT_EQUAL_STRING("62020d37c936725634911feb5a7685e715dcef50cb2b997812567021e09181ab7e67d9020100.2",
                           res->u.output_ids->cursor);
  TEST_ASSERT_EQUAL_STRING("1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005",
                           res_outputs_output_id(res, 0));
  TEST_ASSERT_EQUAL_STRING("ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010",
                           res_outputs_output_id(res, 1));
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

void test_get_output_ids() {
  char addr[] = "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk";
  char dust_ret_addr[] = "atoi1qpszqzadsym6wpppd6z037dvlejmjuke7s24hm95s9fg9vpua7vluehe53e";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length =
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk3efg256shxtb7812b";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  char const* const tag = "4ec7f23a";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Tests for NULL cases
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_id(NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_id(NULL, NULL, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Test for /outputs without query params
  TEST_ASSERT_EQUAL_INT(0, get_outputs_id(&ctx, NULL, res));
  TEST_ASSERT(res->is_error == false);

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Test invalid address len
  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_outputs_id(&ctx, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  outputs_query_list_free(list);
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);

  // Test invalid address
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_outputs_id(&ctx, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  outputs_query_list_free(list);
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr) == 0);
  int ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_DUST_RET, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_DUST_RET, "false") == 0);
  ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_DUST_RET_ADDR, dust_ret_addr) == 0);
  ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_SENDER, addr) == 0);
  ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TAG, tag) == 0);
  ret = get_outputs_id(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  outputs_query_list_free(list);
  res_outputs_free(res);
}

void test_get_nft_output() {
  char addr_nft[] = "atoi1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwn";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "atoi1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwn426sdvcxjxsb628726zxsb";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_nft) == 0);
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(NULL, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(&ctx, list, NULL));

  //=====Test for nft outputs without query params
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, NULL, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test invalid address len=====
  outputs_query_list_free(list);
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, list, res));
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test invalid nft address=====
  outputs_query_list_free(list);
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, list, res));
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test valid nft address=====
  outputs_query_list_free(list);
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_nft) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test dust return condition=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  // TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_DUST_RET, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_DUST_RET, "false") == 0);
  int ret = get_nft_outputs(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test dust return address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_DUST_RET_ADDR, addr_nft) == 0);
  ret = get_nft_outputs(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test sender=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_SENDER, addr_nft) == 0);
  ret = get_nft_outputs(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test Tag=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TAG, "4ec7f23a") == 0);
  ret = get_nft_outputs(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test Page Size=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  ret = get_nft_outputs(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test Cursor=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  ret = get_nft_outputs(&ctx, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  outputs_query_list_free(list);
  res_outputs_free(res);
}

void test_get_alias_outputs() {
  char addr_alias[] = "atoi1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwn";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "atoi1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwnfgs527svshx5275";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(NULL, NULL, res));

  // Test for case without query params
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, NULL, res));
  TEST_ASSERT(res->is_error == false);

  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(&ctx, list, NULL));

  //=====Test invalid address len=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test invalid alias address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr_hex_invalid) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test valid alias address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test issuer address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ISSUER, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test Page Size=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test Cursor=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  outputs_query_list_free(list);
}

void test_get_foundry_outputs() {
  char addr_alias[] = "atoi1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwn";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "atoi1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwndsjsh5262725sgnb";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(NULL, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(&ctx, list, NULL));

  //=====Test without query params=====
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, NULL, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test invalid address len=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test invalid alias address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test valid alias address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test page size=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test Cursor=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, list, res));
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  outputs_query_list_free(list);
}

void test_get_output_ids_from_nft_id() {
  char nft_id[] = "efdc112efe262b304bcf379b26c31bad029f61de";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "efdc112efe262b304bcf379b26c31bad029f61def346ab52ef";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(NULL, nft_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, nft_id, NULL));

  //=====Test invalid id len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid nft id=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_nft_id(&ctx, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  /* FIXME : Test with a valif nft id
  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid nft id=====
  int ret = get_outputs_from_nft_id(&ctx, nft_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);
  */
  res_outputs_free(res);
}

void test_get_output_ids_from_alias_id() {
  char alias_id[] = "23dc192ede262b3f4bce379b26c31bad029f62fe";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "23dc192ede262b3f4bce379b26c31bad029f62fe246ec78";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(NULL, alias_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, alias_id, NULL));

  //=====Test invalid id len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias id=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_alias_id(&ctx, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }
  /* FIXME : Test with a valid alias id
  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias id=====
  int ret = get_outputs_from_alias_id(&ctx, alias_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);
  */

  res_outputs_free(res);
}

void test_get_output_ids_from_foundry_id() {
  char foundry_id[] = "56ec192ede262b3f4bce379b26c31bad029f63bc23ef56ee48cf";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "56ec192ede262b3f4bce379b26c31bad029f63bc23ef56ee48cf257efc375";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(NULL, foundry_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, foundry_id, NULL));

  //=====Test invalid id len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid foundry id=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_foundry_id(&ctx, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  /* FIXME : test with a valid foundry ID
  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid foundry id=====
  int ret = get_outputs_from_foundry_id(&ctx, foundry_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);
  */

  res_outputs_free(res);
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_query_params);
  RUN_TEST(test_deser_outputs);
  RUN_TEST(test_deser_outputs_err);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_output_ids);
  RUN_TEST(test_get_nft_output);
  RUN_TEST(test_get_alias_outputs);
  RUN_TEST(test_get_foundry_outputs);
  RUN_TEST(test_get_output_ids_from_nft_id);
  RUN_TEST(test_get_output_ids_from_alias_id);
  RUN_TEST(test_get_output_ids_from_foundry_id);
#endif

  return UNITY_END();
}
