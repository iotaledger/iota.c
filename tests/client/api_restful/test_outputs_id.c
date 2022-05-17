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
  char addr_alias[] = "rms1qzc7h2etq6ph4ssgpls6lucg9m84jrtngrvewsp8gjv6y5h4tth9xnas62c";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  char const* const expected_query_str =
      "address=atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&aliasAddress="
      "rms1qzc7h2etq6ph4ssgpls6lucg9m84jrtngrvewsp8gjv6y5h4tth9xnas62c&hasNativeTokens=true&minNativeTokenCount=2&"
      "maxNativeTokenCount=5&hasStorageReturnCondition=true&storageReturnAddress="
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&hasTimelockCondition=true&timelockedBefore="
      "1643383242&timelockedAfter=1643383242&timelockedBeforeMilestone=1000&timelockedAfterMilestone=1000&"
      "hasExpirationCondition=false&expiresBefore=1643383242&expiresAfter=1643383242&expiresBeforeMilestone=2000&"
      "expiresAfterMilestone=2200&expirationReturnAddress="
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&sender="
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&tag=0x4ec7f23&createdBefore=1643383242&"
      "createdAfter=1643383242&pageSize=2&cursor="
      "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2&stateController="
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&governor="
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk&issuer="
      "atoi1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk";
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
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ALIAS_ADDRESS, addr_alias) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_NATIVE_TOKENS, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_MIN_NATIVE_TOKENS, "2") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_MAX_NATIVE_TOKENS, "5") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_STORAGE_RET, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STORAGE_RET_ADDR, addr) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_TIMELOCK, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TIMELOCKED_BEFORE, "1643383242") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TIMELOCKED_AFTER, "1643383242") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TIMELOCKED_BEFORE_MS, "1000") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TIMELOCKED_AFTER_MS, "1000") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_EXP_COND, "false") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_EXPIRES_BEFORE, "1643383242") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_EXPIRES_AFTER, "1643383242") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_EXPIRES_BEFORE_MS, "2000") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_EXPIRES_AFTER_MS, "2200") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_EXP_RETURN_ADDR, addr) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_SENDER, addr) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TAG, "4ec7f23") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CREATED_BEFORE, "1643383242") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CREATED_AFTER, "1643383242") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_GOV, addr) == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ISSUER, addr) == 0);
  query_str_len = get_outputs_query_str_len(list);
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
      "{\"pageSize\":2,\"items\":[\"0x1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005\","
      "\"0xed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010\"],\"ledgerIndex\":837834}";
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
      "{\"pageSize\":2,\"cursor\":\"0x62020d37c936725634911feb5a7685e715dcef50cb2b997812567021e09181ab7e67d9020100.2\","
      "\"items\":[\"0x1c6943b0487c92fd057d4d22ad844cc37ee27fe6fbe88e5ff0d20b2233f75b9d0005\","
      "\"0xed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c0010\"],\"ledgerIndex\":837834}";
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

void test_get_basic_outputs() {
  char addr[] = "rms1qq7fpfau73mg0936yv2ye80e2urauqlz5m98qhjh6re0jsqdngvg52lqe5l";
  char storage_ret_addr[] = "rms1qq7fpfau73mg0936yv2ye80e2urauqlz5m98qhjh6re0jsqdngvg52lqe5l";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length =
      "rms1qpl4a3k3dep7qmw4tdq3pss6ld40jr5yhaq4fjakxgmdgk238j5hzsk2xsk3efg256shxtb7812b";
  char const* const cursor = "627c304462ebbb56532393d53a6ae55893cb6109708e1eea5d2e5c3d5e8bafc7486e3d6e0000.2";
  char const* const tag = "4ec7f23a";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Tests for NULL cases
  TEST_ASSERT_EQUAL_INT(-1, get_basic_outputs(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_basic_outputs(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_basic_outputs(NULL, INDEXER_API_PATH, NULL, res));

  // Test unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_basic_outputs(&ctx, "/indexer/x2", NULL, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // Test for basic outputs without query params
  TEST_ASSERT_EQUAL_INT(0, get_basic_outputs(&ctx, INDEXER_API_PATH, NULL, res));
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
  TEST_ASSERT_EQUAL_INT(0, get_basic_outputs(&ctx, INDEXER_API_PATH, list, res));
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
  TEST_ASSERT_EQUAL_INT(0, get_basic_outputs(&ctx, INDEXER_API_PATH, list, res));
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
  int ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  // TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_STORAGE_RET, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_STORAGE_RET, "false") == 0);
  ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STORAGE_RET_ADDR, storage_ret_addr) == 0);
  ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_SENDER, addr) == 0);
  ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TAG, tag) == 0);
  ret = get_basic_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  outputs_query_list_free(list);
  res_outputs_free(res);
}

void test_get_nft_outputs() {
  char addr_nft[] = "rms1qzazzswdkdmslc5pvjxr896d8ggw8c8d4a3j2spd32nk4vfjcxf4zytd2qn";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "rms1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwn426sdvcxjxsb628726zxsb";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_nft) == 0);
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(NULL, NULL, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(NULL, INDEXER_API_PATH, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(&ctx, INDEXER_API_PATH, list, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(&ctx, NULL, list, res));

  //=====Test for nft outputs without query params
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, INDEXER_API_PATH, NULL, res));
  TEST_ASSERT(res->is_error == false);

  // Test for unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_nft_outputs(&ctx, "/indexer/x2", list, res));

  //=====Test invalid address len=====
  outputs_query_list_free(list);
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ADDRESS, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, INDEXER_API_PATH, list, res));
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
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, INDEXER_API_PATH, list, res));
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
  TEST_ASSERT_EQUAL_INT(0, get_nft_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test storage return condition=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  // TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_STORAGE_RET, "true") == 0);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_HAS_STORAGE_RET, "false") == 0);
  int ret = get_nft_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test storage return address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STORAGE_RET_ADDR, addr_nft) == 0);
  ret = get_nft_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test sender=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_SENDER, addr_nft) == 0);
  ret = get_nft_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test Tag=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_TAG, "4ec7f23a") == 0);
  ret = get_nft_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test Page Size=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  ret = get_nft_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  //=====Test Cursor=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  ret = get_nft_outputs(&ctx, INDEXER_API_PATH, list, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  outputs_query_list_free(list);
  res_outputs_free(res);
}

void test_get_alias_outputs() {
  char addr_alias[] = "rms1qzc7h2etq6ph4ssgpls6lucg9m84jrtngrvewsp8gjv6y5h4tth9xnas62c";
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "rms1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwnfgs527svshx5275";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(NULL, NULL, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(NULL, INDEXER_API_PATH, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(&ctx, INDEXER_API_PATH, list, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(&ctx, NULL, list, res));

  // Test for case without query params
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, NULL, res));
  TEST_ASSERT(res->is_error == false);

  // Test unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(&ctx, "indexer/v2", list, res));

  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(-1, get_alias_outputs(&ctx, INDEXER_API_PATH, list, NULL));

  //=====Test invalid address len=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_STATE_CTRL, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, list, res));
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
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, list, res));
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
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test issuer address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ISSUER, addr_alias) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test Page Size=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test Cursor=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_alias_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  outputs_query_list_free(list);
}

void test_get_foundry_outputs() {
  byte_t output_id[] = "eb962eb4e400b5f0a5534255a721ffcd7b";
  address_t addr_alias;
  alias_address_from_output(output_id, sizeof(output_id), &addr_alias);
  char bech32_alias[65] = {};
  address_to_bech32(&addr_alias, "rms", bech32_alias, sizeof(bech32_alias));
  char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const addr_hex_invalid_length = "rms1zpk6m4x7m2t6k5pvgs0yd2nqelfaz09ueyyv6fwndsjsh5262725sgnb";
  char const* const cursor = "6209d527453cf2b9896146f13fbef94f66883d5e4bfe5600399e9328655fe0850fd3d05a0000.2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  outputs_query_list_t* list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ALIAS_ADDRESS, bech32_alias) == 0);
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(NULL, NULL, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(NULL, INDEXER_API_PATH, list, res));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(&ctx, INDEXER_API_PATH, list, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(&ctx, INDEXER_API_PATH, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(&ctx, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(&ctx, NULL, list, res));

  // Test unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_foundry_outputs(&ctx, "/indexer/x2", list, res));

  //=====Test without query params=====
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, INDEXER_API_PATH, NULL, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test invalid address len=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ALIAS_ADDRESS, addr_hex_invalid_length) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test invalid foundry address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ALIAS_ADDRESS, addr_hex_invalid) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  //=====Test valid foundry address=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_free(list);
  list = outputs_query_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_ALIAS_ADDRESS, bech32_alias) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test page size=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_PAGE_SIZE, "2") == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  //=====Test Cursor=====
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(outputs_query_list_add(&list, QUERY_PARAM_CURSOR, cursor) == 0);
  TEST_ASSERT_EQUAL_INT(0, get_foundry_outputs(&ctx, INDEXER_API_PATH, list, res));
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
  outputs_query_list_free(list);
}

void test_get_output_ids_from_nft_id() {
  char nft_id[] = "19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "efdc112efe262b304bcf379b26c31bad029f61def346ab52ef";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(NULL, NULL, nft_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(NULL, INDEXER_API_PATH, nft_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, INDEXER_API_PATH, nft_id, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, INDEXER_API_PATH, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, NULL, nft_id, res));

  // Test unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, "indexer/x2", nft_id, res));

  //=====Test invalid id len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_nft_id(&ctx, INDEXER_API_PATH, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid nft id=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_nft_id(&ctx, INDEXER_API_PATH, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid nft id=====
  int ret = get_outputs_from_nft_id(&ctx, INDEXER_API_PATH, nft_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_alias_id() {
  char alias_id[] = "01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "23dc192ede262b3f4bce379b26c31bad029f62fe246ec78";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(NULL, NULL, alias_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(NULL, INDEXER_API_PATH, alias_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, INDEXER_API_PATH, alias_id, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, INDEXER_API_PATH, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, NULL, alias_id, res));

  // Test unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, "indexer/x2", alias_id, res));

  //=====Test invalid id len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_alias_id(&ctx, INDEXER_API_PATH, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid alias id=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_alias_id(&ctx, INDEXER_API_PATH, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }
  /* FIXME : Test with a valid alias id */
  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid alias id=====
  int ret = get_outputs_from_alias_id(&ctx, INDEXER_API_PATH, alias_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

void test_get_output_ids_from_foundry_id() {
  char foundry_id[] = "08f010ad0aa58d86e348d34639308a4ea7b8566c0ebd8d2d428a3834fa65e573610100000000";
  char const* const id_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  char const* const id_invalid_length = "56ec192ede262b3f4bce379b26c31bad029f63bc23ef56ee48cf257efc375";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Tests for parameters NULL cases=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(NULL, NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(NULL, NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(NULL, NULL, foundry_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(NULL, INDEXER_API_PATH, foundry_id, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, INDEXER_API_PATH, foundry_id, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, INDEXER_API_PATH, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, NULL, foundry_id, res));

  // Test unsupported indexer path
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, "indexer/x2", foundry_id, res));

  //=====Test invalid id len=====
  TEST_ASSERT_EQUAL_INT(-1, get_outputs_from_foundry_id(&ctx, INDEXER_API_PATH, id_invalid_length, res));

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test invalid foundry id=====
  TEST_ASSERT_EQUAL_INT(0, get_outputs_from_foundry_id(&ctx, INDEXER_API_PATH, id_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // Re initializing res
  res_outputs_free(res);
  res = NULL;
  res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);

  //=====Test valid foundry id=====
  int ret = get_outputs_from_foundry_id(&ctx, INDEXER_API_PATH, foundry_id, res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);

  res_outputs_free(res);
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_query_params);
  RUN_TEST(test_deser_outputs);
  RUN_TEST(test_deser_outputs_err);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_basic_outputs);
  RUN_TEST(test_get_nft_outputs);
  RUN_TEST(test_get_alias_outputs);
  RUN_TEST(test_get_foundry_outputs);
  RUN_TEST(test_get_output_ids_from_nft_id);
  RUN_TEST(test_get_output_ids_from_alias_id);
  RUN_TEST(test_get_output_ids_from_foundry_id);
#endif

  return UNITY_END();
}
